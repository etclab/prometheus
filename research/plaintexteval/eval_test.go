package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	api "github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/promql/parser"
)

// stubProm serves /api/v1/query returning the given instant-vector body, so the
// real client_golang API client parses a realistic Prometheus response.
func stubProm(t *testing.T, vectorResult string) *httptest.Server {
	t.Helper()
	body := `{"status":"success","data":{"resultType":"vector","result":` + vectorResult + `}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// stubAM captures alerts POSTed to /api/v2/alerts.
func stubAM(t *testing.T, got *[]amAlert, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v2/alerts", r.URL.Path)
		var batch []amAlert
		require.NoError(t, json.NewDecoder(r.Body).Decode(&batch))
		mu.Lock()
		*got = append(*got, batch...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestEvaluator(t *testing.T, rules []alertRule, promURL, amURL string) *evaluator {
	t.Helper()
	client, err := api.NewClient(api.Config{Address: promURL})
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newEvaluator(rules, v1.NewAPI(client), newAlertSender(amURL, logger), promURL, time.Minute, logger)
}

// decreasingRule is the alerts.yml rule, pre-split.
func decreasingRule() alertRule {
	return alertRule{
		name:          "MyappOpsDecreasing",
		query:         "delta(myapp_processed_ops[1m])",
		hasComparison: true,
		op:            parser.LSS,
		threshold:     0,
		labels:        map[string]string{"severity": "warning"},
		annotations:   map[string]string{"description": "myapp_processed_ops fell by {{ $value }} over the last minute."},
	}
}

func TestEvalOnce_FiresOnBreach(t *testing.T) {
	prom := stubProm(t, `[{"metric":{"instance":"localhost:2112","job":"myapp"},"value":[1700000000,"-6"]}]`)

	var got []amAlert
	var mu sync.Mutex
	am := stubAM(t, &got, &mu)

	ev := newTestEvaluator(t, []alertRule{decreasingRule()}, prom.URL, am.URL)
	ev.evalOnce(context.Background(), time.Now())

	require.Len(t, got, 1)
	require.Equal(t, "MyappOpsDecreasing", got[0].Labels["alertname"])
	require.Equal(t, "warning", got[0].Labels["severity"])
	require.Equal(t, "myapp", got[0].Labels["job"])
	require.Equal(t, "myapp_processed_ops fell by -6 over the last minute.", got[0].Annotations["description"])
}

func TestEvalOnce_LogOnlyWithoutSender(t *testing.T) {
	prom := stubProm(t, `[{"metric":{"instance":"localhost:2112","job":"myapp"},"value":[1700000000,"-6"]}]`)

	client, err := api.NewClient(api.Config{Address: prom.URL})
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Nil sender: a breach must be handled (logged) without panicking or erroring.
	ev := newEvaluator([]alertRule{decreasingRule()}, v1.NewAPI(client), nil, prom.URL, time.Minute, logger)
	require.NotPanics(t, func() { ev.evalOnce(context.Background(), time.Now()) })
}

func TestEvalOnce_NoFireWhenNotBreaching(t *testing.T) {
	prom := stubProm(t, `[{"metric":{"instance":"localhost:2112","job":"myapp"},"value":[1700000000,"4"]}]`)

	var got []amAlert
	var mu sync.Mutex
	am := stubAM(t, &got, &mu)

	ev := newTestEvaluator(t, []alertRule{decreasingRule()}, prom.URL, am.URL)
	ev.evalOnce(context.Background(), time.Now())

	require.Empty(t, got)
}

func TestEvalOnce_ForDelaysFiring(t *testing.T) {
	prom := stubProm(t, `[{"metric":{"instance":"localhost:2112","job":"myapp"},"value":[1700000000,"-6"]}]`)

	var got []amAlert
	var mu sync.Mutex
	am := stubAM(t, &got, &mu)

	r := decreasingRule()
	r.forDur = time.Minute
	ev := newTestEvaluator(t, []alertRule{r}, prom.URL, am.URL)

	start := time.Now()
	ev.evalOnce(context.Background(), start) // pending: within `for`.
	require.Empty(t, got)

	ev.evalOnce(context.Background(), start.Add(90*time.Second)) // now past `for`.
	require.Len(t, got, 1)
}
