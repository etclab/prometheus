package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	timecrypt "github.com/aashutoshpaudyal/timecrypt-go"
	api "github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/prometheus/prometheus/promql/parser"
)

const (
	testMetric = "myapp_processed_ops"
	testTimeID = "myapp_processed_ops_timeid"
	testScale  = 1000.0
	testMod    = 32
	testDepth  = 20
	// seriesLabels is the non-name label set shared by the value and timeID
	// series, so they pair by identity after __name__ is stripped.
	seriesLabels = `"instance":"localhost:2112","job":"myapp"`
)

// writeManifest writes a one-stream manifest + master seed into dir, matching
// what research/keytool produces.
func writeManifest(t *testing.T, dir string, master []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "s.key"), master, 0o600))
	manifest := `{"streams":[{"metric":"` + testMetric + `","key_file":"s.key","timeid_metric":"` +
		testTimeID + `","scale":1000,"mod_bits":32,"tree_depth":20}]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644))
}

func newClientScheme(t *testing.T, master []byte) *timecrypt.TimeCryptEncryptionBI {
	t.Helper()
	skm, err := timecrypt.NewStreamKeyManager(master, testDepth)
	require.NoError(t, err)
	return timecrypt.NewTimeCryptEncryptionBI(skm.TreeKeyRegression(), testMod)
}

// setup generates fresh key material, writes the manifest, and returns the
// evaluator's loaded streams alongside the matching client-side scheme (as
// myapp would hold), which share keys as the demo does.
func setup(t *testing.T) (map[string]*encStream, *timecrypt.TimeCryptEncryptionBI) {
	t.Helper()
	keysDir := t.TempDir()
	master, err := timecrypt.GenerateKey(16)
	require.NoError(t, err)
	writeManifest(t, keysDir, master)
	streams, err := loadStreams(keysDir)
	require.NoError(t, err)
	return streams, newClientScheme(t, master)
}

// mustSplit parses and splits one rule against the loaded streams.
func mustSplit(t *testing.T, streams map[string]*encStream, alert, expr string) alertRule {
	t.Helper()
	ar, err := splitRule(parser.NewParser(parser.Options{}), rulefmt.Rule{Alert: alert, Expr: expr}, streams)
	require.NoError(t, err)
	return ar
}

// encodeValues encrypts each plaintext value at its contiguous timeID (as myapp
// does) and returns the ciphertext residues carried as exact-integer float64s.
func encodeValues(t *testing.T, enc *timecrypt.TimeCryptEncryptionBI, values []float64) []float64 {
	t.Helper()
	resid := make([]float64, len(values))
	for i, v := range values {
		ct, err := enc.EncryptMetadata(big.NewInt(timecrypt.FloatToFixed(v, testScale)), int64(i), 0)
		require.NoError(t, err)
		resid[i] = timecrypt.ResidueToFloat(ct)
	}
	return resid
}

// captureHandler is a slog.Handler that records the "ALERT firing" log lines so
// tests can assert the fire decision + reported value without an Alertmanager.
type captureHandler struct {
	mu    sync.Mutex
	fired []firedRecord
}

type firedRecord struct {
	alert string
	value float64
}

func (c *captureHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message != "ALERT firing" {
		return nil
	}
	rec := firedRecord{}
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "alert":
			rec.alert = a.Value.String()
		case "value":
			rec.value = a.Value.Float64()
		}
		return true
	})
	c.mu.Lock()
	c.fired = append(c.fired, rec)
	c.mu.Unlock()
	return nil
}

func (c *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (c *captureHandler) WithAttrs([]slog.Attr) slog.Handler       { return c }
func (c *captureHandler) WithGroup(string) slog.Handler            { return c }

// stubProm serves /api/v1/query, routing each query string through route. An
// unroutable query fails the test (a missing case means the evaluator asked for
// something unexpected).
func stubProm(t *testing.T, route func(q string) (string, bool)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.FormValue("query")
		body, ok := route(q)
		if !ok {
			t.Errorf("stubProm: unexpected query %q", q)
			http.Error(w, "unexpected query", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// sampleValues renders a range-vector's [ts,"val"] pairs, one every 10s from base.
func sampleValues(base time.Time, vals []float64) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		ts := base.Add(time.Duration(i) * 10 * time.Second).Unix()
		parts[i] = fmt.Sprintf(`[%d,%q]`, ts, strconv.FormatFloat(v, 'f', -1, 64))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func matrixBody(name, values string) string {
	return fmt.Sprintf(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":%q,%s},"values":%s}]}}`, name, seriesLabels, values)
}

// runOnce runs the evaluator over one rule against srv and returns the captured
// firing records.
func runOnce(t *testing.T, ar alertRule, srvURL string) []firedRecord {
	t.Helper()
	cap := &captureHandler{}
	client, err := api.NewClient(api.Config{Address: srvURL})
	require.NoError(t, err)
	ev := newEvaluator([]alertRule{ar}, v1.NewAPI(client), slog.New(cap))
	ev.evalOnce(context.Background(), time.Now())
	cap.mu.Lock()
	defer cap.mu.Unlock()
	return cap.fired
}

// TestDeltaAlertOverCiphertext is the end-to-end endpoint-path alert: a downward
// walk stored as HEAC ciphertext fires `delta(...) < 0`, with the firing
// decision and reported value computed at the key holder. Prometheus only ever
// selected + windowed the ciphertext.
func TestDeltaAlertOverCiphertext(t *testing.T) {
	streams, enc := setup(t)
	base := time.Now().Add(-time.Minute).Truncate(time.Second)
	resid := encodeValues(t, enc, []float64{10, 9, 7, 4}) // net change -6.
	ids := []float64{0, 1, 2, 3}

	srv := stubProm(t, func(q string) (string, bool) {
		switch q {
		case testMetric + "[1m]":
			return matrixBody(testMetric, sampleValues(base, resid)), true
		case testTimeID + "[1m]":
			return matrixBody(testTimeID, sampleValues(base, ids)), true
		}
		return "", false
	})

	ar := mustSplit(t, streams, "MyappOpsDecreasing", "delta("+testMetric+"[1m]) < 0")
	fired := runOnce(t, ar, srv.URL)

	require.Len(t, fired, 1)
	require.Equal(t, "MyappOpsDecreasing", fired[0].alert)
	require.InDelta(t, -6.0, fired[0].value, 1e-6)
}

// TestDeltaDoesNotFireWhenIncreasing checks the comparison really gates firing:
// an upward walk yields delta > 0 and produces no alert.
func TestDeltaDoesNotFireWhenIncreasing(t *testing.T) {
	streams, enc := setup(t)
	base := time.Now().Add(-time.Minute).Truncate(time.Second)
	resid := encodeValues(t, enc, []float64{1, 3, 6, 10}) // net change +9.
	ids := []float64{0, 1, 2, 3}

	srv := stubProm(t, func(q string) (string, bool) {
		switch q {
		case testMetric + "[1m]":
			return matrixBody(testMetric, sampleValues(base, resid)), true
		case testTimeID + "[1m]":
			return matrixBody(testTimeID, sampleValues(base, ids)), true
		}
		return "", false
	})

	ar := mustSplit(t, streams, "MyappOpsDecreasing", "delta("+testMetric+"[1m]) < 0")
	require.Empty(t, runOnce(t, ar, srv.URL))
}

// TestSumOverTimeLocalAggregation exercises the summable path: Prometheus only
// selects and windows the raw ciphertext (value + timeID series), and the
// evaluator adds the residues locally and decrypts that single sum with the
// boundary keys (HEAC telescoping) before applying the threshold.
func TestSumOverTimeLocalAggregation(t *testing.T) {
	streams, enc := setup(t)
	base := time.Now().Add(-time.Minute).Truncate(time.Second)
	resid := encodeValues(t, enc, []float64{10, 9, 7, 4}) // plaintext sum 30, timeIDs 0..3.
	ids := []float64{0, 1, 2, 3}

	srv := stubProm(t, func(q string) (string, bool) {
		switch q {
		case testMetric + "[1m]":
			return matrixBody(testMetric, sampleValues(base, resid)), true
		case testTimeID + "[1m]":
			return matrixBody(testTimeID, sampleValues(base, ids)), true
		}
		return "", false
	})

	sumRule := mustSplit(t, streams, "SumHigh", "sum_over_time("+testMetric+"[1m]) > 0")
	fired := runOnce(t, sumRule, srv.URL)
	require.Len(t, fired, 1)
	require.InDelta(t, 30.0, fired[0].value, 1e-6)

	avgRule := mustSplit(t, streams, "AvgHigh", "avg_over_time("+testMetric+"[1m]) > 0")
	fired = runOnce(t, avgRule, srv.URL)
	require.Len(t, fired, 1)
	require.InDelta(t, 30.0/4, fired[0].value, 1e-6)
}
