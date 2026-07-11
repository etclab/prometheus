package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// amAlert is one alert in the Alertmanager v2 POST body
// (/api/v2/alerts). The schema is small and stable, so it is hand-built here
// rather than pulling in the alertmanager client / Prometheus notifier deps.
type amAlert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

// alertSender posts alerts to an Alertmanager v2 endpoint.
type alertSender struct {
	url    string // base URL, e.g. http://localhost:9093.
	client *http.Client
	logger *slog.Logger
}

func newAlertSender(url string, logger *slog.Logger) *alertSender {
	return &alertSender{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
		logger: logger,
	}
}

// send POSTs the batch to <url>/api/v2/alerts. Failures are returned so the
// caller can log them, but the demo keeps evaluating regardless.
func (s *alertSender) send(ctx context.Context, alerts []amAlert) error {
	if len(alerts) == 0 {
		return nil
	}
	body, err := json.Marshal(alerts)
	if err != nil {
		return fmt.Errorf("marshaling alerts: %w", err)
	}
	endpoint := s.url + "/api/v2/alerts"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("posting to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("alertmanager %s returned %s: %s", endpoint, resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}
