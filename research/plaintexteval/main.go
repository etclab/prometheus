// Command plaintexteval is the standalone, no-TimeCrypt rule evaluator for the
// encrypted-Prometheus experiment. It is the plaintext skeleton of the trusted
// external evaluator described in research/docs/architecture-assumptions-and-
// decisions.md (decision #7): it reads an ordinary Prometheus alerting-rule
// file, splits each rule at its comparison into an aggregation subquery + a
// threshold, runs only the aggregation against Prometheus over the HTTP query
// API, applies the comparison itself, and posts firing alerts to Alertmanager.
//
// Prometheus's own rule/alert evaluation is turned off for this demo (run it
// with research/configs/prometheus-plaintext.yml, which omits rule_files and
// alertmanagers). The eventual encrypted evaluator keeps this exact shape and
// only swaps the query transport + adds decryption before the comparison.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	api "github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
)

func main() {
	prometheusURL := flag.String("prometheus-url", "http://localhost:9090", "base URL of the Prometheus HTTP API")
	alertmanagerURL := flag.String("alertmanager-url", "", "base URL of the Alertmanager v2 API; if empty, firing alerts are only logged")
	rulesFile := flag.String("rules", "research/configs/alerts.yml", "alerting-rule file to evaluate")
	evalInterval := flag.Duration("eval-interval", 15*time.Second, "how often to evaluate the rules")
	resolveTimeout := flag.Duration("resolve-timeout", 3*time.Minute, "Alertmanager EndsAt offset; firing alerts auto-resolve after this if evaluation stops")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	rules, err := loadRules(*rulesFile, logger)
	if err != nil {
		logger.Error("loading rules", "err", err)
		os.Exit(1)
	}
	if len(rules) == 0 {
		logger.Error("no alerting rules to evaluate", "file", *rulesFile)
		os.Exit(1)
	}

	client, err := api.NewClient(api.Config{Address: *prometheusURL})
	if err != nil {
		logger.Error("building Prometheus client", "err", err)
		os.Exit(1)
	}

	// Alertmanager delivery is optional. Without a URL the evaluator just logs
	// firing alerts, which is enough to see the split/query/threshold flow work.
	var sender *alertSender
	if *alertmanagerURL != "" {
		sender = newAlertSender(*alertmanagerURL, logger)
	}

	// atp:
	ev := newEvaluator(rules, v1.NewAPI(client), sender, *prometheusURL, *resolveTimeout, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	alertmanagerTarget := *alertmanagerURL
	if alertmanagerTarget == "" {
		alertmanagerTarget = "(none: log-only)"
	}
	logger.Info("starting plaintext evaluator",
		"prometheus", *prometheusURL, "alertmanager", alertmanagerTarget,
		"rules", *rulesFile, "eval_interval", *evalInterval)

	ticker := time.NewTicker(*evalInterval)
	defer ticker.Stop()

	ev.evalOnce(ctx, time.Now()) // evaluate immediately, then on the tick.
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return
		case t := <-ticker.C:
			ev.evalOnce(ctx, t)
		}
	}
}
