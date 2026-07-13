// Command timecrypteval is the standalone, key-holding rule evaluator for the
// encrypted-Prometheus experiment. It is the TimeCrypt counterpart of
// research/plaintexteval: the trusted external evaluator described in
// research/docs/architecture-assumptions-and-decisions.md (decision #7).
//
// It reads an ordinary Prometheus alerting-rule file, splits each rule at its
// comparison into an aggregation + a threshold, and fetches the rule's full range
// of raw ciphertext (value + timeID series) from Prometheus, which only ever
// stores and serves ciphertext. Every aggregation happens here, at the key
// holder; HEAC ciphertext supports keyless addition but not keyless
// subtraction/division, so the local strategy depends on the rule's function:
//
//   - delta/increase/rate: decrypt the two window endpoints and subtract.
//   - sum_over_time/avg_over_time: add the windowed ciphertext residues locally
//     and decrypt that single sum with only the two boundary keys (HEAC
//     telescoping).
//
// The terminal comparison (`> k`, `< k`, ...) also runs here, after decryption.
// Prometheus never holds keys or plaintext, and performs no aggregation.
//
// Prometheus's own rule/alert evaluation is turned off for this demo (run it
// with research/configs/prometheus-timecrypt.yml, which omits rule_files and
// alertmanagers). Firing alerts are only logged; Alertmanager delivery is out of
// scope for now, exactly as in the plaintext evaluator.
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
	rulesFile := flag.String("rules", "research/configs/alerts.yml", "alerting-rule file to evaluate")
	keysDir := flag.String("keys-dir", "research/keys", "directory holding the TimeCrypt manifest and master seeds")
	evalInterval := flag.Duration("eval-interval", 15*time.Second, "how often to evaluate the rules")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	streams, err := loadStreams(*keysDir)
	if err != nil {
		logger.Error("loading TimeCrypt streams", "err", err)
		os.Exit(1)
	}

	rules, err := loadRules(*rulesFile, streams, logger)
	if err != nil {
		logger.Error("loading rules", "err", err)
		os.Exit(1)
	}
	if len(rules) == 0 {
		logger.Error("no encrypted alerting rules to evaluate", "file", *rulesFile)
		os.Exit(1)
	}

	client, err := api.NewClient(api.Config{Address: *prometheusURL})
	if err != nil {
		logger.Error("building Prometheus client", "err", err)
		os.Exit(1)
	}

	ev := newEvaluator(rules, v1.NewAPI(client), logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("starting TimeCrypt evaluator",
		"prometheus", *prometheusURL, "rules", *rulesFile,
		"keys_dir", *keysDir, "eval_interval", *evalInterval)

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
