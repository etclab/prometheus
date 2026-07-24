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
//
// Two label planes are supported, selected with -hermes. By default the rule's
// matchers become encrypted Hermes searches, so the server resolves the selector
// without learning a (label, value) pair. With -hermes=false the matchers are
// sent as an ordinary PromQL selector and only the values remain encrypted: the
// TimeCrypt-only configuration, which isolates the HEAC path for study. The whole
// switch is the windowFetcher seam in eval.go; nothing about decryption or
// aggregation changes between them.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	prometheusURL := flag.String("prometheus-url", "http://localhost:9090", "base URL of the Prometheus HTTP API")
	rulesFile := flag.String("rules", "research/configs/alerts.yml", "alerting-rule file to evaluate")
	keysDir := flag.String("keys-dir", "research/keys", "directory holding the TimeCrypt manifest and master seeds")
	evalInterval := flag.Duration("eval-interval", 15*time.Second, "how often to evaluate the rules")
	hermesOn := flag.Bool("hermes", true, "select series through the Hermes encrypted index; with -hermes=false the rule's matchers are sent to Prometheus as an ordinary PromQL selector and only the values stay TimeCrypt-encrypted (Prometheus must then run without --hermes.enabled, and the targets without -hermes)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	streams, hermesCfg, err := loadStreams(*keysDir)
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

	// The label plane: with Hermes on, this process is the only party that can
	// turn a matcher into a search; with it off, matchers travel in the clear and
	// only the TimeCrypt value plane is encrypted.
	var fetcher windowFetcher
	if *hermesOn {
		seed, err := os.ReadFile(filepath.Join(*keysDir, hermesCfg.SeedFile))
		if err != nil {
			logger.Error("reading Hermes seed", "err", err)
			os.Exit(1)
		}
		if fetcher, err = newHermesReader(seed, hermesCfg.NumWriters, *prometheusURL); err != nil {
			logger.Error("building Hermes reader", "err", err)
			os.Exit(1)
		}
	} else {
		var err error
		if fetcher, err = newPlainFetcher(*prometheusURL, logger); err != nil {
			logger.Error("building Prometheus client", "err", err)
			os.Exit(1)
		}
	}

	ev := newEvaluator(rules, fetcher, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("starting TimeCrypt evaluator",
		"prometheus", *prometheusURL, "rules", *rulesFile,
		"keys_dir", *keysDir, "eval_interval", *evalInterval, "hermes", *hermesOn)

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
