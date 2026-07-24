#!/usr/bin/env bash
# Run the encrypted demo stack:
#
#   myapp x2 (ciphertext + encrypted label index)
#        ->  Prometheus (no rules/alerting, Hermes index)  <-  timecrypteval  ->  log
#
# Both planes are encrypted. Values are TimeCrypt (HEAC) ciphertext; the
# (label, value) pairs are indexed into the Hermes encrypted inverted index
# living inside Prometheus, and each series is exposed carrying nothing but the
# opaque id those pairs point at. The evaluator is the only party that can turn
# a label matcher into a search.
#
# Run with HERMES=0 to turn the label plane off and study TimeCrypt on its own:
#
#   HERMES=0 research/scripts/run.sh
#
# The targets then expose myapp_processed_ops{job,instance} (+ its timeID
# companion) with ordinary labels, Prometheus runs without --hermes.enabled, and
# the evaluator selects with plain PromQL. Values are still HEAC ciphertext and
# every decryption/aggregation step is unchanged, so this isolates exactly what
# TimeCrypt does.
#
# Prometheus is started WITHOUT any in-process encrypted evaluator and with a
# config that omits rule_files/alertmanagers, so Prometheus fires nothing itself
# and only ever stores ciphertext. The standalone timecrypteval process does the
# alerting: it reads the alerting rules, hands each rule's aggregation to
# Prometheus (as much as the function allows over encrypted data), decrypts the
# per-series aggregate with the keys, applies the threshold, and LOGS firing
# alerts. See research/docs/architecture-assumptions-and-decisions.md (#7).
set -euo pipefail

# Resolve the repo root from this script's location (research/scripts/run.sh).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"

# Build just the Go binaries, skipping the UI/asset pipeline.
# Run with REBUILD_UI=1 to also rebuild the React frontend (rarely needed).
if [[ "${REBUILD_UI:-0}" == "1" ]]; then
  make build
else
  go build -o prometheus ./cmd/prometheus
fi

# Generate the TimeCrypt key material (trusted authority) into research/keys if
# it is not already there. keytool is its own Go module; build it with the
# workspace disabled (GOWORK=off) so it resolves against its own go.mod.
KEYS_DIR="${REPO_ROOT}/research/keys"
(cd "${REPO_ROOT}/research/keytool" && GOWORK=off go build -o "${REPO_ROOT}/keytool-bin" .)
"${REPO_ROOT}/keytool-bin" -keys-dir "${KEYS_DIR}"

# HERMES=1 (the default) encrypts both planes; HERMES=0 keeps only the TimeCrypt
# value plane. All three roles must agree on it, so derive every flag from the one
# switch here. The key material is the same either way: with Hermes off the seed
# and writer classes in the manifest simply go unused.
if [[ "${HERMES:-1}" == "1" ]]; then
  HERMES_FLAG="-hermes=true"
  PROM_HERMES_ARGS=(--hermes.enabled --hermes.keys-dir="${KEYS_DIR}")
  MODE="encrypted values + encrypted labels"
else
  HERMES_FLAG="-hermes=false"
  PROM_HERMES_ARGS=()
  MODE="encrypted values, plaintext labels (TimeCrypt only)"
fi

# Build and start the demo Go apps "myapp", which encrypts its gauge with the key
# material above and exposes the ciphertext on :2112. It is its own Go module, so
# build it from within its directory with the workspace disabled (GOWORK=off).
(cd "${REPO_ROOT}/research/myapp" && GOWORK=off go build -o "${REPO_ROOT}/myapp-bin" .)
"${REPO_ROOT}/myapp-bin" -keys-dir "${KEYS_DIR}" "${HERMES_FLAG}" \
  -addr ":2112" -target "localhost:2112" &
MYAPP_PID=$!

# A second writer class, so an encrypted search over the writer subset has to
# reassemble hits from two mutually unlinkable indexes. With Hermes off it is
# just a second instance of the same metric, told apart by its instance label.
"${REPO_ROOT}/myapp-bin" -keys-dir "${KEYS_DIR}" "${HERMES_FLAG}" \
  -addr ":2113" -target "localhost:2113" &
MYAPP2_PID=$!

# Build and start the standalone TimeCrypt evaluator. It lives in the main module
# (it reuses Prometheus's rulefmt + PromQL parser + client_golang), so build it
# normally. It shares the same key material as myapp for now.
go build -o "${REPO_ROOT}/timecrypteval-bin" ./research/timecrypteval
"${REPO_ROOT}/timecrypteval-bin" \
  -prometheus-url "http://localhost:9090" \
  -rules "research/configs/alerts.yml" \
  -keys-dir "${KEYS_DIR}" "${HERMES_FLAG}" &
EVAL_PID=$!

# Stop the background processes when this script exits (Ctrl-C, error, or
# Prometheus shutdown).
cleanup() {
  kill "${MYAPP_PID}" "${MYAPP2_PID}" "${EVAL_PID}" 2>/dev/null || true
}
trap cleanup EXIT

echo "encrypted demo (${MODE}): firing alerts are logged by timecrypteval"

# Run Prometheus WITHOUT any encrypted-evaluator flag and with the config that
# disables its own rule evaluation/alerting. --hermes.enabled turns on the
# encrypted inverted index the targets write to and the evaluator searches; with
# HERMES=0 it is left off entirely and Prometheus resolves selectors with its
# ordinary postings index.
./prometheus --config.file=research/configs/prometheus-timecrypt.yml \
  "${PROM_HERMES_ARGS[@]}"
