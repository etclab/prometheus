#!/usr/bin/env bash
# Run the TimeCrypt (encrypted) demo stack:
#
#   myapp (ciphertext)  ->  Prometheus (no rules/alerting)  <-  timecrypteval  ->  log
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

# Build and start the demo Go app "myapp", which encrypts its gauge with the key
# material above and exposes the ciphertext on :2112. It is its own Go module, so
# build it from within its directory with the workspace disabled (GOWORK=off).
(cd "${REPO_ROOT}/research/myapp" && GOWORK=off go build -o "${REPO_ROOT}/myapp-bin" .)
"${REPO_ROOT}/myapp-bin" -keys-dir "${KEYS_DIR}" &
MYAPP_PID=$!

# Build and start the standalone TimeCrypt evaluator. It lives in the main module
# (it reuses Prometheus's rulefmt + PromQL parser + client_golang), so build it
# normally. It shares the same key material as myapp for now.
go build -o "${REPO_ROOT}/timecrypteval-bin" ./research/timecrypteval
"${REPO_ROOT}/timecrypteval-bin" \
  -prometheus-url "http://localhost:9090" \
  -rules "research/configs/alerts.yml" \
  -keys-dir "${KEYS_DIR}" &
EVAL_PID=$!

# Stop the background processes when this script exits (Ctrl-C, error, or
# Prometheus shutdown).
cleanup() {
  kill "${MYAPP_PID}" "${EVAL_PID}" 2>/dev/null || true
}
trap cleanup EXIT

echo "timecrypt demo: firing alerts are logged by timecrypteval"

# Run Prometheus WITHOUT any encrypted-evaluator flag and with the config that
# disables its own rule evaluation/alerting.
./prometheus --config.file=research/configs/prometheus-timecrypt.yml
