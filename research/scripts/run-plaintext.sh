#!/usr/bin/env bash
# Run the plaintext (no-TimeCrypt) demo stack:
#
#   myapp --plaintext  ->  Prometheus (no rules/alerting)  <-  plaintexteval  ->  log (or Alertmanager)
#
# Prometheus is started WITHOUT --timecrypt.keys-dir, so its in-process encrypted
# rule evaluator stays off, and with a config that omits rule_files/alertmanagers,
# so Prometheus fires nothing itself. The standalone plaintexteval process does
# the alerting: it queries Prometheus for each rule's aggregation subquery and
# applies the threshold itself.
#
# By default firing alerts are just LOGGED by the evaluator (no Alertmanager
# needed). To also post them, set ALERTMANAGER_URL to a running Alertmanager,
# e.g. ALERTMANAGER_URL=http://localhost:9093 research/scripts/run-plaintext.sh.
set -euo pipefail

# Resolve the repo root from this script's location (research/scripts/run-plaintext.sh).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"

# Empty by default: the evaluator logs firing alerts instead of posting them.
ALERTMANAGER_URL="${ALERTMANAGER_URL:-}"

# Build just the Go binaries, skipping the UI/asset pipeline.
# Run with REBUILD_UI=1 to also rebuild the React frontend (rarely needed).
if [[ "${REBUILD_UI:-0}" == "1" ]]; then
  make build
else
  go build -o prometheus ./cmd/prometheus
fi

# Build and start the demo Go app "myapp" in --plaintext mode: it exposes the
# raw processed-ops gauge on :2112 (no encryption, no keytool step). It is its
# own Go module, so build it with the repo's go.work workspace disabled
# (GOWORK=off) so it resolves against its own go.mod.
(cd "${REPO_ROOT}/research/myapp" && GOWORK=off go build -o "${REPO_ROOT}/myapp-bin" .)
"${REPO_ROOT}/myapp-bin" -plaintext &
MYAPP_PID=$!

# Build and start the standalone plaintext evaluator. It lives in the main
# module (it reuses Prometheus's rulefmt + PromQL parser), so build it normally.
go build -o "${REPO_ROOT}/plaintexteval-bin" ./research/plaintexteval
"${REPO_ROOT}/plaintexteval-bin" \
  -prometheus-url "http://localhost:9090" \
  -alertmanager-url "${ALERTMANAGER_URL}" \
  -rules "research/configs/alerts.yml" &
EVAL_PID=$!

# Stop the background processes when this script exits.
cleanup() {
  kill "${MYAPP_PID}" "${EVAL_PID}" 2>/dev/null || true
}
trap cleanup EXIT

if [[ -n "${ALERTMANAGER_URL}" ]]; then
  echo "plaintext demo: firing alerts are posted to ${ALERTMANAGER_URL}"
else
  echo "plaintext demo: firing alerts are logged by plaintexteval (set ALERTMANAGER_URL to also post them)"
fi

# Run Prometheus WITHOUT --timecrypt.keys-dir and with the plaintext config that
# disables its own rule evaluation/alerting.
./prometheus --config.file=research/configs/prometheus-plaintext.yml
