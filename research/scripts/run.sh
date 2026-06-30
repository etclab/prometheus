#!/usr/bin/env bash
# Build Prometheus and run it locally with the example config.
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

# Build and start the demo Go app "myapp", which encrypts its gauge with the
# key material above and exposes the ciphertext on :2112. It is its own Go
# module, so build it from within its directory with the repo's go.work
# workspace disabled (GOWORK=off) so it resolves against its own go.mod.
(cd "${REPO_ROOT}/research/myapp" && GOWORK=off go build -o "${REPO_ROOT}/myapp-bin" .)
"${REPO_ROOT}/myapp-bin" -keys-dir "${KEYS_DIR}" &
MYAPP_PID=$!

# Stop myapp when this script exits (Ctrl-C, error, or Prometheus shutdown).
cleanup() {
  kill "${MYAPP_PID}" 2>/dev/null || true
}
trap cleanup EXIT

# Run Prometheus with the example config. --timecrypt.keys-dir turns on the
# encrypted rule evaluator: rules over encrypted metrics are evaluated by
# decrypting the per-series aggregate at this key holder before the threshold
# comparison, so alerts fire over data the server only ever stored encrypted.
./prometheus --config.file=research/configs/prometheus.yml --timecrypt.keys-dir="${KEYS_DIR}"
