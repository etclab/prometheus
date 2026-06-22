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

# Run Prometheus with the example config.
./prometheus --config.file=documentation/examples/prometheus.yml
