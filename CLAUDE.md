# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

The import above covers contribution conventions (PR titles, commits/DCO,
release-notes blocks, test expectations, performance-work rules). This file
covers how to build/test/run and the codebase architecture.

## Build, Test, Lint

This is a Go module (`github.com/prometheus/prometheus`) targeting the Go
version pinned in `go.mod`. A `go.work` workspace links several submodules
(`compliance`, `documentation/examples/remote_storage`, `internal/tools`,
`web/ui/mantine-ui/src/promql/tools`); `go` commands run against the workspace
by default.

```bash
# Build the binaries (prometheus + promtool) via promu, including UI assets.
make build

# Build just the Go binaries quickly, skipping the UI/asset pipeline.
go build ./cmd/prometheus ./cmd/promtool

# Run the full Go test suite (uses the standard common-test target).
make test GO_ONLY=1          # Go tests only — skips UI build/test/lint
make test                    # Full suite incl. generated-parser check + UI

# Run tests for one package.
go test ./tsdb/...
go test ./promql/...

# Run a single test by name.
go test ./promql -run TestEngine
go test ./tsdb -run TestHeadCompaction -v

# Run benchmarks (required for any [PERF] change; see AGENTS.md).
go test -count=6 -benchmem -bench . ./tsdb/...

# Lint — must pass before submitting (golangci-lint, config in .golangci.yml).
make lint                    # Go lint
make lint-fix                # auto-fix where possible
make ui-lint                 # frontend lint
```

## Generated code

Two artifacts are generated and checked in CI for staleness — regenerate and
commit if you touch their sources:

- **PromQL parser**: `promql/parser/generated_parser.y.go` is produced from
  `generated_parser.y` via goyacc. Run `make parser` after editing the grammar
  (`make install-goyacc` first if needed). CI gate: `make check-generated-parser`.
- **PromQL function lists for the UI**: `make generate-promql-functions`
  regenerates `functionSignatures.ts` / `functionDocs.tsx` from Go sources and
  `docs/querying/functions.md`. CI gate: `make check-generated-promql-functions`.

Protobuf definitions live under `prompb/`; regenerate with `make proto`
(requires protoc, installable via `make protoc`).

CLI reference docs are generated: `make cli-documentation`.

## Web UI

The frontend lives in `web/ui/` and is an npm workspace. The current UI is
`web/ui/mantine-ui` (Mantine/React); `web/ui/react-app` is the legacy app, kept
separate from the workspace to avoid dependency conflicts until it is removed.
Built assets are embedded into the Go binary (`web/ui/embed.go.tmpl`,
`assets_embed.go`).

```bash
make ui-install              # install deps (installs react-app deps too)
make ui-build                # build assets (BUILD_UI=mantine for mantine only)
make ui-test                 # frontend tests
```

## Architecture

Prometheus scrapes metrics from targets, stores them in a local TSDB, evaluates
PromQL rules/alerts, and serves queries over HTTP. The data flow:

**service discovery → scrape → storage (TSDB) → PromQL query / rule eval → web API & notifier**

Entry points:
- `cmd/prometheus/main.go` — the server. Wires together every subsystem below
  and runs them as a group of actors; this is the place to understand how
  config flows into discovery, scrape, storage, rules, and web.
- `cmd/promtool/` — CLI for checking config/rules, querying, TSDB inspection
  and backfill, and unit-testing rules (`promtool test rules`).

Core packages:
- `config/` — top-level YAML config model (`config.go`) and live reload logic.
  Many subsystems take their own config struct defined alongside them.
- `discovery/` — service discovery. `manager.go` fans out to one subpackage per
  SD mechanism (`kubernetes/`, `aws/`, `consul/`, `dns/`, `file/`, etc.); each
  registers itself via `install/` and emits target groups.
- `scrape/` — the scrape loop. `manager.go` turns discovered targets into scrape
  loops that parse exposition formats and append samples to storage.
- `storage/` — the storage abstraction layer. `interface.go` defines
  `Storage`, `Appender`, `Querier`, `SeriesSet`; `fanout.go`, `merge.go`,
  `secondary.go` compose multiple storages. `storage/remote/` implements
  remote read/write (incl. the WAL-based remote-write sender).
- `tsdb/` — the local time-series database (the on-disk default storage impl).
  `db.go` is the entry; `head.go` is the in-memory head block, `wlog/` the
  write-ahead log, `chunkenc/`/`chunks/` chunk encoding (incl. native
  histograms), `compact.go`/`block.go` persistent blocks and compaction.
  `tsdb/agent/` is the lightweight agent-mode storage (no querying, remote-write
  only).
- `promql/` — the query engine. `engine.go` evaluates; `parser/` parses PromQL
  (generated grammar) into an AST; `functions.go` implements built-in functions;
  `promqltest/` provides the `.test` file framework used across the codebase.
- `rules/` — recording and alerting rule evaluation (`manager.go`, `group.go`,
  `alerting.go`, `recording.go`).
- `notifier/` — sends fired alerts to Alertmanager(s).
- `web/` — HTTP server. `web/api/v1` is the main query/metadata API; `web/ui`
  serves the embedded frontend; `federate.go` implements federation.
- `model/` — shared data types used everywhere: `labels/`, `histogram/`
  (native histograms), `exemplar/`, `textparse/` (exposition-format parsers),
  `relabel/`, `rulefmt/`, `metadata/`.

The `storage.Storage`/`Appender`/`Querier` interfaces in `storage/interface.go`
are the central seam: scrape and rules write through `Appender`, the web API and
PromQL read through `Querier`, and TSDB / remote / fanout are interchangeable
implementations. When changing read/write behaviour, check the interface
contract there first — buffer-ownership and lifetime semantics are documented at
the interface, per the project's interface-contract rule.
