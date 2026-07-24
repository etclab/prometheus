# Encrypted Prometheus — Assumptions & Architecture Decisions

This document records the working assumptions and the conclusions reached while
reviewing `encrypted-prometheus-design.md`. It supersedes the parts of that
document that describe a separate "Prometheus-compatible encrypted server" and
the exporter/publisher-agent split.

## Deployment assumptions (the mental model we are building to)

1. **Single Prometheus instance.** One Prometheus collects encrypted metrics
   from multiple scrape targets. No horizontal scaling, no Thanos, no central
   aggregation tier. Prometheus itself performs ingestion, storage, and
   server-side aggregation.
2. **Prometheus is the untrusted server.** It is modified (forked) to store and
   aggregate over encrypted data, but it never holds decryption keys and never
   sees plaintext metric names, label values, or sample values.
3. **Prometheus is modified, not extended via plugins.** We will change how
   PromQL storage and query evaluation work internally to support TimeCrypt and
   related schemes — this is a fork of Prometheus, not a storage plugin.
4. **The metric producer is trusted and holds the keys.** The thing emitting
   metrics encrypts them in-process before they leave it. There is no separate
   trusted "publisher agent" sidecar in the base design (see decisions below).
5. **A trusted client/evaluator holds the keys and makes decisions.** It
   compiles queries, receives encrypted aggregate results from Prometheus,
   decrypts them, applies thresholds, and drives alerting. Keys are never
   exposed to Prometheus.
6. **The adversary is an honest-but-curious Prometheus.** It follows the
   protocol but tries to learn from everything it observes, including its own
   in-memory scrape state. For now we accept that Prometheus knows each target's
   scrape URL (`instance`) and `job` — they are in its config and in the scrape
   connection — and defer hiding them behind a **proxy** that fronts all targets
   at one indistinguishable address (see the "What still leaks" note in decision
   #8). Broader adversaries (on-disk block readers, remote-read/federation
   consumers) are out of scope in the base design.

## Decisions

### 1. Terminology

- **"namespace"** is not a Prometheus concept. It is a coined term for a
  *policy/schema unit* (metric family + allowed labels + which labels are
  searchable/groupable + keys + epoch). Rename to **"metric policy"** or
  **"protected metric family"** to avoid colliding with reader expectations.
- **"Prometheus-aware"** means: designed around Prometheus's data model (metric
  name + labels, selectors, range vectors, reset-aware `rate()`), as opposed to
  a generic encrypted database or a full encrypted-PromQL engine. Since the
  server is a modified Prometheus that never runs PromQL over plaintext, the
  design is *shaped like* Prometheus rather than being stock Prometheus.

### 2. No separate untrusted server

The document's "untrusted Prometheus-compatible encrypted server" and our
"modified Prometheus" are the same thing. We do **not** add a new component; we
identify the untrusted-server role with Prometheus itself. Deployment is: one
untrusted (modified) Prometheus + trusted key-holding evaluator/client.

### 3. No exporter/publisher-agent split in the base design

Because the metric producer is trusted, it holds the keys and encrypts inline.
Collapse the exporter and the "trusted publisher agent" into one component.

The sidecar split is retained only as an **optional hardening** for two cases,
and the threat model must state its limits honestly:
- **Practical:** unmodifiable third-party exporters (e.g. `node_exporter`) —
  a sidecar adds encryption without forking the exporter.
- **Security:** shrinking the key-holding TCB / enforcing write-authorization
  against a *partially* compromised exporter. This guarantee is thin: it stops
  forging of series *identities* but not lying about *values*, and it collapses
  if the sidecar is co-compromised.

### 4. Stock Prometheus cannot aggregate ciphertext — this drives the fork

PromQL evaluates `sum`/`rate`/`avg` as float64 arithmetic over plaintext.
TimeCrypt's additive homomorphism is modular integer addition over a keystream,
not IEEE-754 float addition. Therefore server-side homomorphic aggregation
requires forking Prometheus internals, not just implementing a storage
interface.

**Seams (reusable) vs. forks (internal surgery):**

| Need | Prometheus surface | Reality |
|---|---|---|
| Ingest encrypted samples | `storage.Appender` (`storage/interface.go`) | Interface, but sample-value type is the catch |
| Read data back | `storage.Querier` / `SeriesSet` | Interface — clean seam |
| Encrypted metadata / token filtering | postings (`tsdb/index`) | Repurposable — feed opaque field-IDs/tokens as label values |
| Store TimeCrypt chunks + digests | chunk encoding (`tsdb/chunkenc`) | Fork — new `Encoding`; native-histogram-scale surgery through head/WAL/compaction |
| Sample *value* = ciphertext/digest | `float64` / native histogram | Fork — ciphertext/big-int does not fit in a float64 |
| Homomorphic `sum`/`rate`/`avg` | PromQL engine (`promql/engine.go`) | Fork — not an interface |
| Query without leaking selectors | query API + matchers | Fork / move client-side — matchers are plaintext today |

### 5. Prefer pushing aggregation below the engine

Two ways to add homomorphic aggregation:
- **Push aggregation below the engine** into `Querier`/storage: the planner
  recognizes `sum by (...) (rate(...))`, hands the encrypted aggregation to the
  storage layer, and the engine passes the encrypted result through.
  *Preferred* — storage is a stable interface, the engine is not.
- **Teach the engine homomorphic operators** in `engine.go`: needed only for
  what cannot be cleanly pushed down (`rate()` boundary handling, grouping).

### 6. Query privacy boundary lives in the trusted client

A PromQL query carries plaintext selectors (e.g. `{method="GET"}`). The trusted
client must compile PromQL into a **tokenized query plan** (search tokens for
`(__name__=…)`, `(method=…)`, a time/chunk range, a grouping plan over hidden
field-IDs) *before* anything reaches Prometheus. Prometheus matches on tokens it
cannot invert. Consequence: PromQL parse + selector tokenization moves
client-side (or behind a capability); Prometheus receives an encrypted plan, not
raw PromQL.

### 7. Trusted querier / rule evaluator

**There is no hook in Prometheus to delegate rule evaluation to a third party.**
Prometheus evaluates recording and alerting rules in-process
(`rules/manager.go`): PromQL runs against local storage on an interval,
alerting rules emit `ALERTS`, and the `notifier` package ships them to
Alertmanager. There is no plugin seam for "evaluate this rule externally," and
the built-in manager is useless here anyway because it would compare
**ciphertext**.

So the trusted evaluator is **not a Prometheus plugin** — it is an **external
PromQL client** that:

1. queries the modified, untrusted Prometheus API (`/api/v1/query`,
   `/api/v1/query_range`) → receives encrypted aggregate results,
2. decrypts them with keys Prometheus never sees,
3. applies the threshold/comparison,
4. `POST`s firing alerts to Alertmanager (`/api/v2/alerts`).

The only Prometheus seams involved are the **HTTP query API** (results out) and
the **Alertmanager boundary** (alerts out). Both keep us inside the Prometheus
ecosystem — the evaluator is a client of Prometheus, not a departure from it.

**Disabling Prometheus's built-in evaluation/forwarding.** No agent mode and no
special flag required — both are config-driven:
- Omit `rule_files:` from `prometheus.yml` → recording and alerting rules
  evaluate nothing (manager stays inert).
- Omit `alerting: alertmanagers:` → the notifier forwards nothing; Prometheus
  never contacts Alertmanager.
- (Optional, since we fork anyway) stop constructing the rule manager and
  notifier actors in `cmd/prometheus/main.go`. Config-level disabling is
  sufficient; this is just extra hardening.

**Agent mode is not the mechanism.** Agent mode is a writer-only profile
(scrape + remote-write; no TSDB, no query, no rules). It *removes* querying
rather than relocating it. The querier/ruler separation belongs to the
remote-write ecosystem (Thanos/Mimir/Cortex), not to agent mode.

**Reference pattern — Thanos.** Thanos decomposes Prometheus into standalone
processes over a gRPC **StoreAPI**:
- **Store/Sidecar** serve series via StoreAPI.
- **Querier** is a standalone PromQL engine fanning out over StoreAPI, exposing
  the Prometheus HTTP API.
- **Ruler** evaluates rules by querying and drives Alertmanager — i.e. exactly
  "external trusted rule evaluator that queries a store and fires alerts."

Two ways to use it:
- *Borrow the pattern* (recommended first): a small trusted evaluator modeled on
  Thanos Ruler — query, decrypt, threshold, alert. Minimal surface.
- *Borrow the StoreAPI seam* (if aggregation must stay server-side): extend
  StoreAPI to carry encrypted homomorphic aggregates, so the untrusted store
  does the TimeCrypt aggregation and the trusted Querier/Ruler only decrypts.

Caveat: if a Thanos-style trusted Querier runs *all* the PromQL, aggregation
happens after decryption in the trusted zone, discarding the server-side
homomorphic benefit. Keep aggregation on the untrusted side; let the trusted
side only decrypt + threshold.

**Thanos Ruler cannot be run as-is** — treat it as a *code template*, not a
drop-in. Two mismatches with the encrypted setting:
- It assumes **plaintext query results**; it has no decryption seam and would
  threshold ciphertext.
- It sends the **whole expression** (including the comparison) to its query
  endpoint. For `sum(rate(x[5m])) > 100` the untrusted server cannot run the
  `> 100` comparison over ciphertext; only the `sum(rate(...))` aggregation can
  run server-side.

**Chosen split (decision):** Prometheus (untrusted) evaluates the
**aggregation subquery** homomorphically and returns the encrypted aggregate;
the trusted rule evaluator performs the **final decryption, then the
comparison/threshold**, then drives Alertmanager. Concretely, a rule
`sum(rate(x[5m])) > 100` is cut at the comparison: `sum(rate(x[5m]))` goes to
Prometheus (as a tokenized query), the evaluator decrypts the result and applies
`> 100` locally.

**Implementation approach (decision):** build a small **custom evaluator** using
Thanos Ruler as a structural reference rather than running Ruler itself — it
sends only the aggregation subquery, decrypts, applies the threshold, and posts
to Alertmanager. Lift Ruler's Alertmanager/notifier plumbing to avoid
reimplementing the wire format. (The alternative — an unmodified Ruler behind a
trusted decrypting/tokenizing proxy — is rejected for now because Ruler's
whole-expression model fights the aggregate-server / threshold-client split.)

**Where to run the trusted evaluator (deployment choice, architecture-neutral):**
- *Client-side* (data owner's premises): keys never leave the org; strongest
  trust story; more egress of encrypted results.
- *TEE co-located in the cloud* (AWS Nitro Enclaves, AMD SEV-SNP, Intel TDX)
  next to Prometheus: keys live in the enclave, isolated from the cloud operator
  and the untrusted Prometheus process; far less egress. Cost: adds the TEE
  (vendor + attestation + side-channel assumptions) to the TCB and requires
  remote attestation before keys are released to the enclave.

### 8. The metadata plane: Hermes as the encrypted inverted index

The value plane (TimeCrypt) and the metadata plane are separate problems.
Decision #4 covers values; this covers `(label, value) -> series`.

**Hermes** (IEEE S&P 2025, [eprint 2025/701](https://eprint.iacr.org/2025/701),
ported to Go at `../Hermes/hermes-go`) runs **inside** Prometheus as the
encrypted inverted index, consistent with decision #2: Prometheus is the
untrusted server, so the encrypted index belongs to it, not to a new component.
The mapping is:

| Hermes | Prometheus |
| --- | --- |
| writer class | a scrape target, holding its own writer key |
| keyword | a canonical `(label name, value)` pair |
| document id | an opaque, writer-assigned series id (`sid`) |
| engine | `tsdb/hermes`, inside the untrusted server |
| reader | the trusted rule evaluator of decision #7 |

**Why the document id is writer-assigned.** Prometheus mints a `SeriesRef`
internally, *after* the target has already encrypted its pairs, so a writer can
never know it. Instead the target derives `sid = PRF(writerKey, labelset)` and
exposes the series as `enc_series{sid="..."}`. Prometheus's ordinary postings
index then supplies `sid -> SeriesRef` for free, and the encrypted index needs
no id mapping of its own. This is what keeps the change small: the only TSDB
change is one branch in `PostingsForMatchers`.

**How a query carries a search.** Aggregate keys are multi-kilobyte, so they do
not fit in a selector. The evaluator POSTs them as `hermes_<id>` parameters
alongside the PromQL text and refers to them from a reserved matcher:
`enc_series{__hermes__="q0,q1"}[1m]`. The ids are intersected, so an encrypted
lookup composes with ordinary label matching instead of bypassing it.

**Why Hermes rather than the single-writer SSE sketch.** The earlier
`tsdb/index/postings_encrypted.go` (Clusion DynRH2Lev) holds one client key in
one process. Prometheus is inherently multi-writer: several targets index the
same pairs (`job="myapp"`) under keys none of them share. Hermes is built for
exactly that — per-writer keys, one reader aggregate key over a writer subset —
and two writers indexing the same pair leave *unlinkable* state on the server.

**What still leaks, stated plainly:**
- **Target identity.** Prometheus attaches `job` and `instance` itself at scrape
  time, so they stay plaintext no matter what the target encrypts. Relabeling
  them out of storage does *not* close this against the honest-but-curious
  Prometheus of assumption #6: the scrape loop already ties each `sid` to its
  target (the `Target` object) from the connection itself, independent of what
  is stored. That link is what actually hurts — it lets Prometheus re-attach
  plaintext labels to a `sid` and thereby back out which pair an encrypted search
  matched, defeating the query-matcher privacy Hermes is meant to provide.
  Hiding target identity therefore needs a **proxy** (or push/remote-write path)
  that collapses all targets behind one address; the storage relabel is coupled
  to it and must ship *together* with it, otherwise storage re-leaks exactly what
  the proxy just hid. Both are deferred for now (assumption #6).
- **Search access pattern.** The engine sees which writer shards a query matched
  in, and repeated searches for the same pair are linkable.
- **Series cardinality and scrape timing**, as before.
- **Prototype shortcut:** all roles derive the HICKAE authority from one shared
  seed, so the engine can derive secrets a real untrusted server must not hold.
  Only the public correlation matrix is actually used. Fixing this means
  serializing per-role key material in hermes-go.

**Not yet done:** the encrypted index is in-memory only (no WAL, no replay), so
the targets must be restarted whenever Prometheus is. Epoch advancement, and the
forward privacy it buys, is unused.

## One-line summary

Build a **fork of Prometheus** that plays the untrusted-server role for a single
instance: reuse the read/write plumbing and the inverted index as seams, but
fork the sample-value representation, chunk encoding, aggregation semantics, and
selector-privacy boundary. Values are TimeCrypt ciphertext; label pairs live in
a Hermes encrypted index inside the server, reached through a reserved matcher. Keys and all final decisions (thresholds, alerts)
live only in a trusted client/evaluator.
