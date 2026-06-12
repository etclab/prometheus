# Encrypted PromQL Alert Evaluation — Research Notes

## Problem framing

Goal: evaluate Prometheus **alerting rules** over time series stored on an untrusted
server, without decrypting on the server. Test setup already has:

- **CJJJKRS** — encrypted searchable encryption, used so Prometheus can filter / find the
  relevant time-series IDs (the *selector* layer).
- **TimeCrypt** — additively-homomorphic encryption of values, for aggregation over time
  windows (the *temporal* layer).

Question driving the work: where does TimeCrypt run out, and what is the novel contribution?

## Key clarification: AlertManager does not run queries

AlertManager receives **already-fired** alerts from the Prometheus server and only handles
deduplication, grouping, silencing, inhibition, and routing. The querying happens in
**Prometheus's alerting rules** — PromQL expressions evaluated by the Prometheus server.
So the cryptographic burden falls on whatever evaluates PromQL, not on AlertManager.

A rule fires when its PromQL expression holds for a `for:` duration; the expression is
re-evaluated every scrape interval, so any per-evaluation leakage compounds over time.

## The novelty: composition, not a single primitive

PromQL alert evaluation decomposes cleanly into **four layers**. CJJJKRS covers layer 1,
TimeCrypt covers part of layer 2, and layers 3–4 need something new. The research claim is
that a small set of composed primitives serves a large, *characterizable* fraction of real
rules, with a sharp, nameable boundary where it cannot.

### Layer 1 — Selection (CJJJKRS handles this)

Label matchers (`{job="prometheus"}`), regex matchers (`=~`, `!~`), and the
`by` / `without` / `on` / `group_left` grouping keys. Encrypted keyword/equality matching.
Subtlety: `on(instance, device)` joins and `group_left` require matching label *tuples*
across two series (composite-key equality).

### Layer 2 — Temporal reduction over `[window]` (TimeCrypt partially handles this)

- **Linear — covered by TimeCrypt:** `rate`, `irate`, `increase`, `delta`, `deriv`,
  `avg_over_time`, `sum_over_time`, and `predict_linear` (least-squares slope = linear
  combination). These dominate the corpus.
- **Non-linear — NOT covered:** `min_over_time`, `max_over_time`, `last_over_time`,
  `quantile_over_time`, `stddev_over_time`, `changes`. Additive HE gives no path to a max
  or a positional read.

### Layer 3 — Cross-series arithmetic (gap — neither primitive handles this)

- **Scalar affine** (`* 100`, `- boot_time`, `/ 1024`): trivially homomorphic, fine.
- **Series ± series**: additive HE works *only if* operands share key/encoding — not
  guaranteed in multi-writer settings.
- **Series × series, series ÷ series**: the killer. Ratios are pervasive
  (`MemAvailable/MemTotal`, `errs/packets`, `rollback/(rollback+commit)`). Division is not
  homomorphic under additive HE; multiplication needs at least SHE. Standard escape:
  rewrite `a/b > k` as `a > k·b`, valid only when `b > 0` is known (many corpus rules carry
  an explicit `and size_bytes > 0` guard doing exactly this sign-safety by hand). This
  converts division into a layer-4 comparison of two ciphertexts.

### Layer 4 — Terminal comparison (gap — the universal wall)

**Every** rule ends in `> k`, `< k`, `== k`, `!=`, or a `>= a < b` band. Even the simplest
(`mysql_up == 0`, `probe_success == 0`) needs encrypted equality against a public constant.
`vector(1)` / `absent(...)` need existence/cardinality tests. Neither CJJJKRS nor TimeCrypt
addresses this, and it is unavoidable — no useful alert exists without it.

## Coverage map (by rough frequency in the corpus)

| Rule shape | Example | L1 | L2 | L3 | L4 | Verdict |
|---|---|---|---|---|---|---|
| Constant threshold on raw gauge | `mysql_up == 0` | ✓ | — | — | cmp | Needs only a comparison primitive |
| Rate vs constant | `rate(...[5m]) > 0` | ✓ | ✓ | scalar | cmp | Comparison primitive |
| Ratio vs constant | `MemAvailable/MemTotal < .10` | ✓ | ✓/— | division | cmp | Comparison + (rewrite or SHE) |
| Non-linear window | `max_over_time(...) > 70` | ✓ | ✗ | — | cmp | Needs new temporal primitive |
| Two-series compare | `current >= drive_trip` | ✓ | mixed | sub | cmp-of-2-ct | Hardest: cmp on two ciphertexts |
| Existence / cardinality | `absent(...)`, `vector(1)`, `count(...) > 1` | ✓ | — | — | special | Needs encrypted cardinality |

## Takeaways for the research framing

1. **The comparison primitive is the load-bearing decision**, not TimeCrypt's replacement.
   TimeCrypt actually covers the most common temporal reductions; the insufficiency lives in
   layers 3–4. The single primitive that unlocks the most rules is
   *comparison-against-public-constant on an encrypted aggregate*. OPE/ORE buys this (and the
   `>= a < b` bands) but leaks global order — a real confidentiality cost. A comparison gadget
   (garbled circuit / DPF-based) or a TEE leaks less but costs interaction or trust. The
   expressiveness ceiling is set by how much the comparison primitive leaks.

2. **Division is the second axis, and it's separable.** Most ratio alerts reduce to
   `a > k·b`, i.e. a two-ciphertext comparison once the scalar is folded in. If the comparison
   primitive can compare two ciphertexts (not just ciphertext-vs-constant), layers 3-division
   and 4 collapse into one mechanism. Clean, defensible scope boundary.

3. **Non-linear window functions are the honest "out of scope" set.** `max_over_time`,
   `quantile_over_time`, `changes` need either a different digest (TimeCrypt's HEAC-style tree
   can't produce a max) or a TEE fallback. Naming this set explicitly *is* the
   query-expressiveness target.

4. **The multi-writer angle re-enters at layer 3.** `a − b` and `a/b → a > k·b` assume
   operands are homomorphically combinable. Cross-series rules joining across writers
   (`on(instance) group_left`) need operands under a shared encoding — the multi-writer
   secure-aggregation problem. Layer 1 joins and layer 3 cross-series arithmetic are where
   multi-writer stops being free.

## Source

Rule corpus: `samber/awesome-prometheus-alerts` (`_data/rules.yml`, 940+ rules / 93 services).
The operator vocabulary was extracted from a large representative sample (~200 rules across
resource monitoring, hardware, containers, blackbox, databases); remaining services reuse the
same constructs.

## Open / proposed next step

Build a labeled CSV over the full 940-rule file: each rule tagged with the operator set it uses
and which of the four bins it lands in, producing a citable coverage histogram (e.g. "X% need
only comparison-vs-constant, Y% add division, Z% need a non-linear window") to anchor the
expressiveness target empirically.