My recommendation is to build this as a **Prometheus-aware encrypted namespace store**, not as a fully encrypted PromQL engine. Concretely: use a **capability-based authorization plane** for writers/readers, a **multi-writer searchable-encryption metadata plane** for metric names and selected labels, and a **TimeCrypt-style chunk/digest plane** for metric values. That matches Prometheus’s actual model—time series identified by metric name plus labels, queried through label selectors, range windows, and aggregations—and it aligns with the literature: TimeCrypt is a strong template for encrypted time-series analytics, while Omnes, DSE, and Hermes exist because multi-writer encrypted search needs more than naïve public-key search. ([Prometheus][1])

I would **not** try to support full PromQL under encryption. I would support a deliberate subset well: metric-name selection, exact-match private label filters, time-range selection, `sum`, `avg`, `count`, `rate`, and `by` aggregations over selected labels. I would move **exact comparisons, alert thresholds, and recording-rule materialization** to a trusted querier/rule-evaluator client. Forcing exact server-side `min`, `max`, and threshold comparisons over secret raw values pushes you toward OPE/ORE or much heavier MPC/FHE; that is the wrong tradeoff for a first serious design. CryptDB used OPE precisely to enable range/MIN/MAX/ORDER BY, and also explicitly treated it as weaker because it reveals order. ([Prometheus][2])

## 1. Concrete end-to-end architecture

### A. Trusted Authority

The TA is the **policy compiler, KMS, and capability issuer**. It defines a **namespace policy** for each protected Prometheus metric family:

`N = (metric-family, metric-type, fixed labels, variable labels, searchable labels, groupable labels, chunk size Δ, digest schema, epoch)`

Example:

`http_requests_total`
fixed labels: `job="frontend"`
variable labels: `instance = writer-id`, `method ∈ {GET,POST}`, `code ∈ {200,400,500}`
searchable labels: `method`, `code`, `instance`
groupable labels: `job`, `instance`, `method`, `code`
metric type: counter

This is Prometheus-native because Prometheus identifies a series by **metric name + label set**, and every unique label combination creates a different time series. Prometheus also warns that high-cardinality labels explode the number of series, so the searchable/groupable set should be intentionally small and low-cardinality. ([Prometheus][1])

The TA derives and distributes per-namespace key material:

* `K_idx^N`: metadata-index/update capability
* `K_query^N`: query-token capability for readers
* `K_raw^N`: raw chunk encryption root
* `K_agg^N`: aggregate-digest encryption root
* `K_time^N`: time-bucket / interval capability
* `cert_w^N`: writer certificate binding writer identity to namespace policy
* `cap_r^N`: reader capability binding a reader to allowed fields, groupings, and time scope

My strong recommendation is to make these **epoch-scoped** so revocation is practical and so the metadata plane can inherit forward-privacy ideas from Omnes/DSE/Hermes. Omnes and DSE are directly relevant here because they target sublinear multi-writer search with forward privacy, while DSE also adds integrity against malicious clients. Hermes is attractive as a harder-to-attack upgrade because it explicitly targets forward privacy and resilience to dictionary attacks. 

### B. Trusted scrape target component

Do **not** put the trust anchor in the exporter process itself. Put it in a **trusted publisher agent** beside the exporter. The cleanest operational fit is Prometheus **Agent Mode**, because it keeps Prometheus scraping semantics and service discovery but disables local TSDB, alerting, and rule evaluation and optimizes for remote write. The remote-write spec is already built around a sender scraping exporters and shipping labels plus timestamp/value samples to a remote receiver. ([Prometheus][3])

The publisher agent does five things:

1. Scrape the local exporter.
2. Canonicalize the metric name and label set.
3. Check the sample against the TA-issued namespace policy.
4. Build encrypted metadata, raw chunks, and aggregate digests.
5. Send them to the untrusted server via an encrypted remote-write-compatible path. ([Prometheus][4])

This component is also where write authorization lives. If the exporter is compromised but the agent and its keys remain trusted, the exporter cannot mint unauthorized metric/label combinations. If the same compromised component holds the capability and the policy checker, that guarantee collapses. That is an architectural fact, not a cryptographic bug. The paper should say this plainly.

### C. Untrusted Prometheus-compatible encrypted server

The server has four logical stores:

1. **Metadata index store**
   Encrypted inverted indexes for selected searchable atoms such as `(__name__=http_requests_total)`, `(method=GET)`, `(code=500)`, and opaque field identifiers for groupable labels.

2. **Raw chunk store**
   AEAD-encrypted compressed samples, stored in fixed-size time chunks.

3. **Digest store**
   Additively homomorphic encrypted per-chunk digests for `sum`, `count`, counter deltas, and optional histogram/sketch summaries.

4. **Integrity/commitment log**
   A Merkleized append-only log or at least signed manifests so readers can detect dropped or modified chunks. DSE’s integrity concerns around malicious clients are relevant here on the ingest side, and TimeCrypt explicitly aimed to combine encrypted processing with integrity. 

The server never decrypts metric names, label names, label values, or metric values. It only manipulates **opaque field IDs, opaque equality/grouping tags, ciphertext chunks, and homomorphic digest ciphertexts**.

### D. Queriers

A querier is a **trusted client with keys**. Dashboards, automation, and alert/rule evaluators are all queriers.

A querier compiles a PromQL query into:

* metadata predicates over metric name and exact-match labels
* a time interval
* an aggregation plan
* an optional grouping plan

The server executes the encrypted prefilter and encrypted aggregation. The querier decrypts either the final aggregate ciphertext or the returned raw chunks and then does whatever PromQL post-processing is still needed locally.

### E. Trusted rule/alert evaluator

Prometheus normally evaluates recording rules and alerting rules at intervals, but Agent Mode disables rule evaluation. That is actually useful here: move rule evaluation out of the untrusted server and into a **trusted rule-evaluator querier**. Prometheus’s own docs say recording rules and alerting rules are evaluated at regular intervals, and alerting rules are based on PromQL expressions that produce vector elements meeting a condition. In this design, the rule evaluator is simply a privileged reader, and for recording rules it is also a writer that re-encrypts derived series and writes them back. ([Prometheus][5])

That is the cleanest way to support alerts and recording rules **without** giving the untrusted server comparison power over decrypted values.

---

## 2. Recommended primitives for each Prometheus component

### Metric names

Treat metric names as the special Prometheus field `__name__`, because PromQL already models them that way for matching. Index them with the same encrypted metadata mechanism as other searchable fields. I would store an opaque field ID for `__name__` and a searchable encrypted posting list for `(fid___name__, metric_name)`. ([Prometheus][2])

**Primitive choice:** a **DSE/Hermes-class structured-search layer** for exact-match predicates, not IBE/ABE on the hot path. Omnes shows why plain PKSE is too expensive in practice; DSE and Hermes are much closer to what you need for multi-writer searchable metadata. 

### Label names

Do **not** store label names in plaintext. Give each label name an opaque field identifier:

`fid_l = PRF(K_field^N, label_name)`

The server sees repeated opaque field IDs, so it can tell when two predicates use the same hidden field, but it never sees the plaintext label name.

**Why this instead of “fully hidden pair tokens only”?** Because you need grouping. For `sum by (job, cluster)`, the server must know which hidden fields to project onto. Opaque field IDs let it do that without learning plaintext names.

### Label values

For each searchable label field `l` and allowed value `v`, the writer adds the series/chunk ID to a posting list indexed by a search token for `(fid_l, v)`.

For **groupable** labels, the writer also stores a deterministic equality tag for the value:

`g_l(v) = PRF(K_group,l^N, v)`

At query time, the server can group by the tuple of group-tags for the requested label set.

**Important restriction:** only a **small, curated, low-cardinality** subset of labels should be searchable or groupable. Prometheus explicitly warns against high-cardinality labels because each unique label combination becomes a new time series. That warning is not just operational advice here; it is a cryptographic design constraint. High-cardinality labels should usually be stored only inside the encrypted metadata envelope and filtered client-side after decryption. ([Prometheus][6])

### Metric values

Use **two value representations**, not one:

1. **Raw chunk encryption**
   AEAD-encrypted compressed samples for exact recovery and client-side fallback queries.

2. **Encrypted aggregate digest**
   A TimeCrypt-style additively homomorphic digest per chunk. TimeCrypt stores time-ordered chunks plus encrypted digests and uses additively homomorphic encryption on the digests to support efficient statistical queries over ranges. 

For **gauges**, the digest should include at least:

* `sum`
* `count`
* optionally `sumsq`
* optionally bucketized sketch / histogram summary

For **counters**, the digest should include at least:

* adjusted total increase within the chunk
* first timestamp / last timestamp
* first value / last value
* sample count
* reset metadata or reset-adjusted delta

This gives the server enough to homomorphically aggregate range results while leaving final extrapolation and edge-case handling to the reader, which fits Prometheus’s `rate()` semantics better than trying to do everything server-side. Prometheus defines `rate()` as the per-second average increase over the range, adjusted for counter resets and extrapolated to the range boundaries. ([Prometheus][7])

For **histogram metrics**, I would go further and store **encrypted native-histogram digests**. Native histograms are now a first-class Prometheus sample type, carrying count, sum, and sparse buckets in one sample, and PromQL already supports `histogram_count`, `histogram_sum`, `histogram_fraction`, and `histogram_quantile` on them. That makes them a much better substrate for threshold-ish analytics than OPE/ORE on raw values. ([Prometheus][8])

### Time ranges and timestamps

Do **not** use ORE/OPE for timestamps. Use **fixed-size time chunks** plus a **hierarchical time capability tree** in the style of TimeCrypt. TimeCrypt’s access tokens can cover intervals with `O(log n)` tree nodes and support dynamic resolution changes over time. PromQL range vectors already work as explicit time windows like `[5m]`, so chunked interval selection is a natural fit. 

---

## 3. How the system supports the requested PromQL operations

## Exact label matching

Supported for indexed private labels using encrypted exact-match search tokens. PromQL exact label selectors already use equality matchers like `job="prometheus"` and metric-name selection can be expressed through `__name__`. ([Prometheus][2])

Query compilation for:

```promql
http_requests_total{job="frontend",method="GET"}
```

becomes:

* token for `(__name__=http_requests_total)`
* token for `(job=frontend)`
* token for `(method=GET)`

The server intersects the corresponding posting lists and gets matching series/chunks. It never sees the plaintext metric or label values; it sees only hidden field IDs and search tokens.

## Label-based filtering

I would support **conjunctive equality filters** on private labels in v1.

I would **not** support full private-label regex or arbitrary negative matching server-side. PromQL supports `=`, `!=`, `=~`, and `!~`, but regex and negative matching over hidden labels are expensive and leakage-prone unless the domains are tiny or public. My recommendation is:

* `=` on private indexed labels: supported
* conjunction of `=` predicates: supported
* `!=`, `=~`, `!~` on private labels: not supported server-side in v1
* regex/negative matching on explicitly public labels: optional
* anything else: fetch-decrypt-filter client-side ([Prometheus][2])

That is a real semantic restriction, and I would state it explicitly in the paper.

## Range queries

Supported directly through chunking plus encrypted time selection. PromQL range vectors select a window such as `[5m]`; the server maps that to chunk IDs and aggregates over the covered chunks. For edge chunks, the server can return encrypted boundary samples or boundary digests so the reader can finalize interpolation exactly where needed. ([Prometheus][2])

## `sum`, `average`, `count`, `rate`

These are the sweet spot.

* `sum`: server homomorphically adds `sum` digests. PromQL `sum(v)` already means summing sample values. ([Prometheus][9])
* `avg`: server adds `sum` and `count` digests; reader divides after decryption. PromQL defines `avg(v)` as sum divided by number of aggregated samples. ([Prometheus][9])
* `count`: for `count(v)`, the server counts matched series/elements; for `count_over_time`, the digest’s sample-count component handles it. PromQL’s `count(v)` counts the number of values at a timestamp. ([Prometheus][9])
* `rate`: for counters, the server adds per-chunk adjusted deltas; the reader finalizes per-second normalization and boundary extrapolation. PromQL’s `rate()` is explicitly reset-aware and extrapolates to the window edges. ([Prometheus][7])

A concrete example:

```promql
sum by (job,cluster) (rate(http_requests_total{method="GET"}[5m]))
```

Execution plan:

1. search tokens for `(__name__=http_requests_total)` and `(method=GET)`
2. time interval `[now-5m, now]`
3. grouping fields `job, cluster`
4. server: intersect index lists, select chunks, group by hidden `(job,cluster)` tags, homomorphically add counter-delta digests
5. reader: decrypt per-group totals and divide by elapsed time

That is a good, realistic encrypted subset.

## Group-by aggregations

Supported for **whitelisted groupable labels** using hidden field IDs plus deterministic per-field value tags. PromQL aggregation operators already support `by (...)` and `without (...)`; `by` preserves only the listed labels, while `without` removes the listed ones. ([Prometheus][9])

I would support:

* `by (l1, l2, ...)` for groupable private labels
* `without (...)` only over the configured groupable-label universe, or equivalently rewrite it into a `by` clause client-side

The server groups on tuples of hidden equality tags. It learns that two hidden groups are the same, and how big they are, but not the plaintext label values.

To render results, the server returns one encrypted metadata envelope per output group. The reader decrypts that envelope and displays the actual `job`, `cluster`, etc.

## `min` and `max`

I would **not** support exact server-side `min`/`max` over private raw values in the base design.

PromQL defines `min(v)` and `max(v)` over float samples, and CryptDB’s old answer to this kind of operation was OPE because OPE directly enables MIN/MAX/ORDER BY. But CryptDB also explicitly treated OPE as weaker because it reveals order, and the ORE literature likewise makes clear that order-revealing comparison intrinsically exposes ordering. ([Prometheus][9])

My recommendation:

* **Exact `min`/`max` on secret raw values:** reader-side only
* **Approximate `min`/`max` or threshold-style analytics:** use encrypted histogram/sketch digests, ideally native-histogram-based for compatible metrics

That is a Prometheus-aware tradeoff: if users truly need percentile/threshold/min/max-style analytics, instrument those metrics as native histograms or have the writer emit bucketized sketches.

## Alert thresholds

Base design: **threshold evaluation happens in the trusted alert evaluator**, not inside the untrusted server.

PromQL comparison operators like `>`, `<`, `>=`, `<=` are filter operators by default. Prometheus alerting rules are built from PromQL expressions whose vector elements satisfy a condition. ([Prometheus][9])

So the clean design is:

1. server computes encrypted aggregate result
2. alert evaluator reader decrypts it
3. alert evaluator applies the threshold condition
4. alert evaluator sends alerts to Alertmanager

This preserves end-to-end secrecy and keeps the comparison primitive off the server.

If you insist on some **server-side thresholding**, I would only do it for **derived histogram/sketch summaries**, not raw values. That gives approximate threshold counts/fractions without OPE.

## Recording rules

Supported, but not by the untrusted server.

Prometheus recording rules precompute expensive expressions as new time series and are evaluated periodically. In this design, a trusted rule-evaluator querier runs the rule, decrypts the result, and then re-encrypts the derived series under a TA-approved writer namespace and writes it back. ([Prometheus][10])

This is a major design choice, but it is the right one. It keeps the server blind and still lets you preserve most of the Prometheus operational model.

---

## 4. Leakage profile

## What the server inevitably learns

Even in the best single-server version, the server will learn:

* ingestion timing and traffic volume per writer
* chunk boundaries and approximate retention shape
* query arrival times and frequencies
* how many chunks / postings are touched by a query
* result cardinalities and group sizes
* hidden-field reuse and hidden-value equality classes for indexed/grouped metadata
* temporal locality of accesses

That is the standard reality of practical encrypted search and encrypted time-series systems. DORY is useful context here: it exists precisely because hiding search access patterns efficiently usually requires **distributed trust**, not a single server. MUSES likewise framed search/result/volume leakage as a central limitation of prior encrypted-search designs. 

## Additional leakage from searchable encryption

With a DSE/Hermes-class metadata layer, you still have to expect at least:

* **search-pattern leakage**: repeated searches for the same hidden atom can often be linked
* **access-pattern leakage**: repeated result sets or overlapping result sets can be linked
* **result-size leakage**
* **update leakage** unless you add forward privacy
* **dictionary-attack risk** on low-entropy fields unless you harden the scheme

This last point matters a lot in Prometheus because many labels are low-entropy: HTTP method, status code, job names, environment names. Hermes is attractive specifically because it advertises resilience to dictionary attacks in multi-writer encrypted search. DSE is attractive because it gives multi-writer/multi-reader search plus integrity against malicious clients. 

## Additional leakage from deterministic grouping tags

Grouping by hidden labels necessarily reveals **equality classes** for those labels. The server will not know that a given hidden tag means `job="frontend"`, but it will know that all rows with the same hidden tag belong to the same group and how many such rows there are.

I think that leakage is acceptable **if** you are explicit that:

* it applies only to labels intentionally marked groupable/searchable
* those labels are low-cardinality
* all other labels stay opaque and unindexed

Prometheus’s own label-cardinality guidance supports this narrowing. ([Prometheus][6])

## Additional leakage from ORE/OPE

I would treat OPE on raw metric values as **unacceptable** here. CryptDB used OPE to enable range/MIN/MAX/ORDER BY and explicitly said OPE is weaker because it reveals order. The ORE paper is clearer still: order-preserving encryption has limited guarantees, while order-revealing comparison inherently reveals order. 

For this problem, raw metric values are often highly structured and repeatedly queried. Global order leakage over them is too damaging.

## Additional leakage from homomorphic digests

TimeCrypt-style digests do **not** reveal raw values, but they do reveal which chunks are included in which aggregate, unless you add a stronger oblivious-access layer. They also expose the shape of the query plan to the extent that the server knows which digests it is summing. 

## What is likely acceptable to a USENIX Security audience

My judgment:

Likely acceptable if stated honestly:

* equality leakage on a whitelisted set of indexed low-cardinality labels
* result-size leakage
* time-bucket leakage
* access-pattern leakage in the single-server baseline
* forward-private metadata updates as a mitigation

Likely not acceptable as the main story:

* “the server learns no metadata” when searchable/groupable tokens clearly leak structure
* OPE/ORE on raw metric values
* claiming “substantial PromQL support” while quietly requiring client-side execution for most real queries

That is an inference from how DORY and MUSES frame leakage and how the encrypted-query literature treats order leakage. 

---

## 5. Multi-writer analysis

## How independent scrape targets contribute to the same namespace

The right abstraction is **many writers per namespace, ideally one writer per exact series**.

A namespace can cover many exact series, for example:

`http_requests_total{job="frontend", instance=*, method∈{GET,POST}, code∈{200,400,500}}`

Different targets can contribute different `instance` values within that namespace. The server merges them naturally because Prometheus already treats each distinct metric-name-plus-label-set as a distinct series. ([Prometheus][1])

I would **avoid** allowing many writers to append to the exact same series unless you truly need it. It creates replay/dedup/order questions that are annoying even before encryption. If you must allow it, then manifests need writer IDs, monotonic sequence numbers, and replay detection.

## How the TA prevents unauthorized metrics/labels

There are two layers:

### Cryptographic layer

Each writer gets:

* a namespace certificate `cert_w^N`
* update capability for only the authorized searchable/groupable atoms
* raw/digest encryption roots only for the authorized namespace
* a signing key or certificate for chunk manifests

Each chunk manifest binds:

* writer ID
* namespace ID
* hidden series ID
* chunk interval
* hashes of raw ciphertext and digest ciphertext
* epoch / sequence number

The server verifies the certificate and signature before accepting the write. Readers verify the manifest chain when reading. DSE is relevant here because it explicitly models integrity against malicious clients in the multi-writer setting. 

### Policy-model layer

This only works cleanly when the label policy is **fixed or bounded**:

* fixed labels like `job="frontend"`
* labels derived from writer identity like `instance = writer-id`
* labels drawn from a bounded domain like `method ∈ {GET,POST}`

If you allow arbitrary free-form future label values, pure offline cryptography cannot stop a writer from inventing new ones unless you add online authorization or a much heavier predicate system. Fortunately, Prometheus already discourages high-cardinality, unbounded labels. ([Prometheus][6])

## What a compromised target can still do

Even in this design, a compromised writer that still controls its trusted agent can **lie about values within its authorized namespace**. Your scheme enforces **which series identities may be minted**, not whether the observed metric is truthful. That is the right claim.

If you want stronger guarantees, you need one of:

* a trusted publisher agent outside the compromised exporter
* a hardware root such as a TEE/HSM
* attested local metadata for some labels

That point should be explicit in the threat model.

## Best-fit primitive family

My opinionated answer:

* **Best fit overall:** capability-based cryptography + hierarchical key derivation + DSE/Hermes-class encrypted metadata index
* **Useful as a control-plane tool:** HIBE / key-hierarchy ideas for namespace delegation
* **Useful only for coarse key wrapping:** CP-ABE
* **Poor fit for the hot path:** per-sample ABE / FE
* **Not my first choice:** plain IBE/PEKS on the data path

Why:

* Omnes explains the performance gap: PKSE search is too expensive, SSE is not naturally multi-writer, and HSE exists to bridge that. 
* DSE is directly aimed at multi-writer, multi-reader search with integrity. 
* Hermes adds forward privacy and dictionary-attack resilience, which is especially relevant because Prometheus metadata often lives in small dictionaries. ([IACR Eprint Archive][11])
* TimeCrypt explicitly notes that adding homomorphic capability to ABE remains limited and expensive. 

So my recommendation is: **do not build the data plane around ABE**. Use ABE only if you want convenient coarse-grained distribution of namespace capabilities to organizational roles.

---

## 6. Hardest unsolved problems and the strongest research contributions

## 1. Prometheus-native write authorization

This is the most distinctive research problem.

Generic encrypted-search papers talk about keywords and documents. Prometheus talks about **metric families, label schemas, and exact series identities**. A strong contribution would be a formal model of **authorized labeled time-series namespaces**, where a writer is authorized to mint only certain metric/label combinations and readers are authorized to retrieve only certain namespaces. Prometheus’s own model that a series is metric name plus label set is what makes this different. ([Prometheus][1])

**Potential contribution:**
A new cryptographic authorization model and construction for **certified Prometheus namespaces** with bounded-label policies.

## 2. Queryable private labels without collapsing under cardinality

Prometheus label cardinality is where generic SSE intuition breaks. You need a metadata index that supports:

* exact-match filtering
* grouping on selected labels
* many writers
* many readers
* bounded leakage
* realistic ingest rates

**Potential contribution:**
A **Prometheus-aware structured index** that separates:

* searchable labels
* groupable labels
* opaque labels
* raw-only labels

and proves leakage/performance bounds under realistic cardinality assumptions. Prometheus’s own best-practice guidance about label cardinality helps justify this restricted model. ([Prometheus][6])

## 3. Reset-aware encrypted `rate()` semantics

This is more interesting than it looks. Prometheus `rate()` is not just “last minus first divided by time.” It adjusts for resets and extrapolates to range boundaries. ([Prometheus][7])

**Potential contribution:**
A new **counter-aware encrypted digest** that preserves PromQL `rate()` / `increase()` semantics closely enough to be useful, without shipping all raw samples back to the reader.

That would feel genuinely Prometheus-specific rather than generic encrypted query processing.

## 4. Comparison-heavy queries without OPE

This is the hardest unsolved piece.

If you insist on server-side exact `min`, `max`, and threshold checks over private raw values, you are back in comparison cryptography. OPE leaks too much. ORE still reveals order. Generic FE/FHE/MPC is too heavy for the full Prometheus ingest path. 

**Potential contribution options:**

* **Practical path:** require histogram/sketch instrumentation for metrics that need threshold/percentile/min-max-like analytics, then operate on encrypted histogram digests.
* **Ambitious path:** add a **two-server comparison service** only for final aggregate outputs, not for every raw sample. DORY and MUSES both show that distributed trust can materially improve privacy properties in encrypted search. 

That second option could elevate the work beyond straightforward integration.

## 5. Trusted rule evaluation loop

This is not just engineering polish. Moving alerting/recording rules to a trusted reader/writer loop gives you a clean systems architecture that preserves Prometheus’s operational model while keeping the server blind.

**Potential contribution:**
A secure architecture for **reader-executed Prometheus rules over encrypted data**, with re-encryption of derived metrics back into the store.

That is especially nice because Prometheus already separates scraping, querying, rules, and alert delivery operationally. ([Prometheus][3])

---

## My strongest opinionated summary

I would build the system around this core idea:

**Three representations per sample**

1. encrypted metadata atoms for private exact-match filtering and grouping
2. AEAD-encrypted raw chunks for correctness and fallback
3. TimeCrypt-style homomorphic digests for range aggregation

And I would make these restrictions explicit:

* private-label server-side filtering is **equality only**
* group-by is only over **whitelisted low-cardinality labels**
* exact server-side `min`/`max`/thresholds on raw secret values are **not supported**
* alerts and recording rules run in a **trusted querier/rule-evaluator**
* high-cardinality/private labels are **opaque and client-filtered**

That is the version I think is both technically coherent and publishable.

The two places where the paper can become more than integration are:

1. a **formal, Prometheus-native namespace authorization model**, and
2. a **reset-aware encrypted digest/query model** for `rate`/`increase`/grouped rollups that generic SSE papers do not capture.

If you want, I can next turn this into a **paper-ready system section** with algorithms, notation, and one worked query path end to end.

[1]: https://prometheus.io/docs/concepts/data_model/ "Data model | Prometheus"
[2]: https://prometheus.io/docs/prometheus/latest/querying/basics/ "Querying basics | Prometheus"
[3]: https://prometheus.io/docs/prometheus/latest/prometheus_agent/ "Prometheus Agent Mode | Prometheus"
[4]: https://prometheus.io/docs/specs/prw/remote_write_spec/ "Prometheus Remote-Write 1.0 specification | Prometheus"
[5]: https://prometheus.io/docs/prometheus/latest/configuration/recording_rules/ "Defining recording rules | Prometheus"
[6]: https://prometheus.io/docs/practices/naming/ "Metric and label naming | Prometheus"
[7]: https://prometheus.io/docs/prometheus/latest/querying/functions/ "Query functions | Prometheus"
[8]: https://prometheus.io/docs/specs/native_histograms/ "Native Histograms | Prometheus"
[9]: https://prometheus.io/docs/prometheus/latest/querying/operators/ "Operators | Prometheus"
[10]: https://prometheus.io/docs/prometheus/latest/configuration/recording_rules/?utm_source=chatgpt.com "Defining recording rules - Prometheus"
[11]: https://eprint.iacr.org/2025/701.pdf?utm_source=chatgpt.com "Hermes: Efficient and Secure Multi-Writer Encrypted Database"
