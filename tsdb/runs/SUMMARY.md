# Encrypted-search query-overhead — benchmark summary

Comparison of a **plaintext baseline** TSDB query against the **encrypted-search
prototype** (CJJJKRS / DynRH2Lev for the `label=value → series-ref` inverted
index, plus TimeCrypt HEAC for sample values) over three dataset sizes.

The modelled query is `avg_over_time(cpu_usage_ratio{vendor="intel"}[range])`:
match the encrypted label pair, homomorphically SUM the matching series'
ciphertext samples, then (client-side) decrypt the aggregates and compare to a
threshold.

## Trust boundary

The phases are split by **who can do them**, because the whole point of the
scheme is that the Prometheus server holds no keys:

- **server/\*** — keyless, runs on the untrusted Prometheus server
  (`cjjjkrs_match` = match the search token against the encrypted multimap;
  `retrieve_sum` = scan chunks and additively combine ciphertexts).
- **client/\*** — needs the master key, runs on the trusted key holder
  (`gen_token` = derive the search trapdoor; `resolve_refs` = decrypt identifier
  ciphertexts to series refs; `timecrypt_decrypt` = HEAC-decrypt the per-series
  aggregates). **Decryption is client-side only** — the server cannot decrypt,
  the aggregate goes to the client for the `> threshold` comparison.

## Datasets

All seeded (`-scratch.seed=1`); samples are spaced 1 s apart in TSDB time, and
the TimeCrypt stream index is the sample ordinal `t = 0,1,2,…`. The selector
`vendor="intel"` matches ~1/3 of series (vendor cycles intel/amd/arm).

| Run | Series | Samples/series | Matched series | Fixture | Source file |
|---|---:|---:|---:|---:|---|
| 2×2 | 2 | 2 | 1 | tiny | `bench-20260612-125434.txt` |
| 20×200 | 20 | 200 | 7 | ~small | `bench-20260612-130217.txt` |
| 1000×5000 | 1000 | 5000 | 334 | 135 MB | `bench-20260612-131259.txt` |

## Latency per phase (ns/op)

| Side | Phase | 2×2 (1 matched) | 20×200 (7) | 1000×5000 (334) |
|---|---|---:|---:|---:|
| **Server** | cjjjkrs_match | 2,736 | 11,922 | 224,603 |
| **Server** | retrieve_sum (scan + homomorphic SUM) | 3,368 | 75,245 | 194,398,360 |
| | **→ server total** | **~6,104** | **~87,167** | **~194,622,963** |
| Client | gen_token | 4,145 | 4,094 | 1,822 |
| Client | resolve_refs | 2,262 | 14,548 | 331,219 |
| Client | timecrypt_decrypt | 34,027 | 235,475 | 5,643,658 |
| | **→ client total** | **~40,434** | **~254,117** | **~5,976,699** |
| Both | end_to_end | 51,956 | 447,469 | 204,337,241 |
| *Baseline* | *end_to_end (all server-side)* | *3,896* | *82,318* | *197,649,452* |

### Same data, human units

| Side | Phase | 2×2 | 20×200 | 1000×5000 |
|---|---|---:|---:|---:|
| Server | cjjjkrs_match | 2.7 µs | 11.9 µs | 224.6 µs |
| Server | retrieve_sum | 3.4 µs | 75.2 µs | 194.4 ms |
| Server | **server total** | **~6 µs** | **~87 µs** | **~194.6 ms** |
| Client | gen_token | 4.1 µs | 4.1 µs | 1.8 µs |
| Client | resolve_refs | 2.3 µs | 14.5 µs | 331 µs |
| Client | timecrypt_decrypt | 34 µs | 235 µs | 5.64 ms |
| Client | **client total** | **~40 µs** | **~254 µs** | **~5.97 ms** |
| Both | end_to_end | 52 µs | 447 µs | 204 ms |
| Baseline | end_to_end | 3.9 µs | 82 µs | 197.6 ms |

## Server-side overhead vs plaintext (the number that matters operationally)

| Run | Encrypted server total | Plaintext server (baseline) | Overhead |
|---|---:|---:|---:|
| 2×2 | ~6.1 µs | 3.9 µs | ~1.6× |
| 20×200 | ~87 µs | 82 µs | ~1.06× |
| 1000×5000 | ~194.6 ms | 197.6 ms | ~1.00× (within noise) |

**The encrypted server tax shrinks toward zero as the dataset grows.** It is an
additive cost (the CJJJKRS match), not multiplicative — and it is dwarfed by the
TSDB chunk scan, which the homomorphic SUM rides along with for free.

## If the server also performed decryption (hypothetical)

This is **counterfactual** — the Prometheus server holds no keys and *cannot*
decrypt; identifier resolution and aggregate decryption happen at the trusted
client, and the `> threshold` comparison with them. The table below shows what
the server-side cost *would* be if that decryption were (incorrectly) pushed onto
the server's critical path, i.e. server total **+ both decryptions**
(`resolve_refs`, the identifier decryption, **+** `timecrypt_decrypt`, the value
decryption). It quantifies exactly how much the trust split saves the server.

| Run | Keyless server total | + resolve_refs (id decrypt) | + timecrypt_decrypt (value decrypt) | = server total **with** decryption | vs plaintext baseline | Overhead |
|---|---:|---:|---:|---:|---:|---:|
| 2×2 | 6,104 ns | 2,262 ns | 34,027 ns | **42,393 ns** | 3,896 ns | **~10.9×** |
| 20×200 | 87,167 ns | 14,548 ns | 235,475 ns | **337,190 ns** | 82,318 ns | **~4.1×** |
| 1000×5000 | 194,622,963 ns | 331,219 ns | 5,643,658 ns | **200,597,840 ns** | 197,649,452 ns | **~1.015×** |

### Same data, human units

| Run | Keyless server total | + decryption (resolve + value) | = server total **with** decryption | vs plaintext | Overhead |
|---|---:|---:|---:|---:|---:|
| 2×2 | ~6 µs | +36.3 µs | **~42.4 µs** | 3.9 µs | ~10.9× |
| 20×200 | ~87 µs | +250 µs | **~337 µs** | 82 µs | ~4.1× |
| 1000×5000 | ~194.6 ms | +5.97 ms | **~200.6 ms** | 197.6 ms | ~1.015× |

**Takeaways:**

- Decryption is the single most expensive part of the scheme, and it is exactly
  the part the trust split keeps **off** the server. On the smallest workload it
  would inflate the server's cost ~10.9× (decrypt is 80 % of the total there);
  keeping it client-side is what makes the server overhead ~1.6× instead.
- Even at 1000×5000 the *hypothetical* "server decrypts too" overhead is only
  ~1.015× — because the ~195 ms chunk scan still dominates and decryption
  (~6 ms) scales with matched-series count, not sample volume. So at large scale
  the placement of decryption barely moves the server number; at small scale it
  is decisive. Either way the design choice (decrypt at the client) is strictly
  better for the server and is *required* by the threat model regardless of cost.

## Key findings

1. **The homomorphic SUM is free.** `retrieve_sum` is identical between baseline
   and encrypted at every scale (1000×5000: 194.4 ms vs 198.3 ms). The
   cross-series merge is the *same TSDB code path*; encryption only changes which
   refs feed it and what the sample bits mean. TimeCrypt's additive combine is
   just the int64 additions the scan already performs.

2. **CJJJKRS match scales with fan-out, and amortizes well.** One `label=value`
   pair maps to many series; `cjjjkrs_match` (`QueryCiphertexts`) returns one
   identifier ciphertext per matching series, so its cost is linear in the number
   of matched series — but the per-series constant *drops* with scale:
   ~1.7 µs/series at 7 matched → ~0.67 µs/series at 334. At 334-way fan-out the
   match is 224.6 µs ≈ **0.1 % of the server's query time.**

3. **The merge is two merges; only one is encrypted-specific.** Resolving + sort/
   dedup of the postings list (`resolve_refs`, client) is the encrypted analog of
   merging plaintext postings — cheap, ~1 µs/series. The per-series sample merge/
   scan is unchanged from plaintext.

4. **Decryption dominates client latency but scales with *matched-series count*,
   not samples/series.** It is one aggregate decrypt per matched series
   (~17 µs/series at scale), with only a weak ~log(range) dependence on samples.
   That is why 200→5000 samples did not blow it up: 5.64 ms ≈ 334 × 17 µs. It is
   borne by the trusted key holder, off the server's critical path.

5. **`gen_token` is constant (~2–4 µs)** — one trapdoor per queried label pair,
   independent of dataset size.

## Caveat / next step

At 1000×5000 the server's ~195 ms is the whole-range scan of 334×5000 ≈ 1.67 M
samples, which dominates everything and is identical in both variants — masking
the crypto deltas. To make the SSE/decrypt terms stand out, narrow the query time
range (e.g. last N samples) so the scan shrinks. The crypto costs above are the
ones that then dominate.

## How to reproduce

```bash
# (Re)generate a fixture (overwrites testdata/scratch_benchdata.json):
go test ./tsdb -run TestGenerateScratchData \
  -scratch.numSeries=1000 -scratch.samplesPerSeries=5000 -scratch.seed=1

# Run the benchmarks against whatever fixture is present:
go test ./tsdb -run '^$' -bench '^BenchmarkQuery(Baseline|Encrypted)$' \
  -benchmem -benchtime=2s -timeout=20m
```

Hardware for these runs: INTEL(R) XEON(R) GOLD 5512U, linux/amd64.
