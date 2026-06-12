# TimeCrypt → Go Port Plan

Goal: port the TimeCrypt crypto core (Java, `timecrypt/timecrypt-crypto`) to a Go
module so Prometheus can store **encrypted sample values** the same way it already
stores an **encrypted inverted index** (label→seriesRef) via
[clusion-go](https://github.com/aashutoshpaudyal/clusion-go) (DynRH2Lev SSE).

The combined target is an end-to-end encrypted Prometheus:

| Layer | Plaintext Prometheus | Encrypted Prometheus |
|---|---|---|
| Inverted index (`label=value` → series refs) | `index.MemPostings` | `index.EncryptedMemPostings` (clusion-go SSE) — **done** |
| Sample values | float64 in XOR chunks | HEAC additively-homomorphic ciphertexts (timecrypt-go) — **this work** |

## Why HEAC fits Prometheus values

HEAC (the TimeCrypt scheme, NSDI'20 Burkhalter et al.) encrypts value `m_i` at time
index `i` as `c_i = m_i + k_i - k_(i+1)` (mod 2^64 or mod M). Adjacent keys telescope:

```
sum(c_i, i=a..b) = sum(m_i) + k_a - k_(b+1)
```

so an untrusted server can **sum ciphertexts over any time range** and the client
decrypts the aggregate with just the two boundary keys. Keys `k_i` come from a
PRF-based binary tree ("key regression"), so the client stores one master seed per
stream and can delegate bounded time ranges by revealing inner tree nodes.
This matches Prometheus's dominant query shapes (`sum_over_time`, `rate`, `avg`)
which are sums over time windows.

## Source → target map (Java → Go)

Module: `github.com/aashutoshpaudyal/timecrypt-go`, flat package `timecrypt`
(same conventions as clusion-go). Java source of truth:
`timecrypt/timecrypt-crypto/src/main/java/ch/ethz/dsg/timecrypt/crypto/`.

| Java | Go file | Notes |
|---|---|---|
| `prf/IPRF.java`, `prf/PRFAes.java` | `prf.go` | AES-128 single-block PRF (AES-ECB over one block). AES-NI comes free from Go's `crypto/aes`. |
| `keyRegression/TreeKeyRegression.java` (+`SeedNode`, `TreeKeyRegressionNode`, factory) | `keyregression.go` | Owner tree from a root seed; receiver tree from revealed seed nodes (`RevealSeeds` = sharing/views). `InvalidKeyDerivation` → error. |
| `keymanagement/KeyUtil.java` | `keyutil.go` | Key derivation from leaf seeds: enc-input `FF^8 ‖ id_be64`, mac-input `id_be64 ‖ FF^8`, default `FF^16`; 128-bit PRF output folded by XOR into `bits`-sized keys (big.Int) or int64. |
| `keymanagement/StreamKeyManager.java`, `CachedKeys.java` | `streamkeys.go` | Per-stream key hierarchy: master seed → (metadata tree, MAC key, sharing key). |
| `encryption/HEAC/HEACEncryptionLong.java` | `heac.go` | int64 arithmetic; Java long overflow == Go int64 wraparound. |
| `encryption/HEAC/HEACEncryptionBI.java` | `heac.go` | big.Int mod M; `decryptLong/Int` negative-number adaptation. |
| `encryption/hoMAC/{IHoMAC,HoMAC,HomomorphicMAC}.java` | `homac.go` | Additively-homomorphic MAC over Z_p, p = 2^128-159. Both variants ported. |
| `encryption/TimeCryptEncryption{Long,BI}{,Plus}.java` | `encryption.go` | The client-facing wrappers: (timeID, metadataID)-addressed encrypt/decrypt, `Plus` = with hoMAC auth tags. `MACCheckFailed` → sentinel error `ErrMACCheckFailed`. |
| `encryption/TimeCryptChunkEncryption.java` | `chunk.go` | AES-GCM with 12-byte nonce prefix, for raw chunk payloads. |
| `src/test/java/TestTimeCryptCrypto.java`, `TestTreeKeyRegression.java` | `*_test.go` | Same assertions ported; plus cross-language fixture-free invariants (telescoping sums, MAC aggregation, share-derive equality). |

Deliberately **not** ported (out of scope for value encryption in Prometheus):
`LabelTreeKeyRegression`, `OldTreeKeyDerivation` (legacy/alternative derivations),
`serialize/`, `sharing/EnvelopeCrypto` (gRPC sharing envelope), the whole
timecrypt-server and timecrypt-client modules — Prometheus's TSDB *is* the server here.

## Java→Go semantic gotchas (checked against source)

1. **Java `long` wraps silently** — HEAC-Long relies on this (`msg + k1 - k2`).
   Go int64 `+`/`-` also wrap (defined behavior). Direct port is sound.
2. **`new BigInteger(1, bytes)`** = unsigned → Go `new(big.Int).SetBytes`.
   **`new BigInteger(bytes)`** (StreamKeyManager MAC key) = signed two's-complement →
   needs an explicit signed conversion helper.
3. **Java `mod`** is always non-negative → Go `Int.Mod` (Euclidean) matches.
4. **`PRFAes.apply(key, int)`** packs the int big-endian in the last 4 of 16 bytes →
   `binary.BigEndian.PutUint32(block[12:16], uint32(x))`.
5. **`KeyUtil.deriveKeyLong`** = XOR-fold 16-byte PRF output into 8 bytes, big-endian
   signed → `int64(binary.BigEndian.Uint64(...))`.
6. HoMAC prime `2^128-159` has bitLength 128, so MAC keys use the whole PRF block
   (1 partition); HEAC-BI with `mBits=64` XOR-folds two 64-bit halves.

## Prometheus integration (phase 2)

1. Add `../timecrypt-go` to `prometheus/go.work` (same as clusion-go).
2. New scratch test in `prometheus/tsdb/scratch_test.go` —
   `TestScratchEncryptedValues` — demonstrating the full client/server split,
   mirroring `TestScratchEncryptedMemPostings`:
   - **Client**: per-series `StreamKeyManager` (master seed). Each sample value
     (float64) → fixed-point int64 (configurable scale, e.g. 1e6) → HEAC-Long
     ciphertext with timeID = per-series sample index.
   - **Storage**: ciphertext int64 stored bit-for-bit as a float64 sample
     (`math.Float64frombits`) in the real TSDB head — XOR chunk encoding preserves
     bits exactly. (A production design would add a chunkenc encoding for int64
     ciphertexts; documented limitation, see PROGRESS.md.)
   - **Query**: label selector resolved via the *encrypted* index (SSE token →
     ciphertext refs → client-side resolve), then the server-side aggregate is the
     plain int64 sum of the ciphertexts over the time range — no keys involved —
     and the client decrypts `sum` with the two boundary keys and un-scales.
3. Optionally a `TimeCryptAppender`-style helper kept inside the test until the
   design settles.

## Order of work

1. `PLAN.md` / `PROGRESS.md` (this doc) ✔
2. Go module + crypto core port (prf, keyregression, keyutil, streamkeys)
3. HEAC + hoMAC + wrappers + chunk encryption
4. Ported test suite green (`go vet`, `go test ./...`)
5. go.work wiring + `TestScratchEncryptedValues` green inside prometheus/tsdb
6. Progress + design notes updated in *.md as each step lands
