# TimeCrypt-Go Progress Log

Running log of the port + Prometheus integration. Newest entries at the bottom.
See PLAN.md for the overall design and source→target map.

## 2026-06-10 — Kickoff

- Read the Java crypto core (`timecrypt-crypto`, ~2.5k LoC) end to end:
  PRF (AES block), TreeKeyRegression (+ sharing via `revealSeeds`), KeyUtil,
  StreamKeyManager, HEAC Long/BigInt, HoMAC/HomomorphicMAC, the four
  TimeCryptEncryption wrappers, AES-GCM chunk encryption, and both Java test
  classes.
- Confirmed integration conventions from the prior SSE work: clusion-go is a flat
  Go package consumed by `prometheus/go.work` (`use ../clusion-go`), exercised in
  `tsdb/scratch_test.go` (`TestScratchEncryptedMemPostings`) against
  `tsdb/index/postings_encrypted.go`.
- Wrote PLAN.md with the file-by-file port map and the Java→Go semantic gotchas
  (long wraparound, BigInteger sign conventions, PRF input packing, XOR key
  folding).

Status: plan written; starting the crypto core port.

## 2026-06-10 — Crypto core ported, tests green

Module `github.com/aashutoshpaudyal/timecrypt-go`, flat package `timecrypt`,
stdlib-only. Files:

- `prf.go` — `PRF` interface + `AESPRF` (raw AES-128 block, = Java PRFAes).
- `keyutil.go` — key derivation (enc/MAC domain-separated PRF inputs, XOR
  folding into N-bit big.Int or int64 keys), combined chunk keys, random key
  generation, signed-BigInteger helper.
- `keyregression.go` — `TreeKeyRegression` (owner + receiver constructors),
  `GetSeed/GetSeeds/GetKey/GetKeys`, `RevealSeeds` (sharing/views),
  `ErrInvalidKeyDerivation` replaces the Java exception.
- `streamkeys.go` — `StreamKeyManager` (master-seed hierarchy: metadata tree /
  MAC key / sharing key), `CachedKeys`, per-chunk combined AES keys.
- `heac.go` — `HEACLong` (int64, M=2^64 via natural wraparound) and
  `HEACBigInt` (Z_M big-int) with range decryption and negative-value adaption.
- `homac.go` — `HoMAC` (inverse-form) + `HomomorphicMAC` (multiply-form) over
  p = 2^128-159, both aggregatable.
- `encryption.go` — the four client schemes `TimeCryptEncryption{Long,BI}{,Plus}`
  with `TCAuth{Long,BI}Ciphertext` aggregate types; `ErrMACCheckFailed`.
- `chunk.go` — AES-GCM (nonce-prefixed) chunk encryption.
- `fixedpoint.go` — float64 ↔ fixed-point int64 glue for Prometheus values
  (not in the Java original; sums commute with encoding).

Tests (ports of `TestTimeCryptCrypto.java` + `TestTreeKeyRegression.java`,
plus a FIPS-197 AES known-answer test to pin the PRF, chunk-key sharing and
AES-GCM round-trip): **13/13 pass** (`go vet` clean, `go test .` 0.6s).

Porting notes:
- Java `long` overflow == Go int64 wraparound, so HEAC-Long ports directly.
- `new BigInteger(byte[])` (signed) only matters for `StreamKeyManager.MacKeyBigInt`;
  handled by an explicit two's-complement conversion.
- Skipped as planned: `LabelTreeKeyRegression`, `OldTreeKeyDerivation`,
  `serialize/`, `sharing/EnvelopeCrypto`.

Status: core port done; wiring into Prometheus next.

## 2026-06-10 — Prometheus integration done

- Added `../timecrypt-go` to `prometheus/go.work` (same wiring as clusion-go;
  workspace mode resolves the import without touching prometheus/go.mod).
- New `TestScratchEncryptedValues` in `prometheus/tsdb/scratch_test.go`,
  exercising the full client/server split on the real TSDB:
  1. **Client**: per-series `StreamKeyManager` (depth-20 tree → 2^20 time
     steps); each float sample → fixed-point int64 (scale 1e6) → HEAC-Long
     ciphertext at timeID = per-series sample index, slot 0.
  2. **Storage**: the int64 ciphertext is appended as the bit pattern of a
     float64 sample (`math.Float64frombits`); the XOR chunk encoding stores
     bits verbatim, verified by round-trip through `db.Querier`.
  3. **Index**: the label selector `vendor="intel"` resolves through the
     SSE-encrypted index (`index.NewEncryptedMemPostings`, clusion-go):
     GenToken → QueryCiphertexts → ResolveRefs, exactly as in
     `TestScratchEncryptedMemPostings`.
  4. **Server**: sums the opaque int64 sample bits per resolved series —
     no keys involved.
  5. **Client**: one `DecryptMetadata(sum, 0, n-1, 0)` per series using only
     the boundary seeds; sums decrypt to exactly 1.0 (0.3+0.7) and
     1.8 (0.5+1.3). Per-sample decryption ([i,i] ranges) also demonstrated
     as the chunk-scan fallback for non-additive queries.
- All `TestScratch*` tests pass; `go vet` on tsdb shows only pre-existing
  upstream warnings (chunkenc Seek signature), nothing from this change.
- Wrote README.md (usage, Java→Go API map, integration pointers).

### Known gaps / next steps (design notes)

- **Plaintext labels still exist in the head.** The scratch test stores
  series with real labels in the TSDB and uses the encrypted index alongside
  it. A split deployment must replace `Head.postings` with
  `EncryptedMemPostings` and store opaque series identifiers in the head
  (e.g., the SSE update-token hash), keeping the label↔ref map client-side.
- **Ciphertext-as-float64-bits is a demo encoding.** ~1/2048 of random int64
  patterns land in the float64 NaN space; the TSDB stores them fine (only the
  exact StaleNaN bit pattern is special-cased), but a production design wants
  a dedicated chunkenc encoding for int64 ciphertexts (XOR chunks over raw
  uint64 would also compress better than NaN-spread floats).
- **timeID assignment**: the demo uses the per-series sample index, which the
  client must track (or derive as (timestamp − stream epoch) / scrape
  interval, TimeCrypt's chunk-window model). Gaps in scrapes need either
  deterministic time-slotting or an explicit per-series counter in client
  state.
- **Non-additive queries** (max/quantiles/rate with reset detection) need the
  chunk-scan fallback (per-sample decryption shown in the test) or extra
  precomputed slots (COUNT, SQUARE for variance), as in the Java client.
- **MAC variant**: `TimeCryptEncryptionLongPlus` is ported and tested; the
  scratch test uses the unauthenticated variant for clarity. Swapping in the
  Plus scheme costs one extra big.Int per sample (the auth tag) and needs a
  side-channel to store tags (they don't fit in the float64 sample).
