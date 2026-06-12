# TimeCrypt-Go — Code Review / Faithfulness Audit

**Reviewer:** Claude (code review pass)
**Date:** 2026-06-12
**Scope:** the `*.go` files in the repo root (`prf.go`, `keyregression.go`, `keyutil.go`,
`streamkeys.go`, `heac.go`, `homac.go`, `encryption.go`, `chunk.go`, `fixedpoint.go`,
plus `*_test.go`). The Java tree under `timecrypt/` is the authors' original and was used
**only** as the reference, together with the NSDI'20 paper
(`nsdi20-paper-burkhalter.pdf`). The Java is **not** audited.

**Question asked:** does the Go port implement TimeCrypt as described in the paper, with the
core idea and construction preserved? Minor implementation deviations are acceptable.

## Verdict

**The port is faithful.** Every core cryptographic construction in the paper — the HEAC
additively-homomorphic encryption with key-canceling, the HoMAC integrity tags, and the
binary key-derivation tree (key regression) with token-based sharing — is implemented
correctly and matches both the paper's equations and the Java source line-for-line in
behavior. `go vet ./...` is clean and `go test ./...` passes (13 tests, ports of the two
Java test classes plus added invariants). I found **no correctness defects** in the crypto
core. The deviations that exist are either explicitly-scoped omissions or faithful copies
of choices the original Java authors made; they are catalogued below with severity.

---

## 1. Core construction — verified against the paper

### 1.1 HEAC symmetric homomorphic encryption (paper §3.1, Eq. 1–3)

Paper:
- Base scheme `c_i = m_i + k_i  mod M`, `Dec = c_i − k_i  mod M`, `M = 2^64` (§3.1).
- Key-canceling (Eq. 2): `Enc_{k'_i}(m_i) = m_i + k'_i mod M` with `k'_i = k_i − k_{i+1}`,
  i.e. `c_i = m_i + k_i − k_{i+1} mod M`.
- In-range decryption (Eq. 1+3): `Σ m_i = Σ c_i − (k_from − k_{to+1}) mod M`.

Implementation:
- `heac.go:41` `EncryptWithKeys: msg + key1 − key2` (HEACLong, M = 2^64 via int64
  wraparound) and `heac.go:105` for HEACBigInt (`mod M`). ✔ matches Eq. 2.
- `heac.go:60` / `heac.go:126` `DecryptWithKeys: ciphertext − key1 + key2 (mod M)`, with
  boundary keys `k_from = key(msgFrom)` and `k_{to+1} = key(msgTo+1)` (`heac.go:66-75`,
  `heac.go:133-142`). ✔ matches Eq. 1+3 exactly (the telescoping sum
  `Σ k'_i = k_from − k_{to+1}`).
- `M = 2^64` for the Long scheme (natural two's-complement wraparound) — the paper's exact
  choice "to support all integer sizes without leaking any information about their original
  size." ✔

The Long ↔ BigInt equivalence is also exercised by the ported tests
(`crypto_test.go:60-165`), including the 1000-element running-sum test from the Java suite.

### 1.2 HoMAC integrity (paper §3.2, Eq. 4–7)

Paper (inverse form):
- Tag (Eq. 4): `σ = HoMAC_s(c) = (s − c)/Z mod p`.
- Key-canceling (Eq. 6): `σ_i = (s_i − s_{i+1} − c_i)/Z mod p`.
- Verify (Eq. 5/7): `Σ s'_i = s_0 − s_{n+1} ?= c_res + σ_res·Z mod p`.

Implementation (`homac.go`, type `HoMAC`):
- `homac.go:70-75` `GetMACWithKeys: (key1 − key2 − msg)·Z⁻¹ mod p` — with `Z⁻¹ = macKeyInv`
  (`homac.go:49`). This is exactly Eq. 6 (`key1 = s_i`, `key2 = s_{i+1}`, `Z = macKey`). ✔
- `homac.go:89-96` `CheckMACWithKeys: (key1 − key2) ?= mac·Z + msg mod p`. With boundary
  keys `s_from, s_{to+1}` the left side telescopes to `Σ s'_i`, so this is Eq. 7 verbatim. ✔
- `p = 2^128 − 159` (`homac.go:9`, `340282366920938463463374607431768211297`), bit length
  128. ✔ matches the Java `HoMAC.PRIME`.
- Aggregation `homac.go:98-101` adds tags mod p — the additive-homomorphism the paper
  relies on. ✔

`HomomorphicMAC` (`homac.go:103-170`, multiply form `msg·a + k_i − k_{i+1}`) is the
"conventional" variant present in the Java original; it's not the form written in the
paper's equations but is internally consistent and aggregatable, and is faithfully ported.
Both MAC schemes verify under the ported `testMACBasic`/`testMACSums`
(`crypto_test.go:239-251`).

### 1.3 Key-derivation tree / key regression (paper §3.3.1, Fig. 2)

Paper: balanced binary tree from a secret root seed; left child `G_0(x)`, right child
`G_1(x)`; leaves form the keystream; inner nodes shared as access tokens; KDF maps a leaf
seed to the actual key, and *different* KDFs are used over the same node for the
encryption key, the chunk key, and the HoMAC key (footnote 4).

Implementation (`keyregression.go`, `keyutil.go`):
- Child `i` of a node with seed `s` is `PRF(s, i)` (`keyregression.go:167`,
  `nodeSeeds`/`GetSeed`). With `kFactor = 2` this realizes `G_0(x) = AES_x(0)`,
  `G_1(x) = AES_x(1)` — a GGM-style PRF tree. The paper says the PRG "can be realized from
  hash functions `H(0‖x)`, `H(1‖x)`"; the implementation realizes the same length-doubling
  PRG from AES instead (see §3.1 deviation below). Structurally and security-wise
  equivalent. ✔
- Leaf-seed → key KDF: `DeriveKeyDefault` (`keyutil.go:80`, all-`0xFF` PRF input, XOR-fold
  to the requested bit width). ✔
- Domain-separated KDFs (footnote 4): encryption key input `0xFF^8 ‖ id_be64`
  (`keyutil.go:20`), MAC key input `id_be64 ‖ 0xFF^8` (`keyutil.go:31`), combined chunk key
  from two adjacent seeds (`keyutil.go:112`). These are the three "different KDFs with the
  same node" the paper calls for. ✔
- Token-based sharing: `RevealSeeds(from, to)` (`keyregression.go:249`) returns the minimal
  inner-node cover for `[from, to]`, and `NewSharedTreeKeyRegression` reconstructs exactly
  those leaves and nothing outside the interval (`checkValidAccess`, `keyregression.go:98`).
  The round-trip is verified end-to-end in `keyregression_test.go:11-58` (owner-revealed
  nodes derive identical seeds; access outside the granted range returns
  `ErrInvalidKeyDerivation`). ✔ This is the paper's §3.3 access-token primitive.

The node math (`computePath`, `computePathFromRoot`, `nodeKeyInterval`, `relevantNode`,
`getSeeds` interval walk) is a line-by-line port of the Java `TreeKeyRegression`; I diffed
each method against `TreeKeyRegression.java` and they agree, including the
`getRelevantNode`/`relevantNode` use of `powers[node.Depth]` and the receiver constructor's
`keyInterval` derived from the first/last revealed node.

### 1.4 Time-encoded keystream & chunk encryption (paper §3.1 end, §2.5)

- Per-chunk raw payloads use AES-GCM with a 12-byte random nonce prefixed to the ciphertext
  (`chunk.go`), matching `TimeCryptChunkEncryption.java` (nonce ‖ ct ‖ tag, 128-bit tag).
  Round-trip + tamper-detection verified (`crypto_test.go:326-351`). ✔
- The "time-encoded keystream" mapping (key index = chunk/time window) is represented by the
  `timeID` argument threaded through `EncryptMetadata`/`DecryptMetadata` in `encryption.go`.
  The float→time-slot glue lives in the Prometheus integration, not the crypto core. ✔

### 1.5 Client schemes (`encryption.go`)

All four paper/Java schemes are present and match their Java counterparts method-for-method:
`TimeCryptEncryptionLong` (LONG), `…LongPlus` (LONG_MAC), `…BI` (BIG_INT_128),
`…BIPlus` (BIG_INT_128_MAC). Spot-checked invariants:
- `BIPlus` derives **encryption** keys at `mac.NumFieldBits()` (= 128) and uses
  `M = HoMACPrime`, exactly as `TimeCryptEncryptionBIPlus.java` (so ciphertext and tag share
  the field). ✔ (`encryption.go:363-381`)
- `BIPlus` MACs the **ciphertext**; `LongPlus` MACs the **plaintext** — this asymmetry is
  inherited verbatim from the Java (`TimeCryptEncryptionLongPlus.java:33` vs
  `TimeCryptEncryptionBIPlus.java:38`). See note 2.4 below.
- Tamper → `ErrMACCheckFailed` (`encryption.go:172`, `:405`), ported test
  `crypto_test.go:283-294`. ✔

---

## 2. Deviations and notes (none block faithfulness)

### 2.1 PRG primitive: AES-PRF tree vs. paper's hash-based PRG — *informational*
The paper describes the tree PRG as `G_0(x)=H(0‖x)`, `G_1(x)=H(1‖x)` but explicitly says it
*"can be realized from hash functions."* The implementation (and the original Java) realizes
the same length-doubling PRG with a single-block AES PRF, `child_i = AES_seed(i)`
(`prf.go:36-55`). This is a standard, security-equivalent GGM construction and is already
documented in `PLAN.md`. **Not a defect** — it matches the Java reference and satisfies the
paper's stated freedom of realization. The FIPS-197 known-answer test (`crypto_test.go:21`)
pins the AES block to the standard so the PRF is reproducible/cross-implementation stable.

### 2.2 Intentionally un-ported components — *expected, documented*
`LabelTreeKeyRegression`, `OldTreeKeyDerivation`, `ResolutionBasedRegression`,
`serialize/`, and `sharing/EnvelopeCrypto` are not ported. These cover the
resolution-restricted access tier (paper §3.3.2) and the gRPC sharing envelope, which are
out of scope for value encryption in the Prometheus use case (per `PLAN.md`). The core
sharing primitive (§3.3, inner-node access tokens) **is** ported via `RevealSeeds`. The
`StreamKeyManager.SharingKeyRegression(precision, depth)` hook (`streamkeys.go:96`) keeps the
precision-based sharing entry point, matching the Java. **Acceptable scope reduction.**

### 2.3 `HoMAC.CheckMAC` reduces by the instance prime, Java uses the static `PRIME` — *cosmetic*
`homac.go:86` reduces the incoming tag with `m.prime`; Java `HoMAC.java:69` reduces with the
static constant `PRIME`. Identical for the default prime (the only one ever used). Would only
diverge if someone constructed a `HoMAC` with a non-default prime via
`NewHoMACWithPrime`, which nothing does. **No practical impact;** arguably the Go version is
the more correct of the two.

### 2.4 `LongPlus` authenticates plaintext, not ciphertext — *inherited from Java, by design*
The paper's HoMAC (Eq. 4) is defined over the ciphertext `c`. `TimeCryptEncryptionLongPlus`
tags the *plaintext* value instead (`encryption.go:157` / Java `…LongPlus.java:33`), while
`BIPlus` tags the ciphertext per the paper. Both are internally consistent (encrypt and
verify use the same quantity), so integrity holds; this is purely a choice the original
authors made for the Long variant and is reproduced faithfully. Flagging only because a
reader comparing strictly to Eq. 4 will notice it. **No action needed for a faithful port.**

### 2.5 `fixedpoint.go` is new glue, not in the original — *expected, documented*
Float64↔fixed-point int64 (`fixedpoint.go`) is additive glue so Prometheus float samples can
ride the int64 HEAC scheme; sums commute with the encoding (`crypto_test.go:353`). Not part
of the Java crypto module and clearly labelled as such. The scale (`1e6`) trades integer
headroom for precision — documented in `PROGRESS.md` as a known limitation, not a crypto
issue.

### 2.6 Operational caveats (already captured in `PROGRESS.md`) — *out of crypto scope*
The Prometheus integration stores int64 ciphertexts as float64 sample bits (~1/2048 land in
NaN space), keeps plaintext labels in the head alongside the encrypted index, and assigns
`timeID` from a per-series counter. These are integration/demo limitations, not deviations in
the crypto port, and the authors have written them up. Noted here for completeness.

---

## 3. Correctness cross-checks performed

- Java↔Go method diff for every crypto file (PRF, KeyUtil, TreeKeyRegression, StreamKeyManager,
  HEAC Long/BI, HoMAC/HomomorphicMAC, all four TimeCryptEncryption wrappers, chunk enc).
- Paper equation check: Eq. 1, 2, 3 (HEAC) and Eq. 4, 6, 7 (HoMAC) against the Go arithmetic.
- Signed/unsigned `BigInteger` conventions: `new BigInteger(1, …)` → `SetBytes` (unsigned,
  `keyutil.go:57`); `new BigInteger(byte[])` (signed, only `StreamKeyManager.macKey`) →
  `bigIntFromSignedBytes` (`keyutil.go:144`, two's-complement). ✔
- PRF input packing: int big-endian in the last 4 bytes of the block (`prf.go:53`) vs Java
  `PRFAes.java:53`. ✔ (`crypto_test.go:31` asserts this.)
- `go vet ./...` clean; `go test ./...` green (Go 1.24.5).

## 4. Recommendation

Accept. The Go port preserves TimeCrypt's core idea and construction as specified in the
NSDI'20 paper. The only items worth a one-line code comment (optional) are the LongPlus
plaintext-vs-ciphertext MAC asymmetry (§2.4) and the AES-vs-hash PRG realization (§2.1), both
of which faithfully track the original Java and the paper's stated flexibility. No crypto
correctness changes are required.
