# timecrypt-go

A Go port of the [TimeCrypt](https://github.com/TimeCrypt/timecrypt) crypto
core (NSDI'20, Burkhalter et al.) — `timecrypt-crypto` in the Java original.
Built to encrypt sample **values** in an end-to-end encrypted Prometheus,
alongside [clusion-go](https://github.com/aashutoshpaudyal/clusion-go) which
encrypts the **inverted index** (label → series refs) with searchable
encryption.

```
go get github.com/aashutoshpaudyal/timecrypt-go
```

Pure stdlib, no dependencies. The Java source lives in `timecrypt/` for
reference; `PLAN.md` has the file-by-file port map, `PROGRESS.md` the log.

## What it does

HEAC encrypts value `m_i` at time index `i` as

```
c_i = m_i + k_i − k_(i+1)   (mod 2^64, or mod M)
```

with keys derived from a PRF tree ("key regression"). Adjacent keys cancel
under addition, so an **untrusted server can sum ciphertexts over any time
range** and the client decrypts the aggregate with only the two boundary keys:

```
sum(c_i, i=a..b) = sum(m_i) + k_a − k_(b+1)
```

The PRF tree also gives O(log n) sharing: revealing inner nodes delegates
exactly one key range (TimeCrypt "views").

## Quick start

```go
// Owner: one stream per time series, one master seed per stream.
master, _ := timecrypt.GenerateKey(16)
skm, _ := timecrypt.NewStreamKeyManager(master, 20) // 2^20 time steps
enc := timecrypt.NewTimeCryptEncryptionLong(skm.TreeKeyRegression())

// Encrypt float values as fixed-point ints at consecutive time IDs.
const scale = timecrypt.DefaultFixedPointScale
c0, _ := enc.EncryptMetadata(timecrypt.FloatToFixed(0.3, scale), 0, 0)
c1, _ := enc.EncryptMetadata(timecrypt.FloatToFixed(0.7, scale), 1, 0)

// Server: adds ciphertexts. No keys.
sum := c0 + c1

// Client: decrypts the aggregate with the two boundary keys.
dec, _ := enc.DecryptMetadata(sum, 0, 1, 0)
fmt.Println(timecrypt.FixedToFloat(dec, scale)) // 1.0
```

For integrity-protected aggregates use `TimeCryptEncryptionLongPlus` /
`TimeCryptEncryptionBIPlus` (homomorphic MACs, `ErrMACCheckFailed` on
tamper). For sharing, `TreeKeyRegression.RevealSeeds(from, to)` →
`NewSharedTreeKeyRegression`. For raw chunk payloads, `EncryptAESGCM` with
per-chunk keys from `StreamKeyManager.ChunkEncryptionKey`.

## API map (Java → Go)

| Java class | Go |
|---|---|
| `PRFAes` / `IPRF` | `AESPRF` / `PRF` |
| `TreeKeyRegression`, `TreeKeyRegressionFactory` | `TreeKeyRegression`, `NewTreeKeyRegression`, `NewSharedTreeKeyRegression` |
| `KeyUtil` | `DeriveKey*`, `DeriveCombinedKey`, `GenerateKey`, `GenerateMACKey` |
| `StreamKeyManager`, `CachedKeys` | same names |
| `HEACEncryptionLong` / `HEACEncryptionBI` | `HEACLong` / `HEACBigInt` |
| `HoMAC` / `HomomorphicMAC` | same names (`HoMACScheme` interface) |
| `TimeCryptEncryption{Long,BI}{,Plus}` | same names; `TCAuth{Long,BI}Ciphertext` |
| `TimeCryptChunkEncryption` | `EncryptAESGCM` / `DecryptAESGCM` |
| `MACCheckFailed`, `InvalidKeyDerivation` | `ErrMACCheckFailed`, `ErrInvalidKeyDerivation` |

## Prometheus integration

`prometheus/tsdb/scratch_test.go` has the demos (the repo's `go.work` pulls
in this module and clusion-go):

- `TestScratchEncryptedMemPostings` — the SSE-encrypted inverted index.
- `TestScratchEncryptedValues` — HEAC-encrypted sample values stored in the
  real TSDB (ciphertext int64 bits as float64 samples), label lookup through
  the encrypted index, server-side homomorphic `sum_over_time`, client-side
  decryption with boundary keys only.
