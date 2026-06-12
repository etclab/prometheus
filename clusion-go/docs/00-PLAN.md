# Plan: Porting Clusion (2Lev + Dyn2Lev) to Go

## Goal

Port the searchable symmetric encryption (SSE) schemes from the Java
[Clusion](../Clusion/) library to Go, so they can be used in Prometheus TSDB
experiments (`prometheus/tsdb/scratch_test.go`). In those experiments the
encrypted multi-map is the natural analogue of the TSDB **inverted index**:

| TSDB concept            | SSE concept     |
| ----------------------- | --------------- |
| label pair `name=value` | keyword `w`     |
| series reference (id)   | document id     |
| inverted index          | multi-map `MM`  |
| encrypted postings      | encrypted MM    |

## Scope (agreed with user)

Only two schemes are needed:

1. **2Lev** — the static scheme of Cash et al. (NDSS'14) [CJJJKRS14].
   Two flavours share almost all code:
   - `RR2Lev` — *response-revealing* (server learns the plaintext ids on search).
   - `RH2Lev` — *response-hiding* (server returns ciphertexts; client decrypts).
2. **Dyn2Lev (addition only)** — `DynRH2Lev`, a dynamic, forward-secure
   variant that supports **add** operations on top of a static `RH2Lev` base.

Everything else in Clusion is **out of scope**: boolean search (IEX/ZMF),
ZMF/Matryoshka filters, the delete-capable dynamic schemes (DynRH), Lucene/
PDFBox/POI text extraction, and the Hadoop/Amazon distributed setup. The
Prometheus experiment supplies the multi-map directly (label-pair -> ids), so
no document parsing is needed.

## Source files being ported

| Java (`Clusion/src/main/java/org/crypto/sse/`) | Go            | Notes |
| ---------------------------------------------- | ------------- | ----- |
| `CryptoPrimitives.java` (subset)               | `crypto.go`   | AES-CTR, AES-CMAC, HMAC-SHA256, PBKDF2 keygen |
| `RR2Lev.java`                                  | `rr2lev.go`   | static, response-revealing |
| `RH2Lev.java`                                  | `rh2lev.go`   | static, response-hiding (base for Dyn) |
| `DynRH2Lev.java`                               | `dynrh2lev.go`| dynamic, add-only (embeds RH2Lev) |

## The 2Lev data structure (what we are reproducing)

For each keyword `w` with id list `DB(w)`:

- **Small** (`|DB(w)| <= smallBlock`): store the whole (padded) list inline in a
  dictionary `gamma` under a deterministic tag `T = MAC(MAC(K,"1"+w), "0")`,
  encrypted under `K2 = MAC(K,"2"+w)`. Plaintext is prefixed with flag `"1"`.
- **Medium** (`|DB(w)|` needs `t <= smallBlock` big-blocks): chop `DB(w)` into
  `bigBlock`-sized chunks, store each encrypted chunk at a random free slot of a
  flat array `A`, and store the *list of slot indices* inline in `gamma` with
  flag `"2"`.
- **Large**: one more level of indirection — the slot-index list is itself
  chopped into the array, and `gamma` holds indices-of-indices with flag `"3"`.

Search: token = `(MAC(K,"1"+w), MAC(K,"2"+w))`. Look up the tag in `gamma`,
decrypt, read the flag, then follow 0/1/2 levels of array indirection.

`DynRH2Lev` adds a second dictionary `dictionaryUpdates`. Each added `(w,id)` is
stored at key `MAC(MAC(K,"4"+w), counter_w)` with the id encrypted under
`K3 = MAC(K,"3")`. Search queries both the static structure and every counter
`0..state[w]` in the updates dictionary.

## Step-by-step plan

1. Write this plan + a porting-notes log (`01-PORTING-NOTES.md`). *(done)*
2. Port the crypto primitives (`crypto.go`) and unit-test round-trips.
3. Port `RR2Lev` (static, response-revealing).
4. Port `RH2Lev` (static, response-hiding) — shares the 2Lev builder.
5. Port `DynRH2Lev` (embed RH2Lev, add update dictionary + add/search).
6. Write Go tests that build each scheme from a small in-memory multi-map,
   search, and **print** the recovered ids (mirroring the Java `TestLocal*`
   mains, but non-interactive and assertion-checked).
7. `go test ./...` and iterate to green.

## Non-goals / deviations (see porting notes for rationale)

- Not wire-compatible with Java Clusion ciphertexts (clean Go byte handling).
- Setup is sequential, not thread-pooled (semantically identical output).
- Delete and forward-secure-only query paths are omitted (add-only scope).
