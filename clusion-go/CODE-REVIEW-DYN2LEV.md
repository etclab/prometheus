# Code Review — DynRH2Lev (Dynamic 2Lev) vs. CJJJKRS (NDSS'14)

**Reviewer:** Claude (faithful-reviewer pass)
**Date:** 2026-06-12
**Scope:** Whether the Go code implements the dynamic add‑only 2Lev construction
("Dyn2Lev" / `DynRH2Lev`) as described in *Cash, Jaeger, Jarecki, Jutla,
Krawczyk, Roşu, Steiner — "Dynamic Searchable Encryption in Very-Large
Databases: Data Structures and Implementation", NDSS 2014* (`cjjjkrs-paper.pdf`).
Per request: **Go code only**, **Dyn2Lev only**. `RH2Lev` is reviewed as the
static base that `DynRH2Lev` extends; `RR2Lev` is noted only where relevant.

Files reviewed: `dynrh2lev.go`, `rh2lev.go`, `twolev_common.go`, `crypto.go`
(plus `schemes_test.go`, `blocking_test.go`). Java in `Clusion/` used only as a
fidelity reference.

---

## Verdict

**The implementation is faithful to the paper.** The core construction — a
static response‑hiding 2Lev encrypted multi‑map (`Π_2lev`, Fig. 9) augmented
with an add‑only auxiliary dictionary (`Π⁺_bas` / `D⁺`, §4) — is reproduced
correctly. All small/medium/large packing paths, the add‑token mechanism, the
per‑keyword counter state, and the two‑phase search (static base ∪ updates) match
the paper's design and the original Clusion Java. `go test ./...` passes,
including the medium/large blocking paths and the dynamic add‑then‑search test.

The deviations found are either (a) explicitly sanctioned by the paper, (b)
inherited verbatim from the original Clusion implementation, or (c) cosmetic. One
**documentation inaccuracy** (a "forward‑secure" label that the implemented
variant does not satisfy) and one **pre‑existing robustness caveat** (binary
ciphertext vs. textual separators) are worth fixing but do not affect
conformance to the scheme.

---

## How the paper maps onto the code

The paper (§4, p.17) states the dynamic scheme = *"a statically encrypted
database `EDB` using any of the schemes described above, and an auxiliary
encrypted database `EDB⁺` which is maintained to be of the form of a basic
dictionary‑based scheme."*

`DynRH2Lev` is exactly that:

| Paper concept | Go realization |
|---|---|
| Static `EDB` (here `Π_2lev`, Fig. 9) | embedded `*RH2Lev` (`dynrh2lev.go:11`) |
| Auxiliary `D⁺` (basic dictionary, §4 p.17) | `dictionaryUpdates map[string][]byte` |
| Client `D_count`: keyword → counter | `state map[string]int` |
| Update label `ℓ ← F(K1⁺, c)` | `l = CMAC(CMAC(key,"4"+w), strconv(counter))` (`dynrh2lev.go:43-44`) |
| Update value `d ← Enc(K2⁺, id)` | `EncryptAESCTRString(key3, iv, id, idSize)` (`dynrh2lev.go:46`) |
| `c++`; `Insert(w,c)` into `D_count` | `d.state[word] = counter + 1` (`dynrh2lev.go:43`) |
| Server: add `(ℓ,d)` to `D⁺` | `Update()` writes into `dictionaryUpdates` (`dynrh2lev.go:58-62`) |
| Search: run static search, then recompute `F(K1⁺,c)` for c=0,1,… | `Query()` calls `RH2Lev.Query` then loops `i<count` recomputing `CMAC(updKey,i)` (`dynrh2lev.go:85-96`) |

### Static base `Π_2lev` (Fig. 9) → `rh2lev.go`

The three size classes match Figure 9 precisely (flags `"1"/"2"/"3"` are a
Clusion encoding detail, not in the paper's pseudocode, but functionally
equivalent):

- **Small** `|DB(w)| ≤ b`: ids encrypted and stored as one block directly in the
  dictionary under `CMAC(key1,"0")` ≈ `F(K1,0)` — `rh2lev.go:82-90`. ✔ matches
  Fig. 9 step 2.
- **Medium** `b < |DB(w)| ≤ Bb`: ids chopped into `B`‑blocks placed at random
  free array slots; the slot‑index list stored as one dictionary block
  (`t ≤ smallBlock`) — `rh2lev.go:93-114`. ✔ matches Fig. 9 step 3.
- **Large**: id `B`‑blocks in the array, the pointer list itself chopped into
  array blocks, and a single second‑level pointer block in the dictionary —
  `rh2lev.go:117-136`. ✔ matches Fig. 9 step 4 (two indirection levels).

Search reverses this by reading the single dictionary entry and following 0/1/2
levels of array indirection (`rh2lev.go:162-215`), which is the `Π_2lev` search
on p.15. Random free‑slot placement (`takeFreeSlot`, `twolev_common.go:79`)
realizes "choose random empty indices `i₁…iₜ`". ✔

### Cross‑check against Clusion Java

`dynrh2lev.go` is a line‑for‑line port of `Clusion/.../DynRH2Lev.java`:
`tokenUpdate` (key3/key4 derivation, per‑word counter, `CMAC(key4,counter)`
label), `update`, `genToken` (`keys[0..2]` + counter in `keys[3]`), and `query`
(static query then `i < count` loop over `CMAC(keys[2],i)`) all correspond
exactly. The port is structurally faithful.

---

## Findings

### F1 — "Forward‑secure" claim is inaccurate (documentation)

`dynrh2lev.go:5` and the project memory describe `DynRH2Lev` as the
*"forward‑secure"* variant. **The implemented search does not provide forward
privacy.**

`GenToken` (`dynrh2lev.go:73-80`) hands the server `updKey = CMAC(key,"4"+w)`
(the static `K1⁺`). Once a keyword has been searched, the holder of `updKey` can
compute the label `CMAC(updKey, c)` for **any future** counter `c`, and thus
link later additions of `w` to the past query — exactly the property forward
privacy forbids. The paper confirms this for `Π⁺_bas`: *"if … the keywords were
previously searched for, then the server can reuse its keys from before to detect
the presence of these keywords"* (§4 leakage discussion, p.18).

The Java source agrees: the standard `genToken`/`query` (the methods ported here)
are **not** forward secure; Clusion's forward‑secure path is the *separate*
`genTokenFS`/`queryFS`, which sends per‑counter tokens `CMAC(key4,i)` so the
server cannot derive future labels. The memory note itself lists
"forward‑secure‑only token variants" as **out of scope** — i.e. `genTokenFS` was
deliberately not ported. So the code is internally consistent *except* for the
comment, which claims a property the chosen variant gives up.

**Recommendation:** change the wording in `dynrh2lev.go:5` (and the memory note)
from "forward-secure" to something like "add‑only dynamic" or "non‑forward‑secure
add‑only". No code change needed.

### F2 — Single global encryption key for `D⁺` (sanctioned deviation)

The paper's `Π⁺_bas` encrypts each update value under a **per‑keyword**
`K2⁺ = F(K⁺,w)`. The Go code (matching Java) instead encrypts every update — and
every static id — under one global SIV‑style key `key3 = CMAC(key,"3")`
(`dynrh2lev.go:38,46`), recovered uniformly by `Resolve` with `CMAC(masterKey,"3")`.

This is an intentional Clusion design choice (the same global resolve key already
used by static `RH2Lev`, `rh2lev.go:66`) and does not break the construction:
labels remain keyword‑specific, so retrieval is unaffected; only the
id‑confidentiality key is shared. It changes the security reduction (a single key
guards all id ciphertexts) but preserves response hiding and is consistent with
how the paper's response‑hiding family is realized in practice. **Acceptable** —
worth a one‑line note in the doc comment so it isn't mistaken for `K2⁺` per
keyword.

### F3 — Search uses client‑supplied count instead of "loop until ⊥" (benign)

The paper's server loops `c = 0 until Get returns ⊥`. The Go `Query`
(`dynrh2lev.go:90`) instead loops `i < token.count`, where `count` is the
client's current `state[w]`. This is functionally identical (the client knows
exactly how many additions exist), avoids a sentinel‑miss class of bugs, and
matches the Java port. **Acceptable.**

### F4 — Large‑case pointer blocks use `B`, not `b` (sanctioned deviation)

Figure 9's large case writes `t' ← ⌈t/b⌉` (partition pointers into `b`‑sized
blocks), whereas the Go code uses `tPrime = ceil(t / bigBlock)` — `B`‑sized
pointer blocks (`rh2lev.go:117`). This follows the Clusion implementation and the
paper's own "Pointers vs. identifiers" paragraph (p.16), which explicitly notes
implementations pack a *different* (larger) number of pointers per block than the
presentation uses and introduces `b'/B'` for exactly this. The two‑level
indirection — the defining feature of `2Lev` — is preserved. **Acceptable.**

### F5 — Binary ciphertext packed with textual separators (pre‑existing robustness caveat)

`RH2Lev` packs inner id‑ciphertexts (random 16‑byte IV + AES‑CTR bytes) into a
block by joining with the literal string `"seperator"` and terminating with
`"\t\t\t"` (`fileIDTerminator`), then splits on those markers at query time
(`rh2lev.go:85,95,172,211`; `crypto.go:134`). Because the inner ciphertext is
binary, a block can in principle contain the byte sequence `09 09 09`
(`fileIDTerminator`, ~2⁻²⁴ per position) or `"seperator"` (~2⁻⁷²), causing the
parser to truncate or mis‑split that keyword's result list.

This is **inherited verbatim from Clusion Java** (same separators, same join/split)
and is not a deviation from the paper, which abstracts serialization as
"parse and output ids". The terminator collision is the realistic one: for a
keyword with on the order of ~10⁵+ identifiers the expected number of `09 09 09`
windows approaches 1, which is plausible at Prometheus scale (many series per
label pair). The IDs themselves are short ASCII so the *outer* layout is fine;
the risk is purely the random IV/ciphertext bytes of the **inner** id encryption.

**Recommendation (optional, beyond paper conformance):** for the Go port,
consider a length‑prefixed or fixed‑width packing of inner ciphertexts instead of
delimiter splitting (the port already abandons Java wire‑compatibility, so this
is low‑cost), or document the size ceiling per keyword. Not required for
correctness on the test‑scale data; flagged for the TSDB‑scale target.

### F6 — `state` and `idSize` consistency (correct, noted)

- `state` correctly excludes the static base: base postings are searched via
  `RH2Lev.Query`, additions via the counter loop, so a keyword present only in
  the base has `count == 0` and is still returned (verified by `TestDynRH2Lev`,
  which seeds `vendor=intel` in the base and adds to it). ✔
- Updates encrypt with `d.idSize` (= `rh2levFileIDSize`, 100) and the same
  `key3`, so a single `Resolve` decrypts both base and update ciphertexts. ✔
- (Original‑Java note, already handled:) the block buffer sizing bug in Java
  `RH2Lev` is fixed here via `packUnit` + `blockHeadroom` (`rh2lev.go:33,49`),
  documented in `docs/01-PORTING-NOTES.md`. This is an improvement, not a
  deviation.

---

## Conclusion

`DynRH2Lev` faithfully implements the CJJJKRS dynamic add‑only 2Lev construction:
static `Π_2lev` response‑hiding base (Fig. 9) + add‑only basic dictionary `D⁺`
(§4), with correct label derivation, counter state, and merged search. All
deviations are sanctioned by the paper, inherited from Clusion, or cosmetic.

Action items, in priority order:
1. **F1** — fix the "forward‑secure" wording (the implemented variant is not
   forward‑private). *Doc only.*
2. **F5** — consider robust inner‑ciphertext framing for TSDB‑scale data, or
   document the per‑keyword size ceiling. *Optional, robustness.*
3. **F2** — note that `D⁺` shares the global `key3` rather than per‑keyword
   `K2⁺`. *Doc only.*

No changes are required to make the scheme match the paper's core idea — it
already does.
