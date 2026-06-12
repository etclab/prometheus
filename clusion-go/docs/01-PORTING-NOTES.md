# Porting Notes (running log)

A running log of the important, non-obvious decisions made while porting
Clusion's 2Lev / Dyn2Lev to Go. Newest entries appended at the bottom.

## Crypto primitives mapping

| Java                                   | Go                                             |
| -------------------------------------- | ---------------------------------------------- |
| `keyGenSetM` (PBKDF2WithHmacSHA1)      | `crypto/pbkdf2` (std, Go 1.24+) with `sha1`    |
| `generateCmac` (BouncyCastle CMac/AES) | hand-rolled AES-CMAC per RFC 4493 (`crypto/aes`)|
| `generateHmac` (BC HMac/SHA256)        | `crypto/hmac` + `crypto/sha256`                |
| `encryptAES_CTR_String`                | `EncryptAESCTRString` (`crypto/cipher` CTR)    |
| `decryptAES_CTR_String`                | `DecryptAESCTRString`                           |
| `randomBytes`                          | `crypto/rand`                                  |
| `getBit`/`getBits`/`getIntFromByte`    | faithful ports (used for slot selection)       |

Output sizes preserved: CMAC = 16 bytes (AES-128 block), HMAC-SHA256 = 32 bytes.
Because `RR2Lev` tags via HMAC (32-byte AES-256 keys) while `RH2Lev`/`DynRH2Lev`
tag via CMAC (16-byte AES-128 keys), both AES key sizes must be supported —
`crypto/aes` handles 16/24/32 transparently.

## Key decision: byte handling, NOT wire compatibility

The Java code stores intermediate ciphertext as `new String(bytes,"ISO-8859-1")`
and later re-`getBytes()` it with the platform default charset. That round-trip
is charset-fragile and is effectively a Java-ism, not part of the scheme.

Go strings are arbitrary byte sequences, so `string(b)` / `[]byte(s)` is a
lossless 1:1 copy. We therefore follow the *structure* of the Java algorithms
exactly but keep bytes clean. Consequence: **the Go port round-trips correctly
(setup -> search -> resolve returns the original ids) but its ciphertexts are
NOT byte-compatible with the Java Clusion.** That is acceptable — the goal is a
working scheme for experimentation, not cross-language interop.

## encryptAES_CTR_String semantics

`identifier -> identifier + "\t\t\t"`, zero-pad to a fixed `size`, AES-CTR
encrypt, then prepend the 16-byte IV. Decrypt strips the IV, CTR-decrypts, and
the caller splits the plaintext on `"\t\t\t"` taking `[0]` to drop the padding.
The fixed `size` (`block * sizeOfFileIdentifier`) hides the true list length.
Fragility (inherited from Java): an id, or a packed block, must not itself
contain the `"\t\t\t"` marker or the `"seperator"` delimiter. Fine for the
numeric series ids used in the Prometheus experiment.

## 2Lev list encodings

- `RR2Lev` (response-revealing) packs ids as a Java-style list string
  `"[a, b, c]"` with a leading flag, and the search parser strips whitespace/
  brackets. Ported verbatim so the server-visible plaintext matches the scheme.
- `RH2Lev` (response-hiding) encrypts each id first (deterministic-ish, random
  IV) and joins the per-id ciphertexts with the literal delimiter `"seperator"`,
  prefixed by a flag. `resolve` decrypts each recovered id ciphertext.
- Array indirection markers: `RR2Lev` stores bare slot numbers; `RH2Lev` stores
  `"<n>***"`. The search side reads the leading run of digits to recover `n`.

## Slot selection (`free` list)

The Java `setup` keeps a global `free` list of array slots and picks a slot via
`getIntFromByte(randomBytes(...), ceil(log2(|free|)))`, halving on overflow.
This is reproduced per-builder (not global static state). Added a guard: when
`|free| <= 1` the Java `while (position >= free.size()-1) position/=2` loop can
spin forever; we clamp instead. Slot *values* are recorded in the encrypted
structure, so the exact RNG distribution does not affect correctness.

## Concurrency

Java's `constructEMMParGMM` shards keywords across a thread pool purely for
speed; the emitted dictionary/array are order-independent. The Go port builds
sequentially (`constructEMM`), which yields the same logical structure.

## DynRH2Lev (add-only)

`DynRH2Lev` embeds an `RH2Lev` (Go composition instead of Java `extends`) plus a
`dictionaryUpdates map[string][]byte` and per-keyword `state` counters.
`TokenUpdate` produces sorted `(label, value)` update tokens; `Update` applies
them; `Query` returns the static `RH2Lev` results concatenated with the update
entries for counters `0..state[w]`. `Resolve` decrypts with `MAC(K,"3")`.
Delete and the forward-secure-only token variant are intentionally omitted.

## Bug found & fixed: RH2Lev block buffer is under-sized in the original

While testing the medium/large packing paths I hit a real defect in the Java
`RH2Lev`/`DynRH2Lev`. The response-hiding scheme packs *encrypted* ids into a
big-block, but sizes the block ciphertext buffer as `bigBlock *
sizeOfFileIdentifer` — reusing the per-id budget. Each packed item is actually
`ivSize + sizeOfFileIdentifer (= 16 + 100 = 116)` bytes plus the 9-byte
`separator`, so a full `bigBlock` of items needs ~`bigBlock * 125` bytes. The
buffer therefore overflows for any keyword large enough to use blocks (and even
the small case overflows above ~80 ids). In Java this throws
`NegativeArraySizeException` inside `encryptAES_CTR_String`; the parallel
`constructEMMPar` builder catches it with `e.printStackTrace()` and silently
drops that keyword's postings.

The Go port sizes blocks as `block * packUnit + blockHeadroom`, where
`packUnit = ivSize + idSize + len(separator)` and `blockHeadroom` covers the
flag byte, leading/trailing separators, and terminator. This is transparent to
search (decryption is length-driven, strips the terminator, and `javaSplit`
discards padding), so it only fixes the overflow without changing semantics.
Verified by `TestRH2LevBlocking` (medium = one indirection, large = two).
RR2Lev is unaffected because it packs raw ids, which are far smaller than its
40-byte per-id budget.
