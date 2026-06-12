# Usage

The Go port lives at the module root (`package clusion`,
module `github.com/aashutoshpaudyal/clusion-go`). It has **no third-party
dependencies** — only the Go standard library (`crypto/*`, including the
Go 1.24 `crypto/pbkdf2`).

## Run the tests

```sh
cd clusion-go
go test ./...            # all schemes + the AES-CMAC known-answer test
go test ./... -v         # also prints each search and its recovered ids
```

What the tests cover:

| Test                  | Scheme / aspect                                            |
| --------------------- | ---------------------------------------------------------- |
| `TestAESCMAC_RFC4493` | hand-rolled AES-CMAC vs RFC 4493 vectors                   |
| `TestAESCTRStringRoundTrip` | AES-CTR string encrypt/decrypt round-trip            |
| `TestRR2Lev`          | static response-revealing 2Lev (prints plaintext ids)      |
| `TestRH2Lev`          | static response-hiding 2Lev (query -> ciphertexts -> resolve) |
| `TestDynRH2Lev`       | add-only dynamic 2Lev: base snapshot + incremental updates |
| `TestRR2LevBlocking` / `TestRH2LevBlocking` | medium/large array indirection |

## API at a glance

```go
sk, _ := clusion.KeyGen(256, "password", []byte("salt"), 100000)

// keyword -> ids; in the Prometheus experiment keyword = "name=value",
// id = series reference.
idx := clusion.Lookup{
    "vendor=intel": {"1", "2"},
    "os=linux":     {"1", "3"},
}

// --- Static, response-revealing 2Lev ---
rr, _ := clusion.ConstructRR2Lev(sk, idx, 1000, 100, 10000)
ids, _ := rr.Query(clusion.TokenRR2Lev(sk, "vendor=intel")) // -> ["1","2"]

// --- Static, response-hiding 2Lev ---
rh, _ := clusion.ConstructRH2Lev(sk, idx, 1000, 100, 10000)
cts, _ := rh.Query(clusion.TokenRH2Lev(sk, "vendor=intel"))
ids, _ = clusion.Resolve(clusion.GenerateCmac(sk, "3"), cts)

// --- Add-only dynamic 2Lev ---
dyn, _ := clusion.ConstructDynRH2Lev(sk, idx, 1000, 100, 10000)
tok, _ := dyn.TokenUpdate(sk, clusion.Lookup{"os=linux": {"4"}}) // add (os=linux, 4)
dyn.Update(tok)
cts, _ = dyn.Query(dyn.GenToken(sk, "os=linux"))
ids, _ = clusion.Resolve(clusion.GenerateCmac(sk, "3"), cts)     // -> ["1","3","4"]
```

The `Construct*` parameters are `(key, lookup, bigBlock, smallBlock, dataSize)`:
- `smallBlock` — keywords with at most this many ids are stored inline.
- `bigBlock` — chunk size for larger keywords, packed into the flat array.
- `dataSize` — number of array slots reserved (must exceed total block count).

## Using it from the Prometheus experiment

In `prometheus/tsdb/scratch_test.go`, the head's inverted index
(`postings`) is exactly a `Lookup`: for each `l.Name=l.Value` key the expanded
postings are the ids. Build a `clusion.Lookup` from `postings.SortedKeys()` and
`index.ExpandPostings(...)`, hand it to `ConstructRR2Lev` / `ConstructRH2Lev` /
`ConstructDynRH2Lev`, then issue token searches. Add this module to the
Prometheus build with a `replace` directive pointing at this directory.
