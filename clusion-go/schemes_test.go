package clusion

import (
	"fmt"
	"sort"
	"testing"
)

// demoIndex is a tiny inverted index shaped like the one the Prometheus TSDB
// builds from appended series: keyword = label pair "name=value", id = series
// reference. Two series share vendor=intel; os splits them.
//
//	series 1: __name__=cpu_usage_ratio host=127.0.0.1 os=linux   vendor=intel
//	series 2: __name__=cpu_usage_ratio host=127.0.0.2 os=windows vendor=intel
//	series 3: __name__=mem_usage_bytes host=127.0.0.1 os=linux   vendor=amd
func demoIndex() Lookup {
	return Lookup{
		"__name__=cpu_usage_ratio": {"1", "2"},
		"__name__=mem_usage_bytes": {"3"},
		"host=127.0.0.1":           {"1", "3"},
		"host=127.0.0.2":           {"2"},
		"os=linux":                 {"1", "3"},
		"os=windows":               {"2"},
		"vendor=intel":             {"1", "2"},
		"vendor=amd":               {"3"},
	}
}

const (
	bigBlock   = 1000
	smallBlock = 100
	dataSize   = 10000
)

func key(t *testing.T) []byte {
	t.Helper()
	k, err := KeyGen(256, "correct horse battery staple", []byte("clusion-salt"), 100000)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestRR2Lev builds the response-revealing 2Lev EMM, searches every keyword,
// and prints the recovered ids.
func TestRR2Lev(t *testing.T) {
	sk := key(t)
	idx := demoIndex()

	emm, err := ConstructRR2Lev(sk, idx, bigBlock, smallBlock, dataSize)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("== RR2Lev (response-revealing 2Lev) ==")
	for _, w := range sortedKeys(idx) {
		got, err := emm.Query(TokenRR2Lev(sk, w))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("  search %-26q -> %v\n", w, sortedCopy(got))
		assertSameSet(t, w, got, idx[w])
	}
	// A keyword absent from the index returns nothing.
	if got, _ := emm.Query(TokenRR2Lev(sk, "os=darwin")); len(got) != 0 {
		t.Fatalf("expected no results for absent keyword, got %v", got)
	}
}

// TestRH2Lev builds the response-hiding 2Lev EMM. Query returns ciphertexts;
// Resolve turns them back into ids. Prints both stages.
func TestRH2Lev(t *testing.T) {
	sk := key(t)
	idx := demoIndex()

	emm, err := ConstructRH2Lev(sk, idx, bigBlock, smallBlock, dataSize)
	if err != nil {
		t.Fatal(err)
	}
	resolveKey := GenerateCmac(sk, "3")

	fmt.Println("== RH2Lev (response-hiding 2Lev) ==")
	for _, w := range sortedKeys(idx) {
		cts, err := emm.Query(TokenRH2Lev(sk, w))
		if err != nil {
			t.Fatal(err)
		}
		ids, err := Resolve(resolveKey, cts)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("  search %-26q -> %d ciphertext(s) -> %v\n", w, len(cts), sortedCopy(ids))
		assertSameSet(t, w, ids, idx[w])
	}
}

// TestDynRH2Lev starts from a base snapshot, then adds two more series via an
// update, and shows that search reflects both the base and the additions.
func TestDynRH2Lev(t *testing.T) {
	sk := key(t)

	// Base snapshot: just the first series' postings.
	base := Lookup{
		"__name__=cpu_usage_ratio": {"1"},
		"host=127.0.0.1":           {"1"},
		"os=linux":                 {"1"},
		"vendor=intel":             {"1"},
	}
	emm, err := ConstructDynRH2Lev(sk, base, bigBlock, smallBlock, dataSize)
	if err != nil {
		t.Fatal(err)
	}
	resolveKey := GenerateCmac(sk, "3")

	// Incremental add: series 2 and 3 arrive later.
	additions := Lookup{
		"__name__=cpu_usage_ratio": {"2"},
		"__name__=mem_usage_bytes": {"3"},
		"host=127.0.0.2":           {"2"},
		"host=127.0.0.1":           {"3"},
		"os=windows":               {"2"},
		"os=linux":                 {"3"},
		"vendor=intel":             {"2"},
		"vendor=amd":               {"3"},
	}
	tokenUp, err := emm.TokenUpdate(sk, additions)
	if err != nil {
		t.Fatal(err)
	}
	emm.Update(tokenUp)

	// Expected final state = base merged with additions.
	want := demoIndex()

	fmt.Println("== DynRH2Lev (add-only dynamic 2Lev) ==")
	for _, w := range sortedKeys(want) {
		cts, err := emm.Query(emm.GenToken(sk, w))
		if err != nil {
			t.Fatal(err)
		}
		ids, err := Resolve(resolveKey, cts)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("  search %-26q -> %v\n", w, sortedCopy(ids))
		assertSameSet(t, w, ids, want[w])
	}
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func assertSameSet(t *testing.T, ctx string, got, want []string) {
	t.Helper()
	g, w := sortedCopy(got), sortedCopy(want)
	if len(g) != len(w) {
		t.Fatalf("%s: got %v want %v", ctx, g, w)
	}
	for i := range g {
		if g[i] != w[i] {
			t.Fatalf("%s: got %v want %v", ctx, g, w)
		}
	}
}
