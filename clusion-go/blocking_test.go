package clusion

import (
	"fmt"
	"strconv"
	"testing"
)

// makeBigPostings builds a single keyword mapping to n distinct ids.
func makeBigPostings(n int) (Lookup, []string) {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = strconv.Itoa(1000 + i)
	}
	return Lookup{"big=keyword": ids}, ids
}

// TestRR2LevBlocking exercises the medium (one array indirection, flag "2") and
// large (two indirections, flag "3") packing paths of RR2Lev, which the small
// demo index never reaches.
func TestRR2LevBlocking(t *testing.T) {
	sk := key(t)
	cases := []struct {
		name                          string
		n, bigBlock, smallBlock, data int
	}{
		{"medium", 250, 100, 100, 10000}, // t=3 <= smallBlock -> flag "2"
		{"large", 120, 10, 5, 10000},     // t=12 > smallBlock  -> flag "3"
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idx, ids := makeBigPostings(c.n)
			emm, err := ConstructRR2Lev(sk, idx, c.bigBlock, c.smallBlock, c.data)
			if err != nil {
				t.Fatal(err)
			}
			got, err := emm.Query(TokenRR2Lev(sk, "big=keyword"))
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("  RR2Lev %-6s: %d ids in -> %d ids out\n", c.name, c.n, len(got))
			assertSameSet(t, c.name, got, ids)
		})
	}
}

// TestRH2LevBlocking exercises the same medium/large paths for the
// response-hiding variant (ids come back encrypted, then resolved).
func TestRH2LevBlocking(t *testing.T) {
	sk := key(t)
	resolveKey := GenerateCmac(sk, "3")
	cases := []struct {
		name                          string
		n, bigBlock, smallBlock, data int
	}{
		{"medium", 250, 100, 100, 10000},
		{"large", 120, 10, 5, 10000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idx, ids := makeBigPostings(c.n)
			emm, err := ConstructRH2Lev(sk, idx, c.bigBlock, c.smallBlock, c.data)
			if err != nil {
				t.Fatal(err)
			}
			cts, err := emm.Query(TokenRH2Lev(sk, "big=keyword"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Resolve(resolveKey, cts)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("  RH2Lev %-6s: %d ids in -> %d ids out\n", c.name, c.n, len(got))
			assertSameSet(t, c.name, got, ids)
		})
	}
}
