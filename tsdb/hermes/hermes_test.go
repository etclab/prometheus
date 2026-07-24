// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hermes

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/etclab/hermes/detrand"
	"github.com/etclab/hermes/hickae"
	hindex "github.com/etclab/hermes/index"
	"github.com/etclab/hermes/partition"
	"github.com/etclab/hermes/prf"
	"github.com/etclab/hermes/promadapter"
	"github.com/stretchr/testify/require"
)

// testSeed is the shared demo seed every role derives its keys from.
const testSeed = "hermes-index-test"

// numTestWriters keeps the trusted setup small: Prep is O(n^2).
const numTestWriters = 2

// testRoles builds an index plus one writer per class and the reader, all from
// the same seed, mirroring how the demo distributes key material.
func testRoles(t *testing.T) (*Index, []*hindex.Writer, *hindex.Reader) {
	t.Helper()
	ix, err := New([]byte(testSeed), numTestWriters)
	require.NoError(t, err)

	auth, err := hickae.NewAuthority(detrand.New(testSeed), numTestWriters)
	require.NoError(t, err)

	writers := make([]*hindex.Writer, numTestWriters)
	for wid := range writers {
		key := prf.DeriveWriterKey([]byte(testSeed), wid)
		writers[wid] = hindex.NewWriter(wid, key, auth.PK, auth.CBK[wid], partition.DefaultConfig(), rand.Reader)
	}
	return ix, writers, hindex.NewReader(auth.SK, auth.Master, partition.DefaultConfig(), rand.Reader)
}

// indexPair encrypts one (label, value) pair under a writer and applies it.
func indexPair(t *testing.T, ix *Index, w *hindex.Writer, name, value string, docID uint64) {
	t.Helper()
	epoch, _ := ix.Epoch()
	op, err := w.Update(epoch, promadapter.Keyword(name, value), docID)
	require.NoError(t, err)
	require.NoError(t, ix.Update(w.WID(), op))
}

// search extracts an aggregate key over every writer class and runs it.
func search(t *testing.T, ix *Index, r *hindex.Reader, name, value string) []string {
	t.Helper()
	epoch, _ := ix.Epoch()
	subset := make([]int, numTestWriters)
	for i := range subset {
		subset[i] = i
	}
	q, err := r.Query(epoch, subset, promadapter.Keyword(name, value))
	require.NoError(t, err)
	sids, err := ix.Search(q)
	require.NoError(t, err)
	return sids
}

// TestSearchUnionsWriters is the property Hermes exists for: two writers can
// index the *same* label pair, and one reader key recovers both their series.
func TestSearchUnionsWriters(t *testing.T) {
	ix, writers, reader := testRoles(t)

	const (
		sid0 = uint64(0xa3f1c208deadbeef)
		sid1 = uint64(0x5d90b71ecafef00d)
	)
	// Both targets carry job="myapp"; each also has its own instance.
	indexPair(t, ix, writers[0], "job", "myapp", sid0)
	indexPair(t, ix, writers[0], "instance", "localhost:2112", sid0)
	indexPair(t, ix, writers[1], "job", "myapp", sid1)
	indexPair(t, ix, writers[1], "instance", "localhost:2113", sid1)

	// Results are unioned across writers and sorted, not returned in writer order.
	require.Equal(t, []string{FormatSID(sid1), FormatSID(sid0)},
		search(t, ix, reader, "job", "myapp"),
		"a shared label pair must resolve to both writers' series")

	require.Equal(t, []string{FormatSID(sid0)},
		search(t, ix, reader, "instance", "localhost:2112"))
	require.Equal(t, []string{FormatSID(sid1)},
		search(t, ix, reader, "instance", "localhost:2113"))

	require.Empty(t, search(t, ix, reader, "job", "other"),
		"a pair that was never indexed must match nothing")
}

// TestSIDRoundTrip pins the encoding shared with the scrape targets: an id
// rendered as a label value must parse back to the same document id.
func TestSIDRoundTrip(t *testing.T) {
	for _, id := range []uint64{0, 1, 0xa3f1c208deadbeef, ^uint64(0)} {
		s := FormatSID(id)
		require.Len(t, s, 16)
		got, err := ParseSID(s)
		require.NoError(t, err)
		require.Equal(t, id, got)
	}
	_, err := ParseSID("nothex")
	require.Error(t, err)
}

// TestBindingsResolve checks the request-scoped plumbing: a matcher value naming
// two searches yields one sid set per search, ready to be intersected.
func TestBindingsResolve(t *testing.T) {
	ix, writers, reader := testRoles(t)
	const sid = uint64(0xa3f1c208deadbeef)
	indexPair(t, ix, writers[0], "job", "myapp", sid)
	indexPair(t, ix, writers[0], "env", "prod", sid)

	epoch, _ := ix.Epoch()
	qJob, err := reader.Query(epoch, []int{0, 1}, promadapter.Keyword("job", "myapp"))
	require.NoError(t, err)
	qEnv, err := reader.Query(epoch, []int{0, 1}, promadapter.Keyword("env", "prod"))
	require.NoError(t, err)

	b := NewBindings(ix, map[string]*hindex.SearchQuery{"q0": qJob, "q1": qEnv})
	sets, err := b.Resolve("q0,q1")
	require.NoError(t, err)
	require.Equal(t, [][]string{{FormatSID(sid)}, {FormatSID(sid)}}, sets)

	_, err = b.Resolve("q0,missing")
	require.Error(t, err)

	// The bindings must survive a context round trip unchanged.
	got, ok := FromContext(Bind(context.Background(), b))
	require.True(t, ok)
	require.Same(t, b, got)

	_, ok = FromContext(context.Background())
	require.False(t, ok)
}

// TestSearchQueryWireRoundTrip covers the transport the evaluator uses to hand
// aggregate keys to Prometheus.
func TestSearchQueryWireRoundTrip(t *testing.T) {
	ix, writers, reader := testRoles(t)
	const sid = uint64(0x0123456789abcdef)
	indexPair(t, ix, writers[1], "job", "myapp", sid)

	epoch, _ := ix.Epoch()
	q, err := reader.Query(epoch, []int{0, 1}, promadapter.Keyword("job", "myapp"))
	require.NoError(t, err)

	encoded, err := EncodeSearchQuery(q)
	require.NoError(t, err)
	decoded, err := DecodeSearchQuery(encoded)
	require.NoError(t, err)

	sids, err := ix.Search(decoded)
	require.NoError(t, err)
	require.Equal(t, []string{FormatSID(sid)}, sids,
		"a query must still match after a wire round trip")
}
