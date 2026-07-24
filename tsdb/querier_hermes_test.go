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

package tsdb

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

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/hermes"
	"github.com/prometheus/prometheus/tsdb/index"
	"github.com/prometheus/prometheus/util/compression"
)

const (
	hermesTestSeed    = "querier-hermes-test"
	hermesTestWriters = 2
	// The opaque ids of the two encrypted series, as their writers derive them.
	hermesTestSID0 = uint64(0xa3f1c208deadbeef)
	hermesTestSID1 = uint64(0x5d90b71ecafef00d)
)

// TestPostingsForMatchersHermes checks the encrypted seam end to end inside the
// storage layer: a selector carrying an encrypted search must resolve to exactly
// the series an equivalent plaintext sid selector would, and must intersect with
// the ordinary matchers next to it.
func TestPostingsForMatchersHermes(t *testing.T) {
	head, _ := newTestHead(t, 1000, compression.None, false)
	t.Cleanup(func() { require.NoError(t, head.Close()) })

	// The scrape targets expose nothing but the opaque id; the decoy carries a
	// different metric name so it can never be matched by the searches below.
	sid0, sid1 := hermes.FormatSID(hermesTestSID0), hermes.FormatSID(hermesTestSID1)
	app := head.Appender(context.Background())
	for _, lset := range []labels.Labels{
		labels.FromStrings("__name__", "enc_series", hermes.SIDLabel, sid0),
		labels.FromStrings("__name__", "enc_series", hermes.SIDLabel, sid1),
		labels.FromStrings("__name__", "enc_series_timeid", hermes.SIDLabel, sid0),
	} {
		_, err := app.Append(0, lset, 100, 1)
		require.NoError(t, err)
	}
	require.NoError(t, app.Commit())

	ir, err := head.Index()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ir.Close()) })

	// Both targets index job="myapp"; only the first indexes its own instance.
	ix, writers, reader := hermesTestRoles(t)
	epoch, _ := ix.Epoch()
	for _, u := range []struct {
		wid         int
		name, value string
		docID       uint64
	}{
		{0, "job", "myapp", hermesTestSID0},
		{1, "job", "myapp", hermesTestSID1},
		{0, "instance", "localhost:2112", hermesTestSID0},
	} {
		op, err := writers[u.wid].Update(epoch, promadapter.Keyword(u.name, u.value), u.docID)
		require.NoError(t, err)
		require.NoError(t, ix.Update(u.wid, op))
	}

	queryFor := func(name, value string) *hindex.SearchQuery {
		q, err := reader.Query(epoch, []int{0, 1}, promadapter.Keyword(name, value))
		require.NoError(t, err)
		return q
	}
	ctx := hermes.Bind(context.Background(), hermes.NewBindings(ix, map[string]*hindex.SearchQuery{
		"q0": queryFor("job", "myapp"),
		"q1": queryFor("instance", "localhost:2112"),
	}))

	name := labels.MustNewMatcher(labels.MatchEqual, "__name__", "enc_series")
	search := func(ids string) *labels.Matcher {
		return labels.MustNewMatcher(labels.MatchEqual, hermes.MatcherName, ids)
	}

	t.Run("resolves to the same series as a plaintext sid selector", func(t *testing.T) {
		got := postingsRefs(t, ctx, ir, name, search("q0"))
		want := postingsRefs(t, ctx, ir, name,
			labels.MustNewMatcher(labels.MatchRegexp, hermes.SIDLabel, sid0+"|"+sid1))
		require.Equal(t, want, got)
		require.Len(t, got, 2)
	})

	t.Run("intersects several searches", func(t *testing.T) {
		got := postingsRefs(t, ctx, ir, name, search("q0,q1"))
		want := postingsRefs(t, ctx, ir, name,
			labels.MustNewMatcher(labels.MatchEqual, hermes.SIDLabel, sid0))
		require.Equal(t, want, got)
		require.Len(t, got, 1)
	})

	t.Run("intersects with ordinary matchers", func(t *testing.T) {
		timeID := labels.MustNewMatcher(labels.MatchEqual, "__name__", "enc_series_timeid")
		require.Len(t, postingsRefs(t, ctx, ir, timeID, search("q0")), 1,
			"only one of the two matched series has a timeID companion")
	})

	t.Run("a search matching nothing yields nothing", func(t *testing.T) {
		miss := hermes.NewBindings(ix, map[string]*hindex.SearchQuery{"q0": queryFor("job", "absent")})
		require.Empty(t, postingsRefs(t, hermes.Bind(context.Background(), miss), ir, name, search("q0")))
	})

	t.Run("an unbound request is rejected", func(t *testing.T) {
		_, err := PostingsForMatchers(context.Background(), ir, name, search("q0"))
		require.ErrorIs(t, err, hermes.ErrNotEnabled)
	})

	t.Run("plaintext selectors are untouched", func(t *testing.T) {
		require.Len(t, postingsRefs(t, context.Background(), ir, name), 2)
	})
}

// hermesTestRoles builds the index, its writers and the reader from one seed.
func hermesTestRoles(t *testing.T) (*hermes.Index, []*hindex.Writer, *hindex.Reader) {
	t.Helper()
	ix, err := hermes.New([]byte(hermesTestSeed), hermesTestWriters)
	require.NoError(t, err)
	auth, err := hickae.NewAuthority(detrand.New(hermesTestSeed), hermesTestWriters)
	require.NoError(t, err)

	writers := make([]*hindex.Writer, hermesTestWriters)
	for wid := range writers {
		key := prf.DeriveWriterKey([]byte(hermesTestSeed), wid)
		writers[wid] = hindex.NewWriter(wid, key, auth.PK, auth.CBK[wid], partition.DefaultConfig(), rand.Reader)
	}
	return ix, writers, hindex.NewReader(auth.SK, auth.Master, partition.DefaultConfig(), rand.Reader)
}

// postingsRefs resolves matchers to the sorted series references they select.
func postingsRefs(t *testing.T, ctx context.Context, ir IndexReader, ms ...*labels.Matcher) []storage.SeriesRef {
	t.Helper()
	p, err := PostingsForMatchers(ctx, ir, ms...)
	require.NoError(t, err)
	refs, err := index.ExpandPostings(ir.SortedPostings(p))
	require.NoError(t, err)
	return refs
}
