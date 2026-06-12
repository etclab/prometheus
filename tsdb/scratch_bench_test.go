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
	"math"
	"os"
	"testing"
	"time"

	clusion "github.com/aashutoshpaudyal/clusion-go"
	timecrypt "github.com/aashutoshpaudyal/timecrypt-go"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
	"github.com/prometheus/prometheus/tsdb/index"
)

// These benchmarks quantify the query-time cost of the encrypted-search
// research prototype (CJJJKRS/DynRH2Lev index + TimeCrypt HEAC values) against
// a plaintext baseline, using the JSON fixture produced by the generator in
// scratch_data_gen_test.go. Both variants share an identical TSDB retrieval
// path, so the difference is exactly the encrypted index search and the value
// crypto.
//
// The encrypted sub-benchmarks are split along the SSE/HEAC trust boundary,
// because in a real split deployment the Prometheus server holds no keys and
// the work runs on two different machines:
//
//   - server/* runs on the (untrusted) Prometheus server with no keys: matching
//     the search token against the encrypted index, scanning the TSDB, and the
//     homomorphic ciphertext SUM. This is the server's query delay.
//   - client/* runs on the (trusted) key holder: deriving the search token,
//     resolving identifier ciphertexts to refs, and decrypting the aggregate.
//     The threshold comparison happens here too, after decryption — the server
//     can neither decrypt the aggregate nor decide whether the alert fires.
//
//	BenchmarkQueryBaseline/index_search           map-backed inverted-index lookup
//	BenchmarkQueryBaseline/retrieve_sum           TSDB scan + plaintext sum
//	BenchmarkQueryBaseline/end_to_end             the whole plaintext query (all server-side)
//
//	BenchmarkQueryEncrypted/server/cjjjkrs_match  token match against the encrypted index
//	BenchmarkQueryEncrypted/server/retrieve_sum   TSDB scan + homomorphic ciphertext sum
//	BenchmarkQueryEncrypted/client/gen_token      derive the search token (master key)
//	BenchmarkQueryEncrypted/client/resolve_refs   decrypt identifier ciphertexts to refs
//	BenchmarkQueryEncrypted/client/timecrypt_decrypt  HEAC decrypt of the per-series aggregates
//	BenchmarkQueryEncrypted/end_to_end            the full client+server round trip
//
// Run only these (the package has unrelated BenchmarkQuery* benchmarks):
//
//	go test ./tsdb -run '^$' -bench '^BenchmarkQuery(Baseline|Encrypted)$' -benchmem

// Sinks defeat dead-code elimination; each benchmark writes its accumulated
// result to the matching-typed sink after its timed loop.
var (
	benchResultSink float64
	benchIntSink    int
	benchInt64Sink  int64
	benchTokenSink  clusion.DynRH2LevToken
)

// benchStream builds a per-series TimeCrypt stream cipher with a distinct
// 16-byte master seed derived from the series index.
func benchStream(seriesIdx int) *timecrypt.TimeCryptEncryptionLong {
	master := make([]byte, 16)
	master[0] = byte(seriesIdx)
	master[1] = byte(seriesIdx >> 8)
	skm, err := timecrypt.NewStreamKeyManager(master, 20)
	noErr(err)
	return timecrypt.NewTimeCryptEncryptionLong(skm.TreeKeyRegression())
}

// builtBaseline is a plaintext TSDB plus its in-memory inverted index, built
// from a dataset. None of the construction cost is timed by the benchmarks.
type builtBaseline struct {
	db   *DB
	dir  string
	memp *index.MemPostings
}

func (bb *builtBaseline) close() {
	noErr(bb.db.Close())
	noErr(os.RemoveAll(bb.dir))
}

// buildBaseline appends every series with its plaintext values and fills a
// MemPostings exactly as the Head would.
func buildBaseline(tb testing.TB, ds scratchDataset) *builtBaseline {
	tb.Helper()
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "tsdb-bench")
	noErr(err)
	db, err := Open(dir, nil, nil, DefaultOptions(), nil)
	noErr(err)

	app := db.Appender(ctx)
	baseTS := time.Now().UnixMilli()
	memp := index.NewMemPostings()
	for _, s := range ds.Series {
		lset := s.labelSet()
		var ref storage.SeriesRef
		for t, v := range s.Values {
			ref, err = app.Append(ref, lset, baseTS+int64(t)*1000, v)
			noErr(err)
		}
		memp.Add(ref, lset)
	}
	noErr(app.Commit())
	return &builtBaseline{db: db, dir: dir, memp: memp}
}

// builtEncrypted is a TSDB holding TimeCrypt ciphertext samples, the encrypted
// (CJJJKRS) inverted index, the per-series stream ciphers keyed by ref, and a
// label-set -> ref map the client uses to recover a series' keystore entry.
type builtEncrypted struct {
	db          *DB
	dir         string
	ep          *index.EncryptedMemPostings
	streams     map[storage.SeriesRef]*timecrypt.TimeCryptEncryptionLong
	refByLabels map[string]storage.SeriesRef
}

func (be *builtEncrypted) close() {
	noErr(be.db.Close())
	noErr(os.RemoveAll(be.dir))
}

// buildEncrypted appends every series' values as TimeCrypt ciphertext bits and
// indexes each series in the encrypted multi-map. All key generation, stream
// construction and index population happen here, outside any timed loop.
func buildEncrypted(tb testing.TB, ds scratchDataset) *builtEncrypted {
	tb.Helper()
	ctx := context.Background()
	const scale = timecrypt.DefaultFixedPointScale

	dir, err := os.MkdirTemp("", "tsdb-bench")
	noErr(err)
	db, err := Open(dir, nil, nil, DefaultOptions(), nil)
	noErr(err)

	key, err := clusion.KeyGen(256, "correct horse battery staple", []byte("clusion-salt"), 100000)
	noErr(err)
	ep, err := index.NewEncryptedMemPostings(key)
	noErr(err)

	app := db.Appender(ctx)
	baseTS := time.Now().UnixMilli()
	streams := make(map[storage.SeriesRef]*timecrypt.TimeCryptEncryptionLong, len(ds.Series))
	refByLabels := make(map[string]storage.SeriesRef, len(ds.Series))
	for i, s := range ds.Series {
		lset := s.labelSet()
		enc := benchStream(i)
		var ref storage.SeriesRef
		for t, v := range s.Values {
			ct, err := enc.EncryptMetadata(timecrypt.FloatToFixed(v, scale), int64(t), 0)
			noErr(err)
			ref, err = app.Append(ref, lset, baseTS+int64(t)*1000, math.Float64frombits(uint64(ct)))
			noErr(err)
		}
		noErr(ep.Add(ref, lset))
		streams[ref] = enc
		refByLabels[lset.String()] = ref
	}
	noErr(app.Commit())
	return &builtEncrypted{db: db, dir: dir, ep: ep, streams: streams, refByLabels: refByLabels}
}

// encAggregate is the server-side homomorphic sum of a matched series'
// ciphertext samples plus the sample count, ready for a single HEAC decrypt.
type encAggregate struct {
	ref   storage.SeriesRef
	sumCt int64
	n     int64
}

// serverAggregates computes, for every series matched by matcher, the
// homomorphic sum of its ciphertext samples and the sample count. This is the
// keyless server-side step; it seeds the decrypt-only sub-benchmark and serves
// as the aggregate the end-to-end path recomputes each iteration.
func (be *builtEncrypted) serverAggregates(tb testing.TB, q storage.Querier, matcher *labels.Matcher) []encAggregate {
	tb.Helper()
	var out []encAggregate
	ss := q.Select(context.Background(), false, nil, matcher)
	for ss.Next() {
		series := ss.At()
		a := encAggregate{ref: be.refByLabels[series.Labels().String()]}
		it := series.Iterator(nil)
		for it.Next() == chunkenc.ValFloat {
			_, v := it.At()
			a.sumCt += int64(math.Float64bits(v))
			a.n++
		}
		noErr(it.Err())
		out = append(out, a)
	}
	noErr(ss.Err())
	return out
}

// BenchmarkQueryBaseline measures the plaintext query and its phases.
func BenchmarkQueryBaseline(b *testing.B) {
	ctx := context.Background()
	ds := loadOrGenerateScratchData(b, *scratchDataPath)
	bb := buildBaseline(b, ds)
	defer bb.close()

	querier, err := benchOpenQuerier(bb.db)
	noErr(err)
	defer func() { noErr(querier.Close()) }()

	matcher := labels.MustNewMatcher(labels.MatchEqual, scratchSelName, scratchSelValue)
	b.Logf("dataset: %d series x %d samples, selector %s=%q matches %d series",
		ds.Config.NumSeries, ds.Config.SamplesPerSeries, scratchSelName, scratchSelValue, ds.matchedSeries())

	b.Run("index_search", func(b *testing.B) {
		b.ReportAllocs()
		var sink int
		for i := 0; i < b.N; i++ {
			refs, err := index.ExpandPostings(bb.memp.Postings(ctx, scratchSelName, scratchSelValue))
			noErr(err)
			sink += len(refs)
		}
		benchIntSink = sink
	})

	b.Run("retrieve_sum", func(b *testing.B) {
		b.ReportAllocs()
		var sink float64
		for i := 0; i < b.N; i++ {
			ss := querier.Select(ctx, false, nil, matcher)
			for ss.Next() {
				it := ss.At().Iterator(nil)
				for it.Next() == chunkenc.ValFloat {
					_, v := it.At()
					sink += v
				}
				noErr(it.Err())
			}
			noErr(ss.Err())
		}
		benchResultSink = sink
	})

	b.Run("end_to_end", func(b *testing.B) {
		b.ReportAllocs()
		var sink float64
		for i := 0; i < b.N; i++ {
			refs, err := index.ExpandPostings(bb.memp.Postings(ctx, scratchSelName, scratchSelValue))
			noErr(err)
			_ = refs
			ss := querier.Select(ctx, false, nil, matcher)
			for ss.Next() {
				it := ss.At().Iterator(nil)
				for it.Next() == chunkenc.ValFloat {
					_, v := it.At()
					sink += v
				}
				noErr(it.Err())
			}
			noErr(ss.Err())
		}
		benchResultSink = sink
	})
}

// BenchmarkQueryEncrypted measures the encrypted query, isolating the CJJJKRS
// search and the TimeCrypt decrypt into their own sub-benchmarks.
func BenchmarkQueryEncrypted(b *testing.B) {
	ctx := context.Background()
	const scale = timecrypt.DefaultFixedPointScale
	ds := loadOrGenerateScratchData(b, *scratchDataPath)
	be := buildEncrypted(b, ds)
	defer be.close()

	querier, err := benchOpenQuerier(be.db)
	noErr(err)
	defer func() { noErr(querier.Close()) }()

	matcher := labels.MustNewMatcher(labels.MatchEqual, scratchSelName, scratchSelValue)
	aggs := be.serverAggregates(b, querier, matcher)
	b.Logf("dataset: %d series x %d samples, selector %s=%q matches %d series",
		ds.Config.NumSeries, ds.Config.SamplesPerSeries, scratchSelName, scratchSelValue, len(aggs))

	// Precompute the artifacts that cross the trust boundary so each side's
	// work can be timed alone: the token the client hands to the server, and
	// the identifier ciphertexts the server hands back to the client.
	token := be.ep.GenToken(scratchSelName, scratchSelValue)
	handoffCts, err := be.ep.QueryCiphertexts(token)
	noErr(err)

	// server/cjjjkrs_match: the server matches the client's token against the
	// encrypted index. Keyless; this is the index half of the server delay.
	b.Run("server/cjjjkrs_match", func(b *testing.B) {
		b.ReportAllocs()
		var sink int
		for i := 0; i < b.N; i++ {
			cts, err := be.ep.QueryCiphertexts(token)
			noErr(err)
			sink += len(cts)
		}
		benchIntSink = sink
	})

	// server/retrieve_sum: identical TSDB scan to the baseline, but adding the
	// opaque ciphertext bits. Keyless homomorphic SUM; comparable to the
	// baseline retrieve_sum. This is the value half of the server delay.
	b.Run("server/retrieve_sum", func(b *testing.B) {
		b.ReportAllocs()
		var sink int64
		for i := 0; i < b.N; i++ {
			ss := querier.Select(ctx, false, nil, matcher)
			for ss.Next() {
				it := ss.At().Iterator(nil)
				for it.Next() == chunkenc.ValFloat {
					_, v := it.At()
					sink += int64(math.Float64bits(v))
				}
				noErr(it.Err())
			}
			noErr(ss.Err())
		}
		benchInt64Sink = sink
	})

	// client/gen_token: the key holder derives the search token (master key).
	b.Run("client/gen_token", func(b *testing.B) {
		b.ReportAllocs()
		var sink clusion.DynRH2LevToken
		for i := 0; i < b.N; i++ {
			sink = be.ep.GenToken(scratchSelName, scratchSelValue)
		}
		benchTokenSink = sink
	})

	// client/resolve_refs: the key holder decrypts the identifier ciphertexts
	// the server returned back into series refs (resolve key).
	b.Run("client/resolve_refs", func(b *testing.B) {
		b.ReportAllocs()
		var sink int
		for i := 0; i < b.N; i++ {
			refs, err := be.ep.ResolveRefs(handoffCts)
			noErr(err)
			sink += len(refs)
		}
		benchIntSink = sink
	})

	// client/timecrypt_decrypt: the key holder performs one HEAC decrypt per
	// matched series over its aggregate. The server cannot do this step.
	b.Run("client/timecrypt_decrypt", func(b *testing.B) {
		b.ReportAllocs()
		var sink float64
		for i := 0; i < b.N; i++ {
			for _, a := range aggs {
				dec, err := be.streams[a.ref].DecryptMetadata(a.sumCt, 0, a.n-1, 0)
				noErr(err)
				sink += timecrypt.FixedToFloat(dec, scale)
			}
		}
		benchResultSink = sink
	})

	// The full client+server round trip: token gen, server match, resolve,
	// server scan+sum, then per matched series a single decrypt.
	b.Run("end_to_end", func(b *testing.B) {
		b.ReportAllocs()
		var sink float64
		for i := 0; i < b.N; i++ {
			cts, err := be.ep.QueryCiphertexts(be.ep.GenToken(scratchSelName, scratchSelValue))
			noErr(err)
			_, err = be.ep.ResolveRefs(cts)
			noErr(err)
			ss := querier.Select(ctx, false, nil, matcher)
			for ss.Next() {
				series := ss.At()
				var sumCt, n int64
				it := series.Iterator(nil)
				for it.Next() == chunkenc.ValFloat {
					_, v := it.At()
					sumCt += int64(math.Float64bits(v))
					n++
				}
				noErr(it.Err())
				ref := be.refByLabels[series.Labels().String()]
				dec, err := be.streams[ref].DecryptMetadata(sumCt, 0, n-1, 0)
				noErr(err)
				sink += timecrypt.FixedToFloat(dec, scale)
			}
			noErr(ss.Err())
		}
		benchResultSink = sink
	})
}

// benchOpenQuerier opens a full-range querier over the whole time domain.
func benchOpenQuerier(db *DB) (storage.Querier, error) {
	return db.Querier(math.MinInt64, math.MaxInt64)
}
