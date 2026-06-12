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
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	clusion "github.com/aashutoshpaudyal/clusion-go"
	timecrypt "github.com/aashutoshpaudyal/timecrypt-go"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
	"github.com/prometheus/prometheus/tsdb/chunks"
	"github.com/prometheus/prometheus/tsdb/index"
)

func TestScratch(t *testing.T) {
	// Create a random dir to work in.  Open() doesn't require a pre-existing dir, but
	// we want to make sure not to make a mess where we shouldn't.
	dir, err := os.MkdirTemp("", "tsdb-test")
	noErr(err)

	// Open a TSDB for reading and/or writing.
	db, err := Open(dir, nil, nil, DefaultOptions(), nil)
	noErr(err)

	// Open an appender for writing.
	app := db.Appender(context.Background())

	// Synthetic base timestamp; TSDB timestamps are milliseconds since epoch.
	ts := time.Now().UnixMilli()

	{
		// The metric name is just another label: __name__ (model.MetricNameLabel).
		seriesLinux := labels.FromStrings(model.MetricNameLabel, "cpu_usage_ratio",
			"host", "127.0.0.1", "os", "linux", "vendor", "intel")

		// Ref is 0 for the first append since we don't know the reference for the series.
		ref, err := app.Append(0, seriesLinux, ts, 0.3)
		noErr(err)

		// Another append for a second later.
		// Re-using the ref from above since it's the same series, makes append faster.
		_, err = app.Append(ref, seriesLinux, ts+1000, 0.7)
		noErr(err)
	}

	{
		// create a new series
		seriesWindows := labels.FromStrings(model.MetricNameLabel, "cpu_usage_ratio",
			"host", "127.0.0.2", "os", "windows", "vendor", "intel")

		ref, err := app.Append(0, seriesWindows, ts, 0.5)
		noErr(err)

		_, err = app.Append(ref, seriesWindows, ts+2000, 1.3)
		noErr(err)
	}

	// Commit to storage.
	err = app.Commit()
	noErr(err)

	// Dump the in-memory inverted index the head built from the appends above.
	// We can reach the unexported Head.postings field because this test is in
	// package tsdb. SortedKeys gives deterministic label-pair order; note the
	// special allPostingsKey ""="" entry that indexes every series.
	fmt.Println("inverted index:")
	postings := db.Head().postings
	for _, l := range postings.SortedKeys() {
		refs, err := index.ExpandPostings(postings.Postings(context.Background(), l.Name, l.Value))
		noErr(err)
		fmt.Printf("  %q=%q -> %v\n", l.Name, l.Value, refs)
	}

	// In case you want to do more appends after app.Commit(),
	// you need a new appender.
	app = db.Appender(context.Background())
	// ... adding more samples.

	// Open a querier for reading.
	querier, err := db.Querier(math.MinInt64, math.MaxInt64)
	noErr(err)
	ss := querier.Select(context.Background(), false, nil, labels.MustNewMatcher(labels.MatchEqual, "vendor", "intel"))

	for ss.Next() {
		series := ss.At()
		fmt.Println("series:", series.Labels().String())

		it := series.Iterator(nil)
		for it.Next() == chunkenc.ValFloat {
			_, v := it.At() // We ignore the timestamp here, only to have a predictable output we can test against (below)
			fmt.Println("sample", v)
		}

		fmt.Println("it.Err():", it.Err())
	}
	fmt.Println("ss.Err():", ss.Err())
	ws := ss.Warnings()
	if len(ws) > 0 {
		fmt.Println("warnings:", ws)
	}
	err = querier.Close()
	noErr(err)

	// Clean up any last resources when done.
	err = db.Close()
	noErr(err)
	err = os.RemoveAll(dir)
	noErr(err)
}

// TestScratchMemPostings exercises the in-memory inverted index (layer 1)
// directly, without a DB or Head. This is the same structure the Head fills
// via Head.getOrCreate -> MemPostings.Add when a new series is appended.
func TestScratchMemPostings(t *testing.T) {
	ctx := context.Background()
	p := index.NewMemPostings()

	// Series IDs are assigned by the caller (the Head uses a monotonically
	// increasing counter). MemPostings just maps label pairs to sorted ID lists.
	p.Add(1, labels.FromStrings(model.MetricNameLabel, "cpu_usage_ratio",
		"host", "127.0.0.1", "os", "linux", "vendor", "intel"))
	p.Add(2, labels.FromStrings(model.MetricNameLabel, "cpu_usage_ratio",
		"host", "127.0.0.2", "os", "windows", "vendor", "intel"))
	p.Add(3, labels.FromStrings(model.MetricNameLabel, "mem_usage_bytes",
		"host", "127.0.0.1", "os", "linux", "vendor", "amd"))

	// Single label=value lookup: one posting list.
	refs, err := index.ExpandPostings(p.Postings(ctx, "vendor", "intel"))
	noErr(err)
	fmt.Println(`vendor="intel":`, refs)

	// A multi-matcher query is an intersection of sorted posting lists.
	refs, err = index.ExpandPostings(index.Intersect(
		p.Postings(ctx, "vendor", "intel"),
		p.Postings(ctx, "os", "linux"),
	))
	noErr(err)
	fmt.Println(`vendor="intel" AND os="linux":`, refs)

	// The label names and values the index knows about. Note the special
	// allPostingsKey ("") entry that indexes every series.
	fmt.Println("label names:", p.LabelNames())
	fmt.Println("hosts:", p.LabelValues(ctx, "host", nil))
}

// TestScratchEncryptedMemPostings mirrors TestScratchMemPostings but stores
// the in-memory inverted index encrypted under the DynRH2Lev SSE scheme:
// Add encrypts each ("name=value", series ref) pair into an update token, and
// queries go through per-pair search tokens instead of map lookups. The
// plaintext index never exists server-side; only the query results do.
func TestScratchEncryptedMemPostings(t *testing.T) {
	ctx := context.Background()

	// Client master key (in a split deployment only the client holds this).
	key, err := clusion.KeyGen(256, "correct horse battery staple", []byte("clusion-salt"), 100000)
	noErr(err)
	p, err := index.NewEncryptedMemPostings(key)
	noErr(err)

	// Same three series as TestScratchMemPostings. Each Add runs the SSE
	// update protocol: TokenUpdate (client) + Update (server).
	noErr(p.Add(1, labels.FromStrings(model.MetricNameLabel, "cpu_usage_ratio",
		"host", "127.0.0.1", "os", "linux", "vendor", "intel")))
	noErr(p.Add(2, labels.FromStrings(model.MetricNameLabel, "cpu_usage_ratio",
		"host", "127.0.0.2", "os", "windows", "vendor", "intel")))
	noErr(p.Add(3, labels.FromStrings(model.MetricNameLabel, "mem_usage_bytes",
		"host", "127.0.0.1", "os", "linux", "vendor", "amd")))

	// A single label=value lookup, spelled out as the three SSE stages.
	//
	// 1. Client: derive the search token from the plaintext pair. We (the
	// client) of course know our own query in plaintext; what makes this SSE
	// is that only the token — CMAC tags derived under the secret key — is
	// given to the server side. "vendor=intel" never touches the structure.
	tok := p.GenToken("vendor", "intel")

	// 2. Server: match the token against the encrypted dictionary. The hits
	// come back still encrypted — without the key this is all the server
	// ever sees of the result.
	cts, err := p.QueryCiphertexts(tok)
	noErr(err)
	fmt.Printf("server returns %d ciphertext(s) for the token:\n", len(cts))
	for _, ct := range cts {
		fmt.Printf("  %x... (%d bytes)\n", ct[:24], len(ct))
	}

	// 3. Client: decrypt the ciphertexts with the resolve key to recover
	// the series refs.
	refs, err := p.ResolveRefs(cts)
	noErr(err)
	fmt.Println(`decrypted: vendor="intel" ->`, refs)
	require.Equal(t, []storage.SeriesRef{1, 2}, refs)

	// Intersection works unchanged: the encrypted index still yields sorted
	// posting lists, so multi-matcher queries compose exactly as before.
	refs, err = index.ExpandPostings(index.Intersect(
		p.Postings(ctx, "vendor", "intel"),
		p.Postings(ctx, "os", "linux"),
	))
	noErr(err)
	fmt.Println(`vendor="intel" AND os="linux":`, refs)
	require.Equal(t, []storage.SeriesRef{1}, refs)

	// The all-postings entry is indexed too.
	refs, err = index.ExpandPostings(p.All(ctx))
	noErr(err)
	require.Equal(t, []storage.SeriesRef{1, 2, 3}, refs)

	// A pair that was never indexed yields empty postings, and — unlike
	// MemPostings — there is no LabelNames/LabelValues: the server cannot
	// enumerate keywords, which is the point of the scheme.
	refs, err = index.ExpandPostings(p.Postings(ctx, "os", "macos"))
	noErr(err)
	require.Empty(t, refs)

	// What the server actually stores: CMAC-derived labels mapping to
	// fixed-size identifier ciphertexts. 3 series x (4 label pairs + the
	// all-postings key) = 15 entries.
	dict := p.DictionaryUpdates()
	fmt.Printf("server-side dictionary: %d entries, e.g.:\n", len(dict))
	shown := 0
	for l, v := range dict {
		fmt.Printf("  %x -> %x...\n", l, v[:16])
		if shown++; shown == 3 {
			break
		}
	}
	require.Len(t, dict, 15)
}

// TestScratchEncryptedValues mirrors TestScratch but stores the sample
// *values* TimeCrypt-encrypted, and resolves the label selector through the
// SSE-encrypted index of TestScratchEncryptedMemPostings. Together the two
// layers are the end-to-end encrypted Prometheus:
//
//   - index:  "vendor=intel" -> series refs goes through DynRH2Lev tokens
//     (clusion-go); the server never sees the label pair in plaintext.
//   - values: each sample is a HEAC ciphertext (timecrypt-go):
//     c_i = m_i + k_i - k_(i+1) (mod 2^64), with per-series keys from a
//     PRF-tree key regression. Adjacent keys telescope, so the server can
//     SUM ciphertexts over any time range without keys, and the client
//     decrypts the aggregate with only the two boundary seeds.
//
// The int64 ciphertext rides inside the regular TSDB as the bit pattern of a
// float64 sample — the XOR chunk encoding stores bits verbatim. (A production
// design would add a chunkenc encoding for int64 ciphertexts and replace the
// head's plaintext MemPostings with the encrypted version; here the plaintext
// labels still exist in the head, which is exactly the remaining gap between
// this scratch test and a real split deployment.)
func TestScratchEncryptedValues(t *testing.T) {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "tsdb-test")
	noErr(err)
	db, err := Open(dir, nil, nil, DefaultOptions(), nil)
	noErr(err)
	app := db.Appender(ctx)
	ts := time.Now().UnixMilli()

	// ---------- Client side: key material ----------
	// One TimeCrypt "stream" per Prometheus series. Only the client holds
	// the per-stream master seeds (and the SSE key below). Float samples
	// ride the additive scheme as fixed-point integers.
	const scale = timecrypt.DefaultFixedPointScale
	newStream := func(seed byte) *timecrypt.TimeCryptEncryptionLong {
		master := make([]byte, 16)
		master[0] = seed
		skm, err := timecrypt.NewStreamKeyManager(master, 20)
		noErr(err)
		return timecrypt.NewTimeCryptEncryptionLong(skm.TreeKeyRegression())
	}

	seriesLinux := labels.FromStrings(model.MetricNameLabel, "cpu_usage_ratio",
		"host", "127.0.0.1", "os", "linux", "vendor", "intel")
	seriesWindows := labels.FromStrings(model.MetricNameLabel, "cpu_usage_ratio",
		"host", "127.0.0.2", "os", "windows", "vendor", "intel")

	// Client-side keystore: series ref -> stream cipher. Populated as the
	// appends below assign refs.
	streams := map[storage.SeriesRef]*timecrypt.TimeCryptEncryptionLong{}

	// appendEncrypted encrypts value v at the per-series sample index
	// timeID (the HEAC key index, *not* the wall-clock timestamp) and
	// appends the ciphertext bits as the float64 sample.
	appendEncrypted := func(enc *timecrypt.TimeCryptEncryptionLong, lset labels.Labels, ts, timeID int64, v float64) storage.SeriesRef {
		ct, err := enc.EncryptMetadata(timecrypt.FloatToFixed(v, scale), timeID, 0)
		noErr(err)
		ref, err := app.Append(0, lset, ts, math.Float64frombits(uint64(ct)))
		noErr(err)
		return ref
	}

	encLinux, encWindows := newStream(1), newStream(2)
	refLinux := appendEncrypted(encLinux, seriesLinux, ts, 0, 0.3)
	appendEncrypted(encLinux, seriesLinux, ts+1000, 1, 0.7)
	refWindows := appendEncrypted(encWindows, seriesWindows, ts, 0, 0.5)
	appendEncrypted(encWindows, seriesWindows, ts+2000, 1, 1.3)
	noErr(app.Commit())
	streams[refLinux] = encLinux
	streams[refWindows] = encWindows

	// ---------- Encrypted index lookup (layer 1, see the test above) ----------
	key, err := clusion.KeyGen(256, "correct horse battery staple", []byte("clusion-salt"), 100000)
	noErr(err)
	ep, err := index.NewEncryptedMemPostings(key)
	noErr(err)
	noErr(ep.Add(refLinux, seriesLinux))
	noErr(ep.Add(refWindows, seriesWindows))

	tok := ep.GenToken("vendor", "intel")
	cts, err := ep.QueryCiphertexts(tok)
	noErr(err)
	refs, err := ep.ResolveRefs(cts)
	noErr(err)
	require.Equal(t, []storage.SeriesRef{refLinux, refWindows}, refs)

	// ---------- Server side: homomorphic range aggregation ----------
	// For each resolved series the server sums the opaque int64 sample
	// bits over the requested range. No keys, no plaintext.
	querier, err := db.Querier(math.MinInt64, math.MaxInt64)
	noErr(err)
	type aggregate struct {
		sumCt int64 // homomorphic sum of ciphertexts
		n     int64 // sample count (= HEAC key range)
	}
	aggregates := map[storage.SeriesRef]aggregate{}
	for _, ref := range refs {
		// The client knows the full label set of each resolved ref (it
		// indexed them); select exactly that series.
		ms := db.Head().series.getByID(chunks.HeadSeriesRef(ref))
		var matchers []*labels.Matcher
		ms.lset.Range(func(l labels.Label) {
			matchers = append(matchers, labels.MustNewMatcher(labels.MatchEqual, l.Name, l.Value))
		})
		ss := querier.Select(ctx, false, nil, matchers...)
		for ss.Next() {
			var agg aggregate
			it := ss.At().Iterator(nil)
			for it.Next() == chunkenc.ValFloat {
				_, v := it.At()
				agg.sumCt += int64(math.Float64bits(v)) // ciphertext + ciphertext
				agg.n++
			}
			noErr(it.Err())
			aggregates[ref] = agg
		}
		noErr(ss.Err())
	}
	noErr(querier.Close())

	// ---------- Client side: decrypt the aggregates ----------
	// One decryption per series, using only the boundary key indices
	// [0, n-1] — the per-sample keys in between are never materialized.
	sums := map[storage.SeriesRef]float64{}
	for ref, agg := range aggregates {
		dec, err := streams[ref].DecryptMetadata(agg.sumCt, 0, agg.n-1, 0)
		noErr(err)
		sums[ref] = timecrypt.FixedToFloat(dec, scale)
		fmt.Printf("series ref %d: server-side ciphertext sum %#x over %d samples -> decrypted sum_over_time = %v\n",
			ref, uint64(agg.sumCt), agg.n, sums[ref])
	}
	require.InDelta(t, 0.3+0.7, sums[refLinux], 1e-9)
	require.InDelta(t, 0.5+1.3, sums[refWindows], 1e-9)

	// Individual samples decrypt too (timeID i over the range [i, i]) —
	// the chunk-scan fallback for non-additive queries.
	querier, err = db.Querier(math.MinInt64, math.MaxInt64)
	noErr(err)
	ss := querier.Select(ctx, false, nil,
		labels.MustNewMatcher(labels.MatchEqual, "os", "linux"))
	for ss.Next() {
		it := ss.At().Iterator(nil)
		var timeID int64
		for it.Next() == chunkenc.ValFloat {
			_, v := it.At()
			dec, err := streams[refLinux].DecryptMetadata(int64(math.Float64bits(v)), timeID, timeID, 0)
			noErr(err)
			fmt.Printf("sample %d decrypts to %v\n", timeID, timecrypt.FixedToFloat(dec, scale))
			if timeID == 0 {
				require.InDelta(t, 0.3, timecrypt.FixedToFloat(dec, scale), 1e-9)
			} else {
				require.InDelta(t, 0.7, timecrypt.FixedToFloat(dec, scale), 1e-9)
			}
			timeID++
		}
		noErr(it.Err())
	}
	noErr(ss.Err())
	noErr(querier.Close())

	noErr(db.Close())
	noErr(os.RemoveAll(dir))
}

// TestScratchEncryptedAlert builds an alerting query on top of the two
// encrypted layers above. It models the Prometheus alerting rule
//
//	alert: HighCPU
//	expr:  avg_over_time(cpu_usage_ratio{vendor="intel"}[<range>]) > 0.6
//
// and evaluates it without the server ever seeing the selector label pair or
// the sample values in the clear:
//
//   - the {vendor="intel"} matcher is resolved through the DynRH2Lev encrypted
//     index (clusion-go, the CJJJKRS14 2Lev scheme): the server matches a
//     search token, never the label pair itself;
//   - avg_over_time's numerator is a HEAC homomorphic SUM of the int64
//     ciphertext samples and its denominator the sample count, both produced
//     server-side with no keys (timecrypt-go);
//   - the only key-holding step is the rule evaluator, which decrypts each
//     per-series aggregate, forms the average, and applies the `> threshold`
//     comparison. The firing decision is therefore made client-side: the
//     server learns neither the inputs nor whether the alert fired.
//
// The comparison cannot be pushed to the server because HEAC is additively
// homomorphic only (no order comparison); decrypt-then-compare at the
// key holder is the honest split for a threshold alert.
func TestScratchEncryptedAlert(t *testing.T) {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "tsdb-test")
	noErr(err)
	db, err := Open(dir, nil, nil, DefaultOptions(), nil)
	noErr(err)
	app := db.Appender(ctx)
	ts := time.Now().UnixMilli()

	// ---------- Client side: key material (one HEAC stream per series) ----------
	const scale = timecrypt.DefaultFixedPointScale
	newStream := func(seed byte) *timecrypt.TimeCryptEncryptionLong {
		master := make([]byte, 16)
		master[0] = seed
		skm, err := timecrypt.NewStreamKeyManager(master, 20)
		noErr(err)
		return timecrypt.NewTimeCryptEncryptionLong(skm.TreeKeyRegression())
	}

	seriesLinux := labels.FromStrings(model.MetricNameLabel, "cpu_usage_ratio",
		"host", "127.0.0.1", "os", "linux", "vendor", "intel")
	seriesWindows := labels.FromStrings(model.MetricNameLabel, "cpu_usage_ratio",
		"host", "127.0.0.2", "os", "windows", "vendor", "intel")

	streams := map[storage.SeriesRef]*timecrypt.TimeCryptEncryptionLong{}
	appendEncrypted := func(enc *timecrypt.TimeCryptEncryptionLong, lset labels.Labels, ts, timeID int64, v float64) storage.SeriesRef {
		ct, err := enc.EncryptMetadata(timecrypt.FloatToFixed(v, scale), timeID, 0)
		noErr(err)
		ref, err := app.Append(0, lset, ts, math.Float64frombits(uint64(ct)))
		noErr(err)
		return ref
	}

	// Two intel series: linux averages 0.5 (stays below the threshold) and
	// windows averages 0.9 (fires). The selector matches both; only the
	// encrypted-value evaluation tells them apart.
	encLinux, encWindows := newStream(1), newStream(2)
	refLinux := appendEncrypted(encLinux, seriesLinux, ts, 0, 0.3)
	appendEncrypted(encLinux, seriesLinux, ts+1000, 1, 0.7)
	refWindows := appendEncrypted(encWindows, seriesWindows, ts, 0, 0.5)
	appendEncrypted(encWindows, seriesWindows, ts+2000, 1, 1.3)
	noErr(app.Commit())
	streams[refLinux] = encLinux
	streams[refWindows] = encWindows

	// ---------- Encrypted index (layer 1) ----------
	key, err := clusion.KeyGen(256, "correct horse battery staple", []byte("clusion-salt"), 100000)
	noErr(err)
	ep, err := index.NewEncryptedMemPostings(key)
	noErr(err)
	noErr(ep.Add(refLinux, seriesLinux))
	noErr(ep.Add(refWindows, seriesWindows))

	// ---------- The alerting rule ----------
	const (
		alertName = "HighCPU"
		threshold = 0.6
	)
	selName, selValue := "vendor", "intel"

	// Step 1 — encrypted-label match: resolve {vendor="intel"} via the SSE
	// index. The server only ever matches the search token.
	cts, err := ep.QueryCiphertexts(ep.GenToken(selName, selValue))
	noErr(err)
	refs, err := ep.ResolveRefs(cts)
	noErr(err)
	require.ElementsMatch(t, []storage.SeriesRef{refLinux, refWindows}, refs)

	// Step 2 — encrypted-value evaluation (server side): per resolved series,
	// homomorphically SUM the opaque ciphertext samples and count them. This
	// is avg_over_time's numerator and denominator; no keys are used.
	querier, err := db.Querier(math.MinInt64, math.MaxInt64)
	noErr(err)
	type aggregate struct {
		sumCt int64 // homomorphic sum of ciphertexts (avg numerator)
		n     int64 // sample count (avg denominator, = HEAC key range)
	}
	aggregates := map[storage.SeriesRef]aggregate{}
	for _, ref := range refs {
		ms := db.Head().series.getByID(chunks.HeadSeriesRef(ref))
		var matchers []*labels.Matcher
		ms.lset.Range(func(l labels.Label) {
			matchers = append(matchers, labels.MustNewMatcher(labels.MatchEqual, l.Name, l.Value))
		})
		ss := querier.Select(ctx, false, nil, matchers...)
		for ss.Next() {
			var agg aggregate
			it := ss.At().Iterator(nil)
			for it.Next() == chunkenc.ValFloat {
				_, v := it.At()
				agg.sumCt += int64(math.Float64bits(v)) // ciphertext + ciphertext
				agg.n++
			}
			noErr(it.Err())
			aggregates[ref] = agg
		}
		noErr(ss.Err())
	}
	noErr(querier.Close())

	// Step 3 — alert evaluation (client side, key holder): decrypt each
	// aggregate, form the average, and apply the threshold comparison. Series
	// whose average exceeds the threshold fire.
	type firingAlert struct {
		ref   storage.SeriesRef
		value float64
	}
	var firing []firingAlert
	for _, ref := range refs { // deterministic order
		agg := aggregates[ref]
		dec, err := streams[ref].DecryptMetadata(agg.sumCt, 0, agg.n-1, 0)
		noErr(err)
		avg := timecrypt.FixedToFloat(dec, scale) / float64(agg.n)
		state := "ok"
		if avg > threshold {
			state = "FIRING"
			firing = append(firing, firingAlert{ref, avg})
		}
		fmt.Printf("alert %s [%s] series ref %d: avg_over_time = %v (threshold %v)\n",
			alertName, state, ref, avg, threshold)
	}

	// Only the windows series (avg 0.9) breaches the 0.6 threshold; linux
	// (avg 0.5) stays silent. The encrypted index alone could not have made
	// this distinction — it required evaluating the expression on ciphertext.
	require.Len(t, firing, 1)
	require.Equal(t, refWindows, firing[0].ref)
	require.InDelta(t, 0.9, firing[0].value, 1e-9)

	noErr(db.Close())
	noErr(os.RemoveAll(dir))
}
