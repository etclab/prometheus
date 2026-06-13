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
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
	"github.com/prometheus/prometheus/tsdb/chunks"
	"github.com/prometheus/prometheus/tsdb/index"
)

// TestEncryptedIndexWalkthrough is the encrypted companion to
// TestInvertedIndexWalkthrough. It tells the same story — store series, build
// an inverted index, select with label matchers, read values back — but now:
//
//   - the inverted index is encrypted with the CJJJKRS14 "2Lev" searchable
//     symmetric encryption (SSE) scheme, in its add-only dynamic response-hiding
//     form DynRH2Lev (clusion-go). The server matches *search tokens*, never the
//     label=value pair itself.
//   - the sample values are encrypted with TimeCrypt's HEAC additively-
//     homomorphic encryption (timecrypt-go). The server can SUM ciphertexts over
//     a time range with no keys; only the client can decrypt the result.
//
// Run it with:
//
//	go test ./tsdb -run '^TestEncryptedIndexWalkthrough$' -v
//
// Every line is tagged [CLIENT] or [SERVER] so the -v output reads as a trace
// across the trust boundary. The one rule to keep in mind:
//
//	╔══════════════════════════ TRUST BOUNDARY ══════════════════════════╗
//	║ CLIENT holds ALL keys: the SSE master key and the per-series HEAC   ║
//	║   stream seeds. It encrypts labels into tokens and values into      ║
//	║   ciphertexts, and is the only party that can decrypt anything.     ║
//	║ SERVER (the TSDB + encrypted index) is untrusted storage+compute:   ║
//	║   it holds opaque ciphertexts, matches tokens, and homomorphically  ║
//	║   sums ciphertexts. It never sees a label pair, a sample value, a   ║
//	║   query's plaintext, or a result in the clear.                      ║
//	╚════════════════════════════════════════════════════════════════════╝
//
// (In this prototype one process plays both roles for convenience — the
// EncryptedMemPostings holds the client key next to the server structure — but
// every call below is annotated with which side it would run on in a real
// split deployment.)
func TestEncryptedIndexWalkthrough(t *testing.T) {
	ctx := context.Background()

	// ---------------------------------------------------------------------
	// Act 0 — Client key material (never leaves the client).
	// ---------------------------------------------------------------------
	// One SSE master key protects the whole index. One TimeCrypt HEAC stream
	// (a key-regression tree seeded by a per-series master) protects each
	// series' values. The server gets neither.
	t.Log("=== Act 0: [CLIENT] generate keys — these never cross the trust boundary ===")

	// SSE master key for the encrypted index (CJJJKRS / DynRH2Lev).
	sseKey, err := clusion.KeyGen(256, "correct horse battery staple", []byte("clusion-salt"), 100000)
	noErr(err)
	t.Logf("[CLIENT] SSE master key derived (%d-bit) for the encrypted inverted index", len(sseKey)*8)

	// One HEAC stream per series. The float samples ride the additive scheme
	// as fixed-point integers.
	const scale = timecrypt.DefaultFixedPointScale
	newStream := func(seed byte) *timecrypt.TimeCryptEncryptionLong {
		master := make([]byte, 16)
		master[0] = seed
		skm, err := timecrypt.NewStreamKeyManager(master, 20)
		noErr(err)
		return timecrypt.NewTimeCryptEncryptionLong(skm.TreeKeyRegression())
	}
	t.Log("[CLIENT] one TimeCrypt HEAC stream seeded per series for the sample values")

	// ---------------------------------------------------------------------
	// Act 1 — The series (plaintext, client side only).
	// ---------------------------------------------------------------------
	// Same toy dataset as the plaintext walkthrough: the `up` metric (1 =
	// healthy, 0 = down) for an api and a db job across two environments. The
	// client knows these in the clear; the server only ever sees encrypted
	// forms. Each sample carries a per-series timeID — the HEAC key index, a
	// 0-based sample counter, NOT the wall-clock timestamp.
	type sample struct {
		timeID int64
		ts     int64
		v      float64
	}
	type seriesDef struct {
		seed    byte
		lset    labels.Labels
		samples []sample
	}
	base := time.Now().UnixMilli()
	mk := func(timeID int64, v float64) sample {
		return sample{timeID: timeID, ts: base + timeID*15000, v: v}
	}
	defs := []seriesDef{
		{seed: 1, lset: labels.FromStrings(model.MetricNameLabel, "up", "job", "api", "instance", "10.0.0.1", "env", "prod"),
			samples: []sample{mk(0, 1), mk(1, 1), mk(2, 0)}}, // up 2/3 of the time
		{seed: 2, lset: labels.FromStrings(model.MetricNameLabel, "up", "job", "api", "instance", "10.0.0.2", "env", "prod"),
			samples: []sample{mk(0, 1), mk(1, 1), mk(2, 1)}}, // up 3/3
		{seed: 3, lset: labels.FromStrings(model.MetricNameLabel, "up", "job", "db", "instance", "10.0.0.3", "env", "prod"),
			samples: []sample{mk(0, 1), mk(1, 0), mk(2, 0)}}, // up 1/3
		{seed: 4, lset: labels.FromStrings(model.MetricNameLabel, "up", "job", "db", "instance", "10.0.0.4", "env", "staging"),
			samples: []sample{mk(0, 1), mk(1, 1), mk(2, 1)}}, // up 3/3
	}

	t.Log("")
	t.Log("=== Act 1: [CLIENT] the four plaintext series (only the client ever sees these) ===")
	for i, d := range defs {
		vals := make([]float64, len(d.samples))
		for j, s := range d.samples {
			vals[j] = s.v
		}
		t.Logf("[CLIENT] series #%d  %s  values=%v", i, d.lset.String(), vals)
	}

	// ---------------------------------------------------------------------
	// Act 2 — Encrypt and store (client encrypts; server stores opaque bits).
	// ---------------------------------------------------------------------
	// VALUES: the client HEAC-encrypts each sample to an int64 ciphertext and
	// ships it to the TSDB as the bit pattern of a float64 (the XOR chunk
	// encoding stores the 64 bits verbatim, so the ciphertext survives a round
	// trip). The server stores what looks like random floats.
	dir, err := os.MkdirTemp("", "tsdb-enc-walkthrough")
	noErr(err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	db, err := Open(dir, nil, nil, DefaultOptions(), nil)
	noErr(err)
	t.Cleanup(func() { _ = db.Close() })
	app := db.Appender(ctx)

	streams := map[storage.SeriesRef]*timecrypt.TimeCryptEncryptionLong{}
	refOf := map[int]storage.SeriesRef{}
	wantSum := map[storage.SeriesRef]float64{} // plaintext sum_over_time the client expects.

	t.Log("")
	t.Log("=== Act 2: [CLIENT] encrypt, [SERVER] store opaque ciphertexts ===")
	for i, d := range defs {
		enc := newStream(d.seed)
		var ref storage.SeriesRef
		var sum float64
		for _, s := range d.samples {
			// [CLIENT] HEAC-encrypt the fixed-point value at its key index.
			ct, err := enc.EncryptMetadata(timecrypt.FloatToFixed(s.v, scale), s.timeID, 0)
			noErr(err)
			// [SERVER] append the ciphertext bits as an ordinary float sample.
			ref, err = app.Append(ref, d.lset, s.ts, math.Float64frombits(uint64(ct)))
			noErr(err)
			sum += s.v
		}
		refOf[i] = ref
		streams[ref] = enc
		wantSum[ref] = sum
	}
	noErr(app.Commit())

	// Show what the server actually holds for one series: garbage floats.
	t.Log("[SERVER] sample values as stored (HEAC ciphertext bits reinterpreted as float64):")
	q0, err := db.Querier(math.MinInt64, math.MaxInt64)
	noErr(err)
	ss0 := q0.Select(ctx, false, nil, labels.MustNewMatcher(labels.MatchEqual, "instance", "10.0.0.1"))
	for ss0.Next() {
		it := ss0.At().Iterator(nil)
		for it.Next() == chunkenc.ValFloat {
			_, v := it.At()
			t.Logf("[SERVER]   stored=%v  (bits=%#016x)  <- server cannot tell this was a 1 or a 0",
				v, math.Float64bits(v))
		}
	}
	noErr(ss0.Err())
	noErr(q0.Close())

	// INDEX: the client builds the encrypted inverted index. Add() encrypts
	// each (label pair, series ref) into an update token client-side and
	// applies it to the server-side encrypted multi-map.
	ep, err := index.NewEncryptedMemPostings(sseKey)
	noErr(err)
	for i, d := range defs {
		// [CLIENT] TokenUpdate over the label set + [SERVER] Update applied.
		noErr(ep.Add(refOf[i], d.lset))
	}
	t.Log("[CLIENT] built the encrypted inverted index (each label pair -> series ref, encrypted)")

	// ---------------------------------------------------------------------
	// Act 3 — What an *encrypted* posting is (server side).
	// ---------------------------------------------------------------------
	// The plaintext index mapped "job=api" -> [1 2] in the clear. Here the
	// server holds a dictionary of CMAC-derived labels -> AES-CTR identifier
	// ciphertexts. There is no "job", no "api", no "[1 2]" anywhere — and,
	// unlike MemPostings, the server cannot even enumerate the label names or
	// values. That non-enumerability is the security goal of keyword hiding.
	dict := ep.DictionaryUpdates()
	t.Log("")
	t.Log("=== Act 3: [SERVER] the encrypted index — CMAC label -> identifier ciphertext ===")
	t.Logf("[SERVER] dictionary holds %d entries (4 series x (4 label pairs + all-postings key)); a few:", len(dict))
	shown := 0
	for l, v := range dict {
		t.Logf("[SERVER]   %x... -> %x...", l[:min(12, len(l))], v[:min(16, len(v))])
		if shown++; shown == 3 {
			break
		}
	}
	t.Log("[SERVER] no label names, no values, no refs in the clear, and no way to list them.")
	require.Len(t, dict, 20)

	// ---------------------------------------------------------------------
	// Act 4 — Selecting through the SSE round trip.
	// ---------------------------------------------------------------------
	// A query is three stages straddling the boundary:
	//   1. [CLIENT] GenToken(name,value)      — derive a search token.
	//   2. [SERVER] QueryCiphertexts(token)   — match it, return encrypted hits.
	//   3. [CLIENT] ResolveRefs(ciphertexts)  — decrypt to series refs.
	// EncryptedMemPostings.Postings() bundles all three, so Intersect (AND) and
	// Merge (OR) compose exactly as in the plaintext walkthrough — over sorted
	// posting lists the server produced without ever learning the query.
	expand := func(p index.Postings) []storage.SeriesRef {
		refs, err := index.ExpandPostings(p)
		noErr(err)
		return refs
	}

	t.Log("")
	t.Log("=== Act 4: select by label; the round trip never reveals the pair to the server ===")

	// Spell out the three stages once for {job="api"} so the boundary is explicit.
	tok := ep.GenToken("job", "api") // [CLIENT]
	t.Log(`[CLIENT] GenToken("job","api") -> search token (CMAC tags + counter)`)
	cts, err := ep.QueryCiphertexts(tok) // [SERVER]
	noErr(err)
	t.Logf("[SERVER] QueryCiphertexts(token) -> %d encrypted hit(s); server sees only ciphertext", len(cts))
	apiRefs, err := ep.ResolveRefs(cts) // [CLIENT]
	noErr(err)
	t.Logf(`[CLIENT] ResolveRefs(...) -> job="api" = %v`, apiRefs)

	// AND / OR compose over the encrypted posting lists just like the plaintext case.
	dbAndProd := expand(index.Intersect(
		ep.Postings(ctx, "job", "db"),
		ep.Postings(ctx, "env", "prod"),
	))
	t.Logf(`[CLIENT] job="db" AND env="prod" -> %v   (Intersect of two encrypted lists)`, dbAndProd)

	apiOrDB := expand(index.Merge(ctx,
		ep.Postings(ctx, "job", "api"),
		ep.Postings(ctx, "job", "db"),
	))
	t.Logf(`[CLIENT] job="api" OR  job="db"  -> %v   (Merge / union)`, apiOrDB)

	// A pair that was never indexed yields nothing — and the server still
	// learns nothing about why.
	none := expand(ep.Postings(ctx, "env", "qa"))
	t.Logf(`[CLIENT] env="qa" (never indexed) -> %v   (empty, as expected)`, none)

	require.Equal(t, []storage.SeriesRef{refOf[0], refOf[1]}, apiRefs)
	require.Len(t, apiOrDB, 4)
	require.Len(t, dbAndProd, 1)
	require.Empty(t, none)

	// ---------------------------------------------------------------------
	// Act 5 — Homomorphic range aggregation (avg_over_time(up{job="api"})).
	// ---------------------------------------------------------------------
	// This is where HEAC earns its keep. To evaluate avg_over_time the server
	// needs sum(values) and count(values) per series. The count is just the
	// number of samples (public). The sum is computed homomorphically: HEAC
	// ciphertexts telescope, so adding the int64 bits of adjacent samples sums
	// the underlying plaintexts — WITHOUT KEYS. The server produces the
	// encrypted sum; only the client, holding the boundary seeds, decrypts.
	t.Log("")
	t.Log(`=== Act 5: avg_over_time(up{job="api"}) — [SERVER] sums ciphertext, [CLIENT] decrypts ===`)

	querier, err := db.Querier(math.MinInt64, math.MaxInt64)
	noErr(err)
	t.Cleanup(func() { _ = querier.Close() })

	for _, ref := range apiRefs {
		// [SERVER] resolve the ref to its (still-plaintext, in this prototype)
		// label set, select its ciphertext samples, and SUM the bits. In a real
		// split deployment the head's labels would be encrypted too; here they
		// remain to keep the example to two moving parts. See the note in
		// scratch_test.go's TestScratchEncryptedValues.
		ms := db.Head().series.getByID(chunks.HeadSeriesRef(ref))
		var matchers []*labels.Matcher
		ms.lset.Range(func(l labels.Label) {
			matchers = append(matchers, labels.MustNewMatcher(labels.MatchEqual, l.Name, l.Value))
		})
		ss := querier.Select(ctx, false, nil, matchers...)
		var sumCt, n int64
		for ss.Next() {
			it := ss.At().Iterator(nil)
			for it.Next() == chunkenc.ValFloat {
				_, v := it.At()
				sumCt += int64(math.Float64bits(v)) // ciphertext + ciphertext
				n++
			}
			noErr(it.Err())
		}
		noErr(ss.Err())
		t.Logf("[SERVER] series ref %d: homomorphic ciphertext sum=%#x over n=%d samples (no keys used)",
			ref, uint64(sumCt), n)

		// [CLIENT] decrypt the aggregate using only the boundary key indices
		// [0, n-1]; the per-sample keys in between are never materialized.
		dec, err := streams[ref].DecryptMetadata(sumCt, 0, n-1, 0)
		noErr(err)
		sum := timecrypt.FixedToFloat(dec, scale)
		avg := sum / float64(n)
		t.Logf("[CLIENT] series ref %d: decrypted sum_over_time=%g -> avg_over_time(up)=%.3f (availability)",
			ref, sum, avg)

		require.InDelta(t, wantSum[ref], sum, 1e-9)
	}

	// ---------------------------------------------------------------------
	// Recap of the trust boundary.
	// ---------------------------------------------------------------------
	t.Log("")
	t.Log("=== Trust boundary recap ===")
	t.Log("[CLIENT] encrypts: label pairs -> SSE tokens; sample values -> HEAC ciphertexts. Holds all keys.")
	t.Log("[CLIENT] decrypts: search results (refs) and homomorphic aggregates. The only party that can.")
	t.Log("[SERVER] stores:   opaque float bits + a CMAC->ciphertext dictionary. Computes: token match + ciphertext SUM.")
	t.Log("[SERVER] never sees: label pairs, sample values, query plaintext, results, or even the label vocabulary.")
}
