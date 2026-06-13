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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
	"github.com/prometheus/prometheus/tsdb/index"
)

// TestInvertedIndexWalkthrough is a narrated, run-it-and-read-the-output tour of
// how Prometheus stores time series in the clear and how the inverted index
// turns a label query into a set of matching series. Run it with:
//
//	go test ./tsdb -run '^TestInvertedIndexWalkthrough$' -v
//
// Every step prints what it is doing with t.Log, so the -v output reads top to
// bottom as an explanation. Nothing here is encrypted: labels, values and the
// index are all plaintext, which is exactly the baseline you want before
// reasoning about an encrypted variant.
//
// The story in five acts:
//
//  1. What a series is: an immutable set of labels (one of which is the metric
//     name __name__) plus an ordered stream of (timestamp, value) samples.
//  2. How it is stored: the label set is interned once and addressed by a
//     numeric series ref; samples are appended into chunks under that ref.
//  3. What the inverted index ("postings") is: a map from a single label=value
//     pair to the *sorted list of series refs* that carry that pair.
//  4. How a query selects: one matcher is one posting list lookup; an AND of
//     matchers is the intersection of their lists; an OR is the merge (union).
//  5. How selected series are read back and merged into one result stream.
func TestInvertedIndexWalkthrough(t *testing.T) {
	ctx := context.Background()

	// ---------------------------------------------------------------------
	// Act 1 — What a series looks like.
	// ---------------------------------------------------------------------
	// A series is identified entirely by its labels. The metric name is not
	// special at storage time: it is just the label __name__ (the constant
	// model.MetricNameLabel). Two series are "the same" iff their full label
	// sets are equal.
	//
	// Our toy dataset is the classic `up` metric (1 = target healthy) for an
	// "api" job and a "db" job, spread across two environments. Read the four
	// label sets below as four distinct series.
	type sample struct {
		t int64
		v float64
	}
	type seriesDef struct {
		lset    labels.Labels
		samples []sample
	}

	base := time.Now().UnixMilli()
	defs := []seriesDef{
		{
			lset:    labels.FromStrings(model.MetricNameLabel, "up", "job", "api", "instance", "10.0.0.1", "env", "prod"),
			samples: []sample{{base, 1}, {base + 15000, 1}, {base + 30000, 0}},
		},
		{
			lset:    labels.FromStrings(model.MetricNameLabel, "up", "job", "api", "instance", "10.0.0.2", "env", "prod"),
			samples: []sample{{base, 1}, {base + 15000, 1}, {base + 30000, 1}},
		},
		{
			lset:    labels.FromStrings(model.MetricNameLabel, "up", "job", "db", "instance", "10.0.0.3", "env", "prod"),
			samples: []sample{{base, 1}, {base + 15000, 0}, {base + 30000, 0}},
		},
		{
			lset:    labels.FromStrings(model.MetricNameLabel, "up", "job", "db", "instance", "10.0.0.4", "env", "staging"),
			samples: []sample{{base, 1}, {base + 15000, 1}, {base + 30000, 1}},
		},
	}

	t.Log("=== Act 1: four time series (a series == its label set + its samples) ===")
	for i, d := range defs {
		// labels.Labels stringifies to the familiar {k="v", ...} PromQL form.
		// Note __name__ is shown as the metric name but is stored like any
		// other label.
		t.Logf("series #%d  %s", i, d.lset.String())
		for _, s := range d.samples {
			t.Logf("            sample t=%d v=%g", s.t, s.v)
		}
	}

	// ---------------------------------------------------------------------
	// Act 2 — How it is stored (in the clear).
	// ---------------------------------------------------------------------
	// We open a real local TSDB and append the samples. Internally the Head:
	//   - interns each unique label set and assigns it a numeric series ref
	//     (a small integer handle, so the labels are stored once, not per
	//     sample);
	//   - appends each sample's (timestamp, value) into that series' chunk,
	//     XOR/delta compressed but otherwise plaintext;
	//   - records the series ref under every one of its label=value pairs in
	//     the inverted index (Act 3).
	dir, err := os.MkdirTemp("", "tsdb-walkthrough")
	noErr(err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	db, err := Open(dir, nil, nil, DefaultOptions(), nil)
	noErr(err)
	t.Cleanup(func() { _ = db.Close() })

	app := db.Appender(ctx)
	// Remember the ref the Head assigned to each series so we can talk about
	// "series ref N" concretely below. The first Append uses ref 0 ("I don't
	// know the ref yet"); the returned ref can be reused for the same series
	// to skip the label lookup on subsequent appends.
	refOf := map[int]storage.SeriesRef{}
	for i, d := range defs {
		// ref starts at 0 ("unknown") and is reused once known, so only the
		// first append of each series pays the label lookup.
		var ref storage.SeriesRef
		for _, s := range d.samples {
			ref, err = app.Append(ref, d.lset, s.t, s.v)
			noErr(err)
		}
		refOf[i] = ref
	}
	noErr(app.Commit())

	t.Log("")
	t.Log("=== Act 2: stored in the clear; the Head assigned each label set a numeric series ref ===")
	for i, d := range defs {
		t.Logf("series ref %d  ->  %s", refOf[i], d.lset.String())
	}
	t.Log("The label set is interned ONCE per ref; every sample is stored under that integer ref,")
	t.Log("so labels are not repeated per sample. Nothing here is encrypted.")

	// ---------------------------------------------------------------------
	// Act 3 — What the inverted index (postings) is.
	// ---------------------------------------------------------------------
	// "Postings" is Prometheus' name for the inverted index, borrowed from
	// classic text search: for each term (here a single label=value pair) it
	// stores a "posting list" — the SORTED list of series refs that contain
	// that term. Sorted order is what makes intersect/merge linear-time later.
	//
	// We read the real index the Head just built. Reaching the unexported
	// Head.postings field is allowed because this test is in package tsdb.
	postings := db.Head().postings

	t.Log("")
	t.Log("=== Act 3: the inverted index — each label=value pair -> sorted list of series refs ===")
	for _, l := range postings.SortedKeys() {
		refs, err := index.ExpandPostings(postings.Postings(ctx, l.Name, l.Value))
		noErr(err)
		// The special key ""="" (the empty label) is the "all postings" key:
		// it lists every series and is how a query with no equality matcher
		// (or a pure negative/regex query) still gets a starting set.
		name, value := l.Name, l.Value
		if name == "" && value == "" {
			t.Logf(`  ALL-POSTINGS key ""="" -> %v   (indexes every series)`, refs)
			continue
		}
		t.Logf("  %s=%q -> %v", name, value, refs)
	}
	t.Log("A single label=value pair pointing at its sorted refs IS a posting list.")

	// ---------------------------------------------------------------------
	// Act 4 — How a query selects and combines posting lists.
	// ---------------------------------------------------------------------
	// A PromQL selector like up{job="api"} becomes index lookups:
	//
	//   - one equality matcher  = one posting-list lookup;
	//   - matcher AND matcher   = INTERSECTION of the two lists (Intersect);
	//   - matcher OR  matcher   = UNION / MERGE of the lists (Merge).
	//
	// Because every list is sorted by series ref, both operations are a
	// straight merge-walk over the lists.
	expand := func(p index.Postings) []storage.SeriesRef {
		refs, err := index.ExpandPostings(p)
		noErr(err)
		return refs
	}

	t.Log("")
	t.Log("=== Act 4: selecting series by combining posting lists ===")

	// 4a. Single matcher: up{job="api"} -> just one posting list.
	jobAPI := expand(postings.Postings(ctx, "job", "api"))
	t.Logf(`  job="api"                      -> %v   (one posting list)`, jobAPI)

	// 4b. AND: up{job="db", env="prod"} -> intersection of two lists. Only the
	// db series that is also in prod survives.
	dbAndProd := expand(index.Intersect(
		postings.Postings(ctx, "job", "db"),
		postings.Postings(ctx, "env", "prod"),
	))
	t.Logf(`  job="db" AND env="prod"        -> %v   (Intersect of two lists)`, dbAndProd)

	// 4c. OR across different series, then merge them together: this selects
	// the api series and the db series and unions the result. This is the
	// "queried different time series and then merged them together" case.
	apiOrDB := expand(index.Merge(ctx,
		postings.Postings(ctx, "job", "api"),
		postings.Postings(ctx, "job", "db"),
	))
	t.Logf(`  job="api" OR  job="db"         -> %v   (Merge / union of lists)`, apiOrDB)

	// 4d. All series, via the special all-postings key.
	allName, allValue := index.AllPostingsKey()
	all := expand(postings.Postings(ctx, allName, allValue))
	t.Logf(`  {} (all-postings key)          -> %v   (every series)`, all)

	// ---------------------------------------------------------------------
	// Act 5 — Read the selected series back and merge into one result stream.
	// ---------------------------------------------------------------------
	// Act 4 worked purely on the index and produced *refs*. A real query then
	// hands those refs to a Querier, which resolves each ref back to its label
	// set and its samples, and the SeriesSet presents them merged and sorted
	// into a single stream — which is what PromQL iterates over.
	//
	// We run env="prod" here: it spans BOTH jobs (api and db), so the one
	// matcher already selects three different series that the querier merges
	// together for us.
	t.Log("")
	t.Log(`=== Act 5: resolving refs back to series and merging — querier.Select(env="prod") ===`)
	querier, err := db.Querier(math.MinInt64, math.MaxInt64)
	noErr(err)
	t.Cleanup(func() { _ = querier.Close() })

	ss := querier.Select(ctx, true, nil, labels.MustNewMatcher(labels.MatchEqual, "env", "prod"))
	var got []string
	for ss.Next() {
		s := ss.At()
		var b strings.Builder
		fmt.Fprintf(&b, "  %s  samples=[", s.Labels().String())
		it := s.Iterator(nil)
		first := true
		for it.Next() == chunkenc.ValFloat {
			ts, v := it.At()
			if !first {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "(%d,%g)", ts, v)
			first = false
		}
		noErr(it.Err())
		b.WriteString("]")
		got = append(got, b.String())
	}
	noErr(ss.Err())
	// Select with sortSeries=true returns series in label order; sort our
	// captured lines too so the logged output is deterministic.
	sort.Strings(got)
	for _, line := range got {
		t.Log(line)
	}
	t.Log("Three different series (two api + one db, all in prod) came back merged into one")
	t.Log("sorted result set — that is the whole point of the inverted index.")

	// A couple of assertions so the walkthrough also doubles as a real test
	// and fails loudly if the storage/index contract ever changes.
	if len(got) != 3 {
		t.Fatalf(`expected env="prod" to select 3 series, got %d`, len(got))
	}
	if len(apiOrDB) != 4 {
		t.Fatalf(`expected job="api" OR job="db" to merge to 4 series, got %d`, len(apiOrDB))
	}
	if len(dbAndProd) != 1 {
		t.Fatalf(`expected job="db" AND env="prod" to intersect to 1 series, got %d`, len(dbAndProd))
	}
}
