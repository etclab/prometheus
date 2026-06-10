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

	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
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
