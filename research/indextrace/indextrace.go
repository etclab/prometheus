// Package indextrace provides opt-in tracing of the write path that turns a
// scraped exposition line into (label, value) -> series-ID postings, for the
// encrypted-Prometheus experiment.
//
// It exists to answer one question at runtime: where are the plaintext label
// sets materialised, who mints the series ID, and what exactly lands in the
// inverted index? Those are the structures the experiment needs to encrypt, so
// being able to watch them being built — in both plaintext and TimeCrypt mode —
// is the starting point.
//
// Tracing is off unless PROM_INDEX_TRACE=1, because the demo configs also
// scrape Prometheus itself (~1000 series) and would drown the interesting
// output. PROM_INDEX_TRACE_FILTER narrows it further to label sets whose
// __name__ contains the given substring; it defaults to "myapp", so the usual
// invocation is just PROM_INDEX_TRACE=1.
//
// Trace lines go to stderr with a leading "indextrace" tag, so they can be
// separated from Prometheus's own slog output with a grep:
//
//	PROM_INDEX_TRACE=1 research/scripts/run.sh 2>&1 | grep indextrace
//
// This package is research scaffolding, not something to carry upstream: it is
// imported by core packages (scrape, tsdb, tsdb/index) purely so the trace sits
// at the real call sites.
package indextrace

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/labels"
)

var (
	once    sync.Once
	enabled bool
	filter  string

	// mtx keeps concurrent trace lines from interleaving. The scrape loop and
	// the head appender both write here from different goroutines.
	mtx sync.Mutex
)

func init0() {
	enabled = os.Getenv("PROM_INDEX_TRACE") == "1"
	filter = os.Getenv("PROM_INDEX_TRACE_FILTER")
	if filter == "" {
		filter = "myapp"
	}
}

// Enabled reports whether tracing is switched on via PROM_INDEX_TRACE=1.
// Call it before doing any work to build trace arguments, so that a disabled
// trace costs nothing on the append path.
func Enabled() bool {
	once.Do(init0)
	return enabled
}

// Match reports whether lset passes the PROM_INDEX_TRACE_FILTER substring test
// against its __name__ label. A label set without __name__ never matches.
func Match(lset labels.Labels) bool {
	once.Do(init0)
	return strings.Contains(lset.Get(model.MetricNameLabel), filter)
}

// On reports whether tracing is enabled and lset passes the filter. It is the
// single guard the call sites use.
func On(lset labels.Labels) bool {
	return Enabled() && Match(lset)
}

// Log writes one trace line attributed to stage, which names the call site
// (e.g. "scrape/parsed"). Callers must guard with On or Enabled first.
//
// The timestamp is included so trace lines can be lined up against Prometheus's
// own slog output, which is what makes it possible to tell a scrape-driven
// append apart from one driven by WAL replay at startup.
func Log(stage, format string, args ...any) {
	mtx.Lock()
	defer mtx.Unlock()
	fmt.Fprintf(os.Stderr, "indextrace time=%s %-22s %s\n",
		time.Now().Format("15:04:05.000"), stage, fmt.Sprintf(format, args...))
}
