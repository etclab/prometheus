// Package timecrypteval is the key-holding rule evaluator for the
// encrypted-Prometheus demo. It wraps the normal PromQL rule QueryFunc so that
// alerting/recording rules over TimeCrypt-encrypted metrics are evaluated
// without the server ever holding plaintext samples:
//
//   - Selection uses the ordinary (plaintext) label index — the encrypted
//     index (CJJJKRS) is out of scope here.
//   - Temporal reduction (Layer 2) over the [window] is computed from the
//     stored HEAC ciphertexts. Linear sums telescope, so sum_over_time /
//     avg_over_time aggregate ciphertexts with no keys; delta/rate/increase
//     read the two window endpoints.
//   - The terminal comparison (`> k`, `< k`, ...) cannot run under additive
//     HE, so it happens here, at the key holder: this evaluator decrypts the
//     per-series aggregate and applies the comparison. The firing decision is
//     made client-side.
//
// Any query that is not a supported `OP(metric{...}[w]) CMP k` over a
// manifest-listed encrypted metric is delegated unchanged to the wrapped
// engine QueryFunc, so Prometheus's own metrics and recording rules behave
// normally.
package timecrypteval

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/rules"
	"github.com/prometheus/prometheus/storage"
)

// QueryFunc is the wrapped-QueryFunc signature alias for readability.
type QueryFunc = rules.QueryFunc

// Evaluator evaluates rules over TimeCrypt-encrypted metrics by decrypting the
// per-series aggregate before the threshold comparison.
type Evaluator struct {
	delegate QueryFunc
	store    storage.Queryable
	parser   parser.Parser
	streams  map[string]*encStream // keyed by encrypted metric name.
}

// New builds an Evaluator from the key material in keysDir (manifest.json plus
// the per-stream master seeds) and returns a QueryFunc that falls back to
// delegate for anything it does not handle.
func New(delegate QueryFunc, store storage.Queryable, keysDir string) (QueryFunc, error) {
	streams, err := loadStreams(keysDir)
	if err != nil {
		return nil, err
	}
	e := &Evaluator{
		delegate: delegate,
		store:    store,
		parser:   parser.NewParser(parser.Options{}),
		streams:  streams,
	}
	return e.eval, nil
}

// parsedRule is the bounded shape this evaluator understands.
type parsedRule struct {
	stream    *encStream
	matchers  []*labels.Matcher // selector matchers, excluding __name__.
	fn        string            // delta | rate | increase | sum_over_time | avg_over_time.
	window    time.Duration
	op        parser.ItemType // comparison operator.
	threshold float64
}

// eval is the wrapped QueryFunc.
func (e *Evaluator) eval(ctx context.Context, qs string, t time.Time) (promql.Vector, error) {
	pr, ok := e.parse(qs)
	if !ok {
		return e.delegate(ctx, qs, t)
	}
	return e.evalEncrypted(ctx, pr, t)
}

// parse recognises `OP(metric{...}[w]) CMP k` over an encrypted metric. It
// returns ok=false (so the caller delegates) for anything else.
func (e *Evaluator) parse(qs string) (parsedRule, bool) {
	expr, err := e.parser.ParseExpr(qs)
	if err != nil {
		return parsedRule{}, false
	}
	bin, ok := expr.(*parser.BinaryExpr)
	if !ok || !bin.Op.IsComparisonOperator() {
		return parsedRule{}, false
	}
	// Expect `call(...) CMP number`.
	call, ok := bin.LHS.(*parser.Call)
	if !ok {
		return parsedRule{}, false
	}
	num, ok := bin.RHS.(*parser.NumberLiteral)
	if !ok {
		return parsedRule{}, false
	}
	switch call.Func.Name {
	case "delta", "rate", "increase", "sum_over_time", "avg_over_time":
	default:
		return parsedRule{}, false
	}
	if len(call.Args) != 1 {
		return parsedRule{}, false
	}
	ms, ok := call.Args[0].(*parser.MatrixSelector)
	if !ok {
		return parsedRule{}, false
	}
	vs, ok := ms.VectorSelector.(*parser.VectorSelector)
	if !ok {
		return parsedRule{}, false
	}

	var metric string
	var matchers []*labels.Matcher
	for _, m := range vs.LabelMatchers {
		if m.Name == model.MetricNameLabel {
			metric = m.Value
			continue
		}
		matchers = append(matchers, m)
	}
	st, ok := e.streams[metric]
	if !ok {
		return parsedRule{}, false
	}
	return parsedRule{
		stream:    st,
		matchers:  matchers,
		fn:        call.Func.Name,
		window:    ms.Range,
		op:        bin.Op,
		threshold: num.Val,
	}, true
}

// evalEncrypted runs the encrypted Layer-2 evaluation + threshold comparison.
func (e *Evaluator) evalEncrypted(ctx context.Context, pr parsedRule, t time.Time) (promql.Vector, error) {
	maxt := t.UnixMilli()
	mint := t.Add(-pr.window).UnixMilli()

	q, err := e.store.Querier(mint, maxt)
	if err != nil {
		return nil, err
	}
	defer q.Close()

	// Pull the encrypted value series and the companion timeID series over the
	// window. Both carry the same non-name labels, so they pair by identity.
	values, err := collectSeries(ctx, q, pr.stream.metric, pr.matchers, mint, maxt)
	if err != nil {
		return nil, err
	}
	timeids, err := collectSeries(ctx, q, pr.stream.timeIDMetric, pr.matchers, mint, maxt)
	if err != nil {
		return nil, err
	}

	var out promql.Vector
	for key, vseries := range values {
		tseries, ok := timeids[key]
		if !ok {
			// No timeID companion for this series: we cannot pick keys, skip.
			continue
		}
		agg, ok, err := e.aggregate(pr, vseries, tseries)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if !compare(pr.op, agg, pr.threshold) {
			continue
		}
		out = append(out, promql.Sample{
			T:        maxt,
			F:        agg,
			Metric:   vseries.metric, // delta/rate/etc. drop __name__; collectSeries already stripped it.
			DropName: true,
		})
	}
	return out, nil
}

// aggregate computes the decrypted Layer-2 reduction for one series, returning
// ok=false when there are too few samples to produce a value.
func (e *Evaluator) aggregate(pr parsedRule, vs, ts seriesSamples) (float64, bool, error) {
	st := pr.stream
	// Align value and timeID samples by timestamp.
	points := pair(vs, ts)
	if len(points) == 0 {
		return 0, false, nil
	}
	sort.Slice(points, func(i, j int) bool { return points[i].t < points[j].t })

	switch pr.fn {
	case "delta", "rate", "increase":
		if len(points) < 2 {
			return 0, false, nil
		}
		first, last := points[0], points[len(points)-1]
		// Decrypt the two window endpoints (point decryption: timeID range
		// [i,i]). The server only ever held ciphertext.
		mFirst, err := st.decryptPoint(first.residue, first.timeID)
		if err != nil {
			return 0, false, err
		}
		mLast, err := st.decryptPoint(last.residue, last.timeID)
		if err != nil {
			return 0, false, err
		}
		delta := mLast - mFirst
		if pr.fn == "rate" {
			secs := float64(last.t-first.t) / 1000
			if secs <= 0 {
				return 0, false, nil
			}
			return delta / secs, true, nil
		}
		return delta, true, nil

	case "sum_over_time", "avg_over_time":
		sum, err := st.decryptWindowSum(points)
		if err != nil {
			return 0, false, err
		}
		if pr.fn == "avg_over_time" {
			return sum / float64(len(points)), true, nil
		}
		return sum, true, nil
	}
	return 0, false, fmt.Errorf("timecrypteval: unsupported function %q", pr.fn)
}

// compare applies a PromQL comparison operator (vector OP scalar).
//
//nolint:exhaustive // non-comparison operators are filtered out before this is called.
func compare(op parser.ItemType, lhs, rhs float64) bool {
	switch op {
	case parser.EQLC:
		return lhs == rhs
	case parser.NEQ:
		return lhs != rhs
	case parser.LSS:
		return lhs < rhs
	case parser.LTE:
		return lhs <= rhs
	case parser.GTR:
		return lhs > rhs
	case parser.GTE:
		return lhs >= rhs
	}
	return false
}
