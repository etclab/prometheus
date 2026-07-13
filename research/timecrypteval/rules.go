package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/prometheus/prometheus/promql/parser"
)

// family classifies the local aggregation strategy this evaluator applies to a
// rule's fetched window of ciphertext. HEAC ciphertext supports keyless addition
// but not keyless subtraction/division, so summable functions can telescope a
// windowed sum while endpoint functions must decrypt individual samples (see the
// aggregate method in eval.go for the two paths).
type family int

const (
	// familyEndpoint covers delta/increase/rate: the evaluator decrypts the two
	// window endpoints and subtracts.
	familyEndpoint family = iota
	// familySummable covers sum_over_time/avg_over_time: the evaluator adds the
	// windowed ciphertext residues locally and decrypts that single sum.
	familySummable
)

// alertRule is one alerting rule after it has been split at the comparison into
// the aggregation this evaluator performs locally (over the fetched window of
// ciphertext) and the threshold it applies itself after decrypting the per-series
// aggregate.
//
// It mirrors research/plaintexteval's alertRule, but instead of a single
// aggregation-subquery string it keeps the parsed pieces (metric stream,
// matchers, function, window) the local aggregation paths need to select the raw
// range and pick decryption keys.
type alertRule struct {
	name string // the rule's alertname.

	stream   *encStream        // the encrypted metric's decryption scheme.
	matchers []*labels.Matcher // selector matchers, excluding __name__.
	fn       string            // delta | increase | rate | sum_over_time | avg_over_time.
	family   family            // which encrypted evaluation path fn takes.
	window   time.Duration     // the range-vector window.

	// The comparison stripped from the rule and re-applied here, per series,
	// after decryption. hasComparison is always true for accepted rules (a
	// threshold is the whole point of an encrypted alert).
	hasComparison   bool
	op              parser.ItemType // comparison operator.
	threshold       float64         // scalar operand.
	thresholdOnLeft bool            // true for `scalar OP query`, false for `query OP scalar`.

	forDur      time.Duration
	labels      map[string]string
	annotations map[string]string
}

// atp: are alerting rules always so simple? ie. has two parts:
// atp: threshold comparison and aggregate

// loadRules parses an alerting-rule file with Prometheus's own rulefmt loader
// and splits every alerting rule into its aggregation + comparison. Recording
// rules, rules over non-encrypted metrics, and rules whose shape this evaluator
// cannot handle are skipped with a warning, so the file stays a normal
// Prometheus rule file shared with the built-in evaluator.
func loadRules(file string, streams map[string]*encStream, logger *slog.Logger) ([]alertRule, error) {
	p := parser.NewParser(parser.Options{})
	rgs, errs := rulefmt.ParseFile(file, false, model.UTF8Validation, p, logger)
	if len(errs) > 0 {
		return nil, fmt.Errorf("parsing %s: %w", file, errs[0])
	}

	var out []alertRule
	for _, g := range rgs.Groups {
		for _, r := range g.Rules {
			if r.Alert == "" {
				continue // recording rule: not our concern.
			}
			ar, err := splitRule(p, r, streams)
			if err != nil {
				logger.Warn("skipping rule this evaluator cannot handle", "alert", r.Alert, "expr", r.Expr, "err", err)
				continue
			}
			out = append(out, ar)
			logger.Info("loaded alerting rule",
				"alert", ar.name, "fn", ar.fn, "window", ar.window,
				"op", ar.op.String(), "threshold", ar.threshold, "for", ar.forDur)
		}
	}
	return out, nil
}

// atp: what if there's nested comparisons under the top-level comparisons?
// what if there are multiple streams?

// splitRule cuts one rulefmt.Rule at its top-level comparison into
// `OP(metric{...}[w]) CMP k` over an encrypted (manifest-listed) metric. It
// reuses the PromQL parser, so the extracted metric/matchers/window/function are
// a faithful decomposition of the operand. Anything outside this bounded shape
// returns an error and is skipped by loadRules.
func splitRule(p parser.Parser, r rulefmt.Rule, streams map[string]*encStream) (alertRule, error) {
	expr, err := p.ParseExpr(r.Expr)
	if err != nil {
		return alertRule{}, fmt.Errorf("parsing expr: %w", err)
	}

	bin, ok := expr.(*parser.BinaryExpr)
	if !ok || !bin.Op.IsComparisonOperator() {
		return alertRule{}, fmt.Errorf("expression is not a top-level threshold comparison")
	}

	base := alertRule{
		name:          r.Alert,
		forDur:        time.Duration(r.For),
		labels:        r.Labels,
		annotations:   r.Annotations,
		hasComparison: true,
		op:            bin.Op,
	}

	// One side must be a scalar, the other the aggregation call.
	var call *parser.Call
	switch {
	case isNumber(bin.RHS):
		c, ok := bin.LHS.(*parser.Call)
		if !ok {
			return alertRule{}, fmt.Errorf("comparison operand is not a range function call")
		}
		call = c
		base.threshold = bin.RHS.(*parser.NumberLiteral).Val
		base.thresholdOnLeft = false
	case isNumber(bin.LHS):
		c, ok := bin.RHS.(*parser.Call)
		if !ok {
			return alertRule{}, fmt.Errorf("comparison operand is not a range function call")
		}
		call = c
		base.threshold = bin.LHS.(*parser.NumberLiteral).Val
		base.thresholdOnLeft = true
	default:
		return alertRule{}, fmt.Errorf("comparison has no scalar side (vector-vector comparisons are not supported)")
	}

	fam, ok := familyOf(call.Func.Name)
	if !ok {
		return alertRule{}, fmt.Errorf("unsupported function %q", call.Func.Name)
	}
	base.fn = call.Func.Name
	base.family = fam

	// atp: weird - never seen matrix selector or data type before in the docs
	if len(call.Args) != 1 {
		return alertRule{}, fmt.Errorf("%s expects a single range-vector argument", call.Func.Name)
	}
	// atp: MatrixSelector is a VectorSelector plus a window range
	// ie. Instant vectors for every timestamp in the range
	ms, ok := call.Args[0].(*parser.MatrixSelector)
	if !ok {
		return alertRule{}, fmt.Errorf("%s argument is not a range vector", call.Func.Name)
	}
	// atp: VectorSelector selects an instant vector
	vs, ok := ms.VectorSelector.(*parser.VectorSelector)
	if !ok {
		return alertRule{}, fmt.Errorf("range vector is not a plain selector")
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
	st, ok := streams[metric]
	if !ok {
		return alertRule{}, fmt.Errorf("metric %q is not an encrypted stream in the manifest", metric)
	}
	base.stream = st
	base.matchers = matchers
	base.window = ms.Range
	return base, nil
}

// atp: a better way to classify functions?

// familyOf maps a supported range function to its encrypted evaluation path.
func familyOf(fn string) (family, bool) {
	switch fn {
	case "delta", "increase", "rate":
		return familyEndpoint, true
	case "sum_over_time", "avg_over_time":
		return familySummable, true
	}
	return 0, false
}

func isNumber(e parser.Expr) bool {
	_, ok := e.(*parser.NumberLiteral)
	return ok
}

// fires reports whether a decrypted series value satisfies the rule's threshold,
// applied in the same operand order as the original PromQL.
func (r alertRule) fires(value float64) bool {
	if !r.hasComparison {
		return true
	}
	if r.thresholdOnLeft {
		return compare(r.op, r.threshold, value)
	}
	return compare(r.op, value, r.threshold)
}

// compare applies a PromQL comparison operator.
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
