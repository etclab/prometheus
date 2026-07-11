package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/prometheus/prometheus/promql/parser"
)

// alertRule is one alerting rule after it has been split at the comparison into
// the part Prometheus evaluates (the aggregation subquery) and the part this
// evaluator applies itself (the threshold comparison).
//
// This mirrors the encrypted split in research/timecrypteval: the server runs
// only the aggregation and the key holder / trusted evaluator applies the final
// comparison. Here there is no encryption, so the "aggregation" runs as plain
// PromQL over the Prometheus HTTP API, but the cut point is identical.
type alertRule struct {
	name  string // the rule's alertname.
	query string // aggregation subquery sent to Prometheus (comparison stripped).

	// hasComparison is false for a bare-vector rule (fire on every returned
	// series). When true the fields below gate firing per series.
	hasComparison   bool
	op              parser.ItemType // comparison operator.
	threshold       float64         // scalar operand.
	thresholdOnLeft bool            // true for `scalar OP query`, false for `query OP scalar`.

	forDur      time.Duration
	labels      map[string]string
	annotations map[string]string
}

// loadRules parses an alerting-rule file with Prometheus's own rulefmt loader
// and splits every alerting rule into its aggregation subquery + comparison.
// Recording rules and rules whose expression cannot be split are skipped with a
// warning, so the file stays a normal Prometheus rule file.
func loadRules(file string, logger *slog.Logger) ([]alertRule, error) {
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
			ar, err := splitRule(p, r)
			if err != nil {
				logger.Warn("skipping rule this evaluator cannot split", "alert", r.Alert, "expr", r.Expr, "err", err)
				continue
			}
			out = append(out, ar)
			logger.Info("loaded alerting rule",
				"alert", ar.name, "aggregation_query", ar.query,
				"op", ar.op.String(), "threshold", ar.threshold, "for", ar.forDur)
		}
	}
	return out, nil
}

// atp: okay
// splitRule cuts one rulefmt.Rule at its top-level comparison. It reuses the
// PromQL parser (parser.ParseExpr) and reconstructs the aggregation subquery
// with the AST's String() method, exactly as research/timecrypteval.parse does,
// so the query sent to Prometheus is a faithful re-render of the operand.
func splitRule(p parser.Parser, r rulefmt.Rule) (alertRule, error) {
	expr, err := p.ParseExpr(r.Expr)
	if err != nil {
		return alertRule{}, fmt.Errorf("parsing expr: %w", err)
	}

	base := alertRule{
		name:        r.Alert,
		forDur:      time.Duration(r.For),
		labels:      r.Labels,
		annotations: r.Annotations,
	}

	bin, ok := expr.(*parser.BinaryExpr)
	if !ok || !bin.Op.IsComparisonOperator() {
		// No top-level comparison: send the whole expression and fire on every
		// series it returns (matches Prometheus alerting on a bare vector).
		base.query = expr.String()
		base.hasComparison = false
		return base, nil
	}

	base.hasComparison = true
	base.op = bin.Op
	switch {
	case isNumber(bin.RHS):
		base.query = bin.LHS.String()
		base.threshold = bin.RHS.(*parser.NumberLiteral).Val
		base.thresholdOnLeft = false
	case isNumber(bin.LHS):
		base.query = bin.RHS.String()
		base.threshold = bin.LHS.(*parser.NumberLiteral).Val
		base.thresholdOnLeft = true
	default:
		return alertRule{}, fmt.Errorf("comparison has no scalar side (vector-vector comparisons are not supported)")
	}
	return base, nil
}

func isNumber(e parser.Expr) bool {
	_, ok := e.(*parser.NumberLiteral)
	return ok
}

// fires reports whether a series value satisfies the rule's threshold. Bare
// vectors always fire; otherwise the comparison is applied in the same operand
// order as the original PromQL.
func (r alertRule) fires(value float64) bool {
	if !r.hasComparison {
		return true
	}
	if r.thresholdOnLeft {
		return compare(r.op, r.threshold, value)
	}
	return compare(r.op, value, r.threshold)
}

// compare applies a PromQL comparison operator (mirrors
// research/timecrypteval/eval.go).
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
