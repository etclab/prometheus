package main

import (
	"strings"
	"testing"

	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

// TestSplitRule_Trace is a learning/observability test: it walks the same AST
// shape splitRule walks and logs every intermediate piece, then runs splitRule
// and dumps the resulting alertRule. Run it with:
//
//	go test ./research/timecrypteval -run TestSplitRule_Trace -v
//
// It asserts nothing about the pieces (the other rules_test.go cases cover
// behaviour); its only job is to make the decomposition visible.
func TestSplitRule_Trace(t *testing.T) {
	streams, _ := setup(t)
	p := parser.NewParser(parser.Options{})

	exprs := []string{
		"delta(" + testMetric + "[1m]) < 0",
		"100 < sum_over_time(" + testMetric + "[5m])",
		"avg_over_time(" + testMetric + `{instance="localhost:2112"}[1m]) > 5`,
	}

	for _, expr := range exprs {
		t.Run(expr, func(t *testing.T) {
			traceExpr(t, p, expr)

			t.Log("--- running splitRule ---")
			ar, err := splitRuleExpr(p, streams, expr)
			if err != nil {
				t.Logf("splitRule rejected: %v", err)
				return
			}
			t.Logf("alertRule: name=%q fn=%q family=%v window=%v",
				ar.name, ar.fn, ar.family, ar.window)
			t.Logf("           op=%s threshold=%v thresholdOnLeft=%v hasComparison=%v",
				ar.op, ar.threshold, ar.thresholdOnLeft, ar.hasComparison)
			t.Logf("           matchers=%s stream!=nil=%v",
				matchersString(ar.matchers), ar.stream != nil)
		})
	}
}

// traceExpr parses expr and logs each layer of the AST that splitRule peels off,
// so the pieces of the parsed query are visible in the test output.
func traceExpr(t *testing.T, p parser.Parser, expr string) {
	t.Helper()

	root, err := p.ParseExpr(expr)
	if err != nil {
		t.Logf("parse error: %v", err)
		return
	}
	t.Logf("root node: %T -> %s", root, root.String())

	bin, ok := root.(*parser.BinaryExpr)
	if !ok {
		t.Logf("not a BinaryExpr; splitRule would reject")
		return
	}
	t.Logf("binary op: %s (comparison=%v)", bin.Op, bin.Op.IsComparisonOperator())
	t.Logf("  LHS: %T -> %s", bin.LHS, bin.LHS.String())
	t.Logf("  RHS: %T -> %s", bin.RHS, bin.RHS.String())

	// Identify the scalar side and the call side, mirroring splitRule.
	var call *parser.Call
	switch {
	case isNumber(bin.RHS):
		t.Logf("scalar side: RHS = %v  =>  `query OP scalar` (thresholdOnLeft=false)",
			bin.RHS.(*parser.NumberLiteral).Val)
		call, _ = bin.LHS.(*parser.Call)
	case isNumber(bin.LHS):
		t.Logf("scalar side: LHS = %v  =>  `scalar OP query` (thresholdOnLeft=true)",
			bin.LHS.(*parser.NumberLiteral).Val)
		call, _ = bin.RHS.(*parser.Call)
	default:
		t.Logf("neither side is a scalar; splitRule would reject")
		return
	}
	if call == nil {
		t.Logf("non-scalar side is not a range-function Call; splitRule would reject")
		return
	}

	fam, ok := familyOf(call.Func.Name)
	t.Logf("call: %s(...)  family=%v supported=%v", call.Func.Name, fam, ok)
	t.Logf("  args: %d", len(call.Args))
	if len(call.Args) != 1 {
		return
	}

	ms, ok := call.Args[0].(*parser.MatrixSelector)
	if !ok {
		t.Logf("  arg[0] is %T, not a MatrixSelector; splitRule would reject", call.Args[0])
		return
	}
	t.Logf("  matrix selector: window=%v", ms.Range)

	vs, ok := ms.VectorSelector.(*parser.VectorSelector)
	if !ok {
		t.Logf("  inner selector is %T, not a plain VectorSelector; splitRule would reject", ms.VectorSelector)
		return
	}
	t.Logf("  vector selector label matchers: %d", len(vs.LabelMatchers))
	for _, m := range vs.LabelMatchers {
		role := "matcher"
		if m.Name == model.MetricNameLabel {
			role = "metric name (__name__)"
		}
		t.Logf("    %-10s %s%s%q", role, m.Name, m.Type, m.Value)
	}
}

// matchersString renders label matchers compactly for the trace output.
func matchersString(ms []*labels.Matcher) string {
	if len(ms) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, m := range ms {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(m.Name + m.Type.String() + m.Value)
	}
	b.WriteByte(']')
	return b.String()
}
