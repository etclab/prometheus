package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/prometheus/prometheus/promql/parser"
)

func TestSplitRule_DeltaEndpointFamily(t *testing.T) {
	streams, _ := setup(t)
	ar := mustSplit(t, streams, "MyappOpsDecreasing", "delta("+testMetric+"[1m]) < 0")

	require.True(t, ar.hasComparison)
	require.Equal(t, "delta", ar.fn)
	require.Equal(t, familyEndpoint, ar.family)
	require.Equal(t, time.Minute, ar.window)
	require.Equal(t, parser.ItemType(parser.LSS), ar.op)
	require.Equal(t, 0.0, ar.threshold)
	require.False(t, ar.thresholdOnLeft)
	require.Empty(t, ar.matchers)
	require.NotNil(t, ar.stream)

	// The comparison gates firing in the original operand order.
	require.True(t, ar.fires(-6))
	require.False(t, ar.fires(3))
}

func TestSplitRule_ScalarOnLeftSummableFamily(t *testing.T) {
	streams, _ := setup(t)
	ar := mustSplit(t, streams, "SumHigh", "100 < sum_over_time("+testMetric+"[5m])")

	require.Equal(t, "sum_over_time", ar.fn)
	require.Equal(t, familySummable, ar.family)
	require.Equal(t, 5*time.Minute, ar.window)
	require.Equal(t, parser.ItemType(parser.LSS), ar.op)
	require.Equal(t, 100.0, ar.threshold)
	require.True(t, ar.thresholdOnLeft)

	// `100 < value` fires when value exceeds 100.
	require.True(t, ar.fires(150))
	require.False(t, ar.fires(50))
}

func TestSplitRule_AvgOverTimeSummableFamily(t *testing.T) {
	streams, _ := setup(t)
	ar := mustSplit(t, streams, "AvgHigh", "avg_over_time("+testMetric+`{instance="localhost:2112"}[1m]) > 5`)

	require.Equal(t, "avg_over_time", ar.fn)
	require.Equal(t, familySummable, ar.family)
	require.Len(t, ar.matchers, 1)
	require.Equal(t, "instance", ar.matchers[0].Name)
}

func TestSplitRule_Rejected(t *testing.T) {
	streams, _ := setup(t)
	p := parser.NewParser(parser.Options{})

	cases := map[string]string{
		"non-encrypted metric": "delta(other_metric[1m]) < 0",
		"no comparison":        "delta(" + testMetric + "[1m])",
		"vector-vector":        "delta(" + testMetric + "[1m]) < delta(" + testMetric + "[1m])",
		"unsupported function": "max_over_time(" + testMetric + "[1m]) > 0",
		"not a range function": testMetric + " > 0",
	}
	for name, expr := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := splitRuleExpr(p, streams, expr)
			require.Error(t, err)
		})
	}
}

// splitRuleExpr is a tiny test helper: split a bare expression as an alert.
func splitRuleExpr(p parser.Parser, streams map[string]*encStream, expr string) (alertRule, error) {
	return splitRule(p, rulefmt.Rule{Alert: "X", Expr: expr}, streams)
}
