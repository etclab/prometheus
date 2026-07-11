package main

import (
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/prometheus/prometheus/promql/parser"
)

func TestSplitRule_QueryOpScalar(t *testing.T) {
	p := parser.NewParser(parser.Options{})
	r := rulefmt.Rule{
		Alert:       "MyappOpsDecreasing",
		Expr:        "delta(myapp_processed_ops[1m]) < 0",
		For:         model.Duration(2 * time.Minute),
		Labels:      map[string]string{"severity": "warning"},
		Annotations: map[string]string{"summary": "ops decreasing"},
	}

	ar, err := splitRule(p, r)
	require.NoError(t, err)
	require.True(t, ar.hasComparison)
	require.Equal(t, "delta(myapp_processed_ops[1m])", ar.query)
	require.Equal(t, parser.ItemType(parser.LSS), ar.op)
	require.Equal(t, 0.0, ar.threshold)
	require.False(t, ar.thresholdOnLeft)
	require.Equal(t, 2*time.Minute, ar.forDur)

	// The comparison must gate firing in the original operand order.
	require.True(t, ar.fires(-6))
	require.False(t, ar.fires(3))
}

func TestSplitRule_ScalarOpQuery(t *testing.T) {
	p := parser.NewParser(parser.Options{})
	r := rulefmt.Rule{Alert: "HighRate", Expr: "100 < sum(rate(http_requests_total[5m]))"}

	ar, err := splitRule(p, r)
	require.NoError(t, err)
	require.Equal(t, "sum(rate(http_requests_total[5m]))", ar.query)
	require.Equal(t, parser.ItemType(parser.LSS), ar.op)
	require.Equal(t, 100.0, ar.threshold)
	require.True(t, ar.thresholdOnLeft)

	// `100 < value` fires when value exceeds 100.
	require.True(t, ar.fires(150))
	require.False(t, ar.fires(50))
}

func TestSplitRule_BareVectorFiresAlways(t *testing.T) {
	p := parser.NewParser(parser.Options{})
	r := rulefmt.Rule{Alert: "AnyResult", Expr: "up == 0"}

	ar, err := splitRule(p, r)
	require.NoError(t, err)
	// `up == 0` is a comparison, so it must be split, not treated as bare.
	require.True(t, ar.hasComparison)
	require.Equal(t, "up", ar.query)

	// A genuinely bare vector fires on every series it returns.
	bare, err := splitRule(p, rulefmt.Rule{Alert: "Bare", Expr: "vector(1)"})
	require.NoError(t, err)
	require.False(t, bare.hasComparison)
	require.True(t, bare.fires(0))
}

func TestSplitRule_VectorVectorUnsupported(t *testing.T) {
	p := parser.NewParser(parser.Options{})
	_, err := splitRule(p, rulefmt.Rule{Alert: "Bad", Expr: "foo > bar"})
	require.Error(t, err)
}
