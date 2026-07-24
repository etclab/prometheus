package main

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/labels"
)

// windowFetcher selects one rule's window of raw ciphertext from Prometheus and
// returns the value series together with its timeID companion. It is the seam
// between the two label planes: hermesReader turns the rule's matchers into
// encrypted searches over opaque series ids, while plainFetcher sends an ordinary
// PromQL selector naming the metric and its labels in the clear. Both return the
// same TimeCrypt ciphertext; only the selection path differs.
//
// The returned matrices are freshly decoded per call; the caller owns them.
type windowFetcher interface {
	fetchWindow(ctx context.Context, r alertRule, t time.Time) (values, timeids model.Matrix, err error)
}

// evaluator runs the split rules on an interval. For each rule it fetches the
// full range of raw ciphertext from Prometheus (which only ever stores and
// serves ciphertext), aggregates it itself with keys Prometheus never holds,
// applies the comparison, tracks the `for` duration, and logs firing alerts.
// Delivery to Alertmanager is intentionally out of scope: firing alerts are only
// logged (matching research/plaintexteval's log-only default).
type evaluator struct {
	rules   []alertRule
	fetcher windowFetcher
	logger  *slog.Logger

	// active maps a (rule, series) key to the time the series first breached,
	// implementing the `for` pending->firing transition.
	active map[string]time.Time
}

func newEvaluator(rules []alertRule, f windowFetcher, logger *slog.Logger) *evaluator {
	return &evaluator{
		rules:   rules,
		fetcher: f,
		logger:  logger,
		active:  map[string]time.Time{},
	}
}

// firedAlert is the resolved labels/annotations of one firing series, built for
// logging. It is the payload an Alertmanager sender would post, kept minimal
// because this evaluator only logs.
type firedAlert struct {
	Labels      map[string]string
	Annotations map[string]string
}

// evalOnce evaluates every rule at time now.
func (e *evaluator) evalOnce(ctx context.Context, now time.Time) {
	nextActive := map[string]time.Time{}

	for _, r := range e.rules {
		if err := e.evalRule(ctx, r, now, nextActive); err != nil {
			e.logger.Error("evaluating rule failed", "alert", r.name, "fn", r.fn, "err", err)
		}
	}

	e.active = nextActive
}

// atp: review the vector and matrix data types in promQL?

// evalRule fetches the rule's full range of raw ciphertext once, aggregates each
// series locally, and applies the threshold. Prometheus only ever selected and
// windowed the ciphertext (value + timeID series); every aggregation happens here
// at the key holder.
func (e *evaluator) evalRule(ctx context.Context, r alertRule, now time.Time, nextActive map[string]time.Time) error {
	series, err := e.fetchPaired(ctx, r, now)
	if err != nil {
		return err
	}

	firing := 0
	for _, sp := range series {
		agg, ok, err := e.aggregate(r, sp.points)
		if err != nil {
			return err
		}
		if !ok {
			continue // too few points to form an aggregate.
		}
		if e.fireIfBreached(r, sp.metric, agg, now, nextActive) {
			firing++
		}
	}
	e.logger.Info("evaluated rule", "alert", r.name, "fn", r.fn, "series", len(series), "firing", firing)
	return nil
}

// aggregate reduces one series' windowed points to the rule's scalar, using the
// local strategy for the rule's family. The bool is false when the window has too
// few points to form an aggregate (the series is then skipped).
func (e *evaluator) aggregate(r alertRule, points []point) (float64, bool, error) {
	switch r.family {
	case familyEndpoint:
		// delta/increase/rate: decrypt the two window endpoints and subtract.
		// rate additionally normalises by the elapsed seconds.
		if len(points) < 2 {
			return 0, false, nil // need both endpoints to form a delta.
		}
		first, last := points[0], points[len(points)-1]
		// Decrypt the two window endpoints (point decryption: timeID range
		// [i,i]). The server only ever held ciphertext.
		mFirst, err := r.stream.decryptPoint(first.residue, first.timeID)
		if err != nil {
			return 0, false, err
		}
		mLast, err := r.stream.decryptPoint(last.residue, last.timeID)
		if err != nil {
			return 0, false, err
		}
		delta := mLast - mFirst
		if r.fn == "rate" {
			secs := float64(last.t-first.t) / 1000
			if secs <= 0 {
				return 0, false, nil
			}
			return delta / secs, true, nil
		}
		return delta, true, nil

	case familySummable:
		// sum_over_time/avg_over_time: add the ciphertext residues locally and
		// decrypt the sum with only the two boundary keys (HEAC telescoping),
		// falling back inside decryptWindowSum to per-point decryption on a
		// non-contiguous window (scrape gap). avg divides by the sample count.
		if len(points) == 0 {
			return 0, false, nil
		}
		total, err := r.stream.decryptWindowSum(points)
		if err != nil {
			return 0, false, err
		}
		if r.fn == "avg_over_time" {
			return total / float64(len(points)), true, nil
		}
		return total, true, nil

	default:
		return 0, false, fmt.Errorf("unknown rule family %d", r.family)
	}
}

// fireIfBreached applies the threshold to one decrypted series value, advances
// the `for` state, and logs the alert once it has breached for long enough. It
// returns whether the series is currently breaching (for the firing count).
func (e *evaluator) fireIfBreached(r alertRule, metric labels.Labels, value float64, now time.Time, nextActive map[string]time.Time) bool {
	if !r.fires(value) {
		return false
	}
	key := r.name + "\x00" + metric.String()
	activeAt, ok := e.active[key]
	if !ok {
		activeAt = now
	}
	nextActive[key] = activeAt
	if now.Sub(activeAt) < r.forDur {
		return true // still pending: within the `for` window.
	}
	alert := e.buildAlert(r, metric, value)
	e.logger.Info("ALERT firing",
		"alert", r.name, "value", value,
		"labels", alert.Labels, "annotations", alert.Annotations)
	return true
}

// buildAlert assembles the alert payload for one firing series: series labels
// (with __name__ dropped, as the range functions do), overlaid with the rule's
// own labels and alertname, plus its rendered annotations.
func (e *evaluator) buildAlert(r alertRule, metric labels.Labels, value float64) firedAlert {
	lbls := map[string]string{}
	metric.Range(func(l labels.Label) {
		if l.Name == model.MetricNameLabel {
			return // aggregations drop __name__; don't resurrect it as a label.
		}
		lbls[l.Name] = l.Value
	})
	maps.Copy(lbls, r.labels)
	lbls["alertname"] = r.name

	// atp: how are annotations different from labels?
	anns := make(map[string]string, len(r.annotations))
	for k, v := range r.annotations {
		anns[k] = renderTemplate(v, value, lbls)
	}
	return firedAlert{Labels: lbls, Annotations: anns}
}

// seriesPoints is one series' paired value+timeID samples, sorted by timestamp.
type seriesPoints struct {
	metric labels.Labels
	points []point
}

// atp: what is a matrix data type?

// fetchPaired asks Prometheus for the raw ciphertext value series and its timeID
// companion over the window, and pairs them per series. This is the selection +
// windowing that Prometheus can always do over encrypted data.
func (e *evaluator) fetchPaired(ctx context.Context, r alertRule, now time.Time) (map[uint64]seriesPoints, error) {
	vm, tm, err := e.fetcher.fetchWindow(ctx, r, now)
	if err != nil {
		return nil, err
	}
	values := matrixToSeries(vm)
	timeids := matrixToSeries(tm)

	out := make(map[uint64]seriesPoints, len(values))
	for key, vs := range values {
		ts, ok := timeids[key]
		if !ok {
			continue // no timeID companion: cannot pick keys, skip.
		}
		pts := pair(vs, ts)
		sort.Slice(pts, func(i, j int) bool { return pts[i].t < pts[j].t })
		out[key] = seriesPoints{metric: vs.metric, points: pts}
	}
	return out, nil
}

// atp: I can't read regex and I cannot lie
var (
	valueTmplRe = regexp.MustCompile(`{{\s*\$value\s*}}`)
	labelTmplRe = regexp.MustCompile(`{{\s*\$labels\.([a-zA-Z_][a-zA-Z0-9_]*)\s*}}`)
)

// atp: example of what the below function is doing
// renderTemplate("{{ $labels.instance }} is at {{ $value }}", 0.87, map[string]string{"instance": "web-1"}) yields "web-1 is at 0.87".

// renderTemplate is a deliberately tiny subset of Prometheus's text/template
// annotation engine: it expands `{{ $value }}` and `{{ $labels.<name> }}`, which
// is enough for the demo rule. It mirrors research/plaintexteval's renderer.
func renderTemplate(s string, value float64, lbls map[string]string) string {
	s = valueTmplRe.ReplaceAllString(s, strconv.FormatFloat(value, 'f', -1, 64))
	return labelTmplRe.ReplaceAllStringFunc(s, func(m string) string {
		name := labelTmplRe.FindStringSubmatch(m)[1]
		return lbls[name]
	})
}
