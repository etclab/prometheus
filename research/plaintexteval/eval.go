package main

import (
	"context"
	"log/slog"
	"maps"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/prometheus/common/model"

	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
)

// evaluator runs the loaded rules on an interval: it queries Prometheus for
// each rule's aggregation subquery, applies the comparison locally, tracks the
// `for` duration, and posts firing alerts to Alertmanager.
type evaluator struct {
	rules  []alertRule
	api    v1.API
	sender *alertSender
	logger *slog.Logger

	promURL        string        // for the alerts' generatorURL.
	resolveTimeout time.Duration // EndsAt = now + resolveTimeout so Alertmanager auto-resolves.

	// active maps a (rule, series) key to the time the series first breached,
	// implementing the `for` pending->firing transition.
	active map[string]time.Time
}

func newEvaluator(rules []alertRule, api v1.API, sender *alertSender, promURL string, resolveTimeout time.Duration, logger *slog.Logger) *evaluator {
	return &evaluator{
		rules:          rules,
		api:            api,
		sender:         sender,
		logger:         logger,
		promURL:        promURL,
		resolveTimeout: resolveTimeout,
		active:         map[string]time.Time{},
	}
}

// evalOnce evaluates every rule at time now and posts the resulting alerts.
func (e *evaluator) evalOnce(ctx context.Context, now time.Time) {
	nextActive := map[string]time.Time{}
	var alerts []amAlert

	for _, r := range e.rules {
		result, warnings, err := e.api.Query(ctx, r.query, now)
		if err != nil {
			e.logger.Error("query failed", "alert", r.name, "query", r.query, "err", err)
			continue
		}
		for _, w := range warnings {
			e.logger.Warn("query warning", "alert", r.name, "warning", w)
		}
		vec, ok := result.(model.Vector)
		if !ok {
			e.logger.Warn("query did not return an instant vector", "alert", r.name, "type", result.Type().String())
			continue
		}

		firing := 0
		for _, s := range vec {
			value := float64(s.Value)
			if !r.fires(value) {
				continue
			}
			firing++
			key := r.name + "\x00" + s.Metric.String()
			activeAt, ok := e.active[key]
			if !ok {
				activeAt = now
			}
			nextActive[key] = activeAt
			if now.Sub(activeAt) < r.forDur {
				continue // still pending: within the `for` window.
			}
			alert := e.buildAlert(r, s.Metric, value, activeAt, now)
			e.logger.Info("ALERT firing",
				"alert", r.name, "value", value,
				"labels", alert.Labels, "annotations", alert.Annotations)
			alerts = append(alerts, alert)
		}
		e.logger.Info("evaluated rule", "alert", r.name, "series", len(vec), "firing", firing)
	}

	e.active = nextActive

	// Delivery is optional: with no Alertmanager configured the firing alerts
	// above are simply logged. When a sender is set, also post them.
	if e.sender == nil || len(alerts) == 0 {
		return
	}
	if err := e.sender.send(ctx, alerts); err != nil {
		e.logger.Error("posting alerts to alertmanager failed", "count", len(alerts), "err", err)
		return
	}
	e.logger.Info("posted alerts to alertmanager", "count", len(alerts))
}

// buildAlert assembles the Alertmanager payload for one firing series: series
// labels, overlaid with the rule's own labels and alertname, plus its rendered
// annotations.
func (e *evaluator) buildAlert(r alertRule, metric model.Metric, value float64, activeAt, now time.Time) amAlert {
	lbls := map[string]string{}
	for name, val := range metric {
		if name == model.MetricNameLabel {
			continue // aggregations drop __name__; don't resurrect it as a label.
		}
		lbls[string(name)] = string(val)
	}
	maps.Copy(lbls, r.labels)
	lbls["alertname"] = r.name

	anns := make(map[string]string, len(r.annotations))
	for k, v := range r.annotations {
		anns[k] = renderTemplate(v, value, lbls)
	}

	return amAlert{
		Labels:       lbls,
		Annotations:  anns,
		StartsAt:     activeAt,
		EndsAt:       now.Add(e.resolveTimeout),
		GeneratorURL: e.promURL + "/graph?g0.expr=" + url.QueryEscape(r.query),
	}
}

var (
	valueTmplRe = regexp.MustCompile(`{{\s*\$value\s*}}`)
	labelTmplRe = regexp.MustCompile(`{{\s*\$labels\.([a-zA-Z_][a-zA-Z0-9_]*)\s*}}`)
)

// renderTemplate is a deliberately tiny subset of Prometheus's text/template
// annotation engine: it expands `{{ $value }}` and `{{ $labels.<name> }}`,
// which is enough for the demo rule. It is not a full template implementation.
func renderTemplate(s string, value float64, lbls map[string]string) string {
	s = valueTmplRe.ReplaceAllString(s, strconv.FormatFloat(value, 'f', -1, 64))
	return labelTmplRe.ReplaceAllStringFunc(s, func(m string) string {
		name := labelTmplRe.FindStringSubmatch(m)[1]
		return lbls[name]
	})
}
