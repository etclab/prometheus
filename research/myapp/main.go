package main

import (
	"math/rand"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	opsProcessed prometheus.Gauge
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		// A gauge (not a counter): the value can go both up and down, so we drop
		// the counter-only "_total" suffix from the metric name.
		opsProcessed: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "myapp_processed_ops",
			Help: "The current number of processed events; randomly walks up and down",
		}),
	}
	return m
}

func recordMetrics(m *metrics) {
	go func() {
		for {
			// Randomly walk the gauge, biased downward so decreases are common
			// and easy to alert on (90% chance to decrease, 10% to increase).
			if rand.Intn(10) < 9 {
				m.opsProcessed.Dec()
			} else {
				m.opsProcessed.Inc()
			}
			time.Sleep(1 * time.Second)
		}
	}()
}

func main() {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)
	recordMetrics(m)

	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	http.ListenAndServe(":2112", nil)
}
