// Package metrics registers all Prometheus counters and histograms.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	WAFActionTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "autoblock_waf_actions_total",
			Help: "Total WAF block/unblock actions performed.",
		},
		[]string{"tenant", "provider", "action"},
	)

	WAFActionErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "autoblock_waf_action_errors_total",
			Help: "Total failed WAF action attempts.",
		},
		[]string{"tenant", "provider"},
	)

	WAFActionLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "autoblock_waf_action_latency_seconds",
			Help:    "Latency of WAF block push operations.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"tenant", "provider"},
	)

	BlacklistTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "autoblock_blacklist_total",
			Help: "Total IPs added to the blacklist.",
		},
		[]string{"tenant", "source"}, // source: engine | api
	)

	EventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "autoblock_events_processed_total",
			Help: "Total penalty state change events processed by the engine.",
		},
		[]string{"tenant", "state"},
	)

	APIRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "autoblock_api_requests_total",
			Help: "Total management API requests.",
		},
		[]string{"method", "path", "status"},
	)
)

var registered bool

// Register registers all metrics exactly once.
func Register() {
	if registered {
		return
	}
	registered = true
	prometheus.MustRegister(
		WAFActionTotal,
		WAFActionErrors,
		WAFActionLatency,
		BlacklistTotal,
		EventsProcessed,
		APIRequestsTotal,
	)
}

// Handler returns the Prometheus HTTP handler.
func Handler() http.Handler {
	return promhttp.Handler()
}
