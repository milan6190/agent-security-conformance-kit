package proxy

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics are exposed in Prometheus text format at /metrics.
type Metrics struct {
	Requests, Denied, AuthFailures, RateLimited, Redactions, UpstreamErrors atomic.Int64
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	for _, c := range []struct {
		name string
		v    *atomic.Int64
	}{
		{"mcpguard_requests_total", &m.Requests},
		{"mcpguard_denied_total", &m.Denied},
		{"mcpguard_auth_failures_total", &m.AuthFailures},
		{"mcpguard_rate_limited_total", &m.RateLimited},
		{"mcpguard_redactions_total", &m.Redactions},
		{"mcpguard_upstream_errors_total", &m.UpstreamErrors},
	} {
		fmt.Fprintf(w, "# TYPE %s counter\n%s %d\n", c.name, c.name, c.v.Load())
	}
}

// limiter is a per-subject token bucket. A rate of 0 disables limiting.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute int) *limiter {
	return &limiter{
		rate:    float64(perMinute) / 60,
		burst:   float64(perMinute),
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

func (l *limiter) allow(key string) bool {
	if l.burst == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Healthz is a trivial liveness handler.
func Healthz(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") }
