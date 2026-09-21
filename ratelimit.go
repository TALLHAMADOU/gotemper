package gotemper

import (
	"net/http"
	"sync"
	"time"
)

// rateLimiter is a simple fixed-window limiter: at most max calls to wait
// are let through per period; once the window's quota is used up, wait
// blocks until the next window starts.
type rateLimiter struct {
	mu        sync.Mutex
	max       int
	period    time.Duration
	count     int
	windowEnd time.Time
}

// newRateLimiter returns nil when n or period is non-positive, meaning
// "no limiting" — every call site treats a nil *rateLimiter as a no-op.
func newRateLimiter(n int, period time.Duration) *rateLimiter {
	if n <= 0 || period <= 0 {
		return nil
	}
	return &rateLimiter{max: n, period: period}
}

func (r *rateLimiter) wait() {
	if r == nil {
		return
	}

	r.mu.Lock()
	now := time.Now()
	if now.After(r.windowEnd) {
		r.windowEnd = now.Add(r.period)
		r.count = 0
	}

	if r.count >= r.max {
		sleepFor := time.Until(r.windowEnd)
		r.mu.Unlock()
		if sleepFor > 0 {
			time.Sleep(sleepFor)
		}
		r.mu.Lock()
		r.windowEnd = time.Now().Add(r.period)
		r.count = 0
	}

	r.count++
	r.mu.Unlock()
}

// rateLimitedTransport throttles every outgoing request through limiter
// before delegating to base, so a Scenario's RateLimit applies uniformly
// to the header check, fuzzing, CORS probe, and debug endpoint scan alike.
type rateLimitedTransport struct {
	limiter *rateLimiter
	base    http.RoundTripper
}

func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.limiter.wait()
	return t.base.RoundTrip(req)
}

// newHTTPClient builds the client Run uses, wiring in rate limiting when
// the scenario configured one.
func newHTTPClient(s *Scenario) *http.Client {
	client := &http.Client{Timeout: 5 * time.Second}

	if limiter := newRateLimiter(s.rateLimitN, s.ratePeriod); limiter != nil {
		client.Transport = &rateLimitedTransport{limiter: limiter, base: http.DefaultTransport}
	}

	return client
}
