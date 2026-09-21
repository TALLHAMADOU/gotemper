// Package gotemper provides a scriptable scenario engine for testing the
// resilience and security posture of HTTP services you are authorized to test.
package gotemper

import "time"

// SecurityHeaders lists the response headers CheckHeaders looks for by default.
var SecurityHeaders = []string{
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Strict-Transport-Security",
}

// Scenario describes a single resilience/security scan against one target,
// built with a fluent API (see NewScenario).
type Scenario struct {
	name            string
	target          string
	requiredHeaders []string
	fuzzPayloads    []Payload
	fuzzParam       string
	rateLimitN      int
	ratePeriod      time.Duration
}

// NewScenario starts a new named scenario.
func NewScenario(name string) *Scenario {
	return &Scenario{name: name}
}

// Target sets the base URL the scenario runs against.
func (s *Scenario) Target(url string) *Scenario {
	s.target = url
	return s
}

// CheckHeaders records which response headers must be present on the target.
func (s *Scenario) CheckHeaders(headers []string) *Scenario {
	s.requiredHeaders = headers
	return s
}

// FuzzInputs records which edge-case payloads to send as a query parameter
// during Run, to check how the target handles malformed input.
func (s *Scenario) FuzzInputs(payloads []Payload) *Scenario {
	s.fuzzPayloads = payloads
	return s
}

// FuzzParam sets the query parameter name payloads are injected into.
// Defaults to "input" when not called.
func (s *Scenario) FuzzParam(name string) *Scenario {
	s.fuzzParam = name
	return s
}

// RateLimit caps outgoing requests to n per period during the scenario run.
func (s *Scenario) RateLimit(n int, period time.Duration) *Scenario {
	s.rateLimitN = n
	s.ratePeriod = period
	return s
}
