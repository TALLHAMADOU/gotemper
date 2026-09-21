package gotemper

import (
	"fmt"
	"os"
)

// Severity indicates how serious a finding is.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityInfo     Severity = "info"
)

// Finding is one issue surfaced while running a Scenario.
type Finding struct {
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// Report collects the findings produced by Run.
type Report struct {
	Scenario string    `json:"scenario"`
	Findings []Finding `json:"findings"`
}

// HasCritical reports whether any finding is critical.
func (r *Report) HasCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// FailBuildIfCritical exits the process with a non-zero status when the
// report contains a critical finding, for use in CI pipelines.
func (r *Report) FailBuildIfCritical() {
	if !r.HasCritical() {
		return
	}
	fmt.Fprintf(os.Stderr, "gotemper: %s a des findings critiques :\n", r.Scenario)
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			fmt.Fprintf(os.Stderr, "  - [%s] %s\n", f.Severity, f.Message)
		}
	}
	os.Exit(1)
}
