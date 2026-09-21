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

// severityRank orders severities from least to most serious, so a threshold
// check can ask "at or above" rather than matching one exact value.
var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityHigh:     1,
	SeverityCritical: 2,
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

// findingsAtOrAbove returns the findings whose severity is at least as
// serious as threshold. An unknown threshold matches nothing.
func (r *Report) findingsAtOrAbove(threshold Severity) []Finding {
	minRank, ok := severityRank[threshold]
	if !ok {
		return nil
	}
	var matches []Finding
	for _, f := range r.Findings {
		if severityRank[f.Severity] >= minRank {
			matches = append(matches, f)
		}
	}
	return matches
}

// FailBuildIfSeverity exits the process with a non-zero status when the
// report contains a finding at or above the given severity threshold — the
// hook used to make a CI pipeline fail on a security regression.
func (r *Report) FailBuildIfSeverity(threshold Severity) {
	matches := r.findingsAtOrAbove(threshold)
	if len(matches) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "gotemper: %s a des findings de sévérité %q ou pire :\n", r.Scenario, threshold)
	for _, f := range matches {
		fmt.Fprintf(os.Stderr, "  - [%s] %s\n", f.Severity, f.Message)
	}
	os.Exit(1)
}

// FailBuildIfCritical exits the process with a non-zero status when the
// report contains a critical finding, for use in CI pipelines.
func (r *Report) FailBuildIfCritical() {
	r.FailBuildIfSeverity(SeverityCritical)
}
