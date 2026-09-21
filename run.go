package gotemper

import (
	"fmt"
	"net/http"
	"time"
)

// Run executes the scenario against its target and returns a Report.
//
// Rate-limited request bursts land in a later iteration.
func Run(s *Scenario) *Report {
	report := &Report{Scenario: s.name}

	if s.target == "" {
		report.Findings = append(report.Findings, Finding{
			Severity: SeverityCritical,
			Message:  "aucune target définie (utilisez Target())",
		})
		return report
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(s.target)
	if err != nil {
		report.Findings = append(report.Findings, Finding{
			Severity: SeverityCritical,
			Message:  fmt.Sprintf("requête vers %s impossible : %v", s.target, err),
		})
		return report
	}
	defer resp.Body.Close()

	for _, header := range s.requiredHeaders {
		if resp.Header.Get(header) == "" {
			report.Findings = append(report.Findings, Finding{
				Severity: SeverityHigh,
				Message:  fmt.Sprintf("header de sécurité manquant : %s", header),
			})
		}
	}

	if len(s.fuzzPayloads) > 0 {
		param := s.fuzzParam
		if param == "" {
			param = defaultFuzzParam
		}
		for _, payload := range s.fuzzPayloads {
			report.Findings = append(report.Findings, fuzzOne(client, s.target, param, payload)...)
		}
	}

	if s.corsCheck {
		report.Findings = append(report.Findings, checkCORS(client, s.target)...)
	}

	if s.debugCheck {
		report.Findings = append(report.Findings, checkDebugEndpoints(client, s.target)...)
	}

	return report
}
