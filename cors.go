package gotemper

import (
	"fmt"
	"net/http"
	"strings"
)

// corsProbeOrigin is sent as the Origin header to see whether the target
// reflects an arbitrary, untrusted origin back in its CORS response.
const corsProbeOrigin = "https://gotemper-cors-probe.invalid"

// checkCORS probes the target's CORS policy and flags common misconfigurations:
// a wildcard origin combined with credentials, or blind reflection of any
// Origin header without validation.
func checkCORS(client *http.Client, targetURL string) []Finding {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", corsProbeOrigin)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")

	var findings []Finding
	switch {
	case allowOrigin == corsProbeOrigin:
		msg := fmt.Sprintf("CORS reflète n'importe quelle origine sans validation (Origin %q acceptée)", corsProbeOrigin)
		if allowCreds {
			msg += " avec Access-Control-Allow-Credentials=true — une origine malveillante peut lire des réponses authentifiées"
		}
		findings = append(findings, Finding{Severity: SeverityHigh, Message: msg})

	case allowOrigin == "*" && allowCreds:
		findings = append(findings, Finding{
			Severity: SeverityCritical,
			Message:  "CORS mal configuré : Access-Control-Allow-Origin=* combiné à Access-Control-Allow-Credentials=true",
		})

	case allowOrigin == "*":
		findings = append(findings, Finding{
			Severity: SeverityInfo,
			Message:  "CORS ouvert à toutes les origines (Access-Control-Allow-Origin=*) — à confirmer que c'est voulu pour une API publique",
		})
	}

	return findings
}
