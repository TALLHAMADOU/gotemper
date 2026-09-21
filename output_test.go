package gotemper

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleReport() *Report {
	return &Report{
		Scenario: "api-check",
		Findings: []Finding{
			{Severity: SeverityCritical, Message: "endpoint exposé /.env (200)"},
			{Severity: SeverityHigh, Message: `payload "script_tag" réfléchi : <script>alert(1)</script>`},
			{Severity: SeverityInfo, Message: "CORS ouvert à toutes les origines"},
		},
	}
}

func TestReport_Summary(t *testing.T) {
	s := sampleReport().Summary()
	if s.Total != 3 || s.Critical != 1 || s.High != 1 || s.Info != 1 {
		t.Fatalf("summary inattendue : %+v", s)
	}
}

func TestReport_JSON(t *testing.T) {
	data, err := sampleReport().JSON()
	if err != nil {
		t.Fatalf("JSON() a échoué : %v", err)
	}

	var decoded struct {
		Scenario string  `json:"scenario"`
		Summary  Summary `json:"summary"`
		Findings []struct {
			Severity string `json:"severity"`
			Message  string `json:"message"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON invalide : %v\n%s", err, data)
	}

	if decoded.Scenario != "api-check" {
		t.Errorf("scenario attendu 'api-check', obtenu %q", decoded.Scenario)
	}
	if decoded.Summary.Total != 3 || decoded.Summary.Critical != 1 {
		t.Errorf("summary JSON inattendue : %+v", decoded.Summary)
	}
	if len(decoded.Findings) != 3 {
		t.Fatalf("attendu 3 findings, obtenu %d", len(decoded.Findings))
	}
	if decoded.Findings[0].Severity != "critical" {
		t.Errorf("severité JSON attendue 'critical', obtenu %q", decoded.Findings[0].Severity)
	}
}

func TestReport_HTML_EscapesPayloads(t *testing.T) {
	html, err := sampleReport().HTML()
	if err != nil {
		t.Fatalf("HTML() a échoué : %v", err)
	}

	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatal("le payload <script> ne doit jamais apparaître non échappé dans le rapport HTML")
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("le payload devrait apparaître échappé dans le rapport HTML")
	}
	if !strings.Contains(html, "api-check") {
		t.Fatal("le nom du scénario devrait apparaître dans le rapport HTML")
	}
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Fatal("le rapport devrait être une page HTML autonome")
	}
}

func TestReport_HTML_NoFindings(t *testing.T) {
	html, err := (&Report{Scenario: "clean-run"}).HTML()
	if err != nil {
		t.Fatalf("HTML() a échoué : %v", err)
	}
	if !strings.Contains(html, "Aucun finding") {
		t.Fatal("un rapport sans findings devrait l'indiquer clairement")
	}
}
