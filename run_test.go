package gotemper

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRun_MissingHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	scenario := NewScenario("api-check").
		Target(srv.URL).
		CheckHeaders(SecurityHeaders)

	report := Run(scenario)

	if len(report.Findings) != len(SecurityHeaders) {
		t.Fatalf("attendu %d findings (headers manquants), obtenu %d", len(SecurityHeaders), len(report.Findings))
	}
	for _, f := range report.Findings {
		if f.Severity != SeverityHigh {
			t.Errorf("severité attendue high, obtenu %s", f.Severity)
		}
	}
}

func TestRun_HeadersPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range SecurityHeaders {
			w.Header().Set(h, "1")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	scenario := NewScenario("api-check").
		Target(srv.URL).
		CheckHeaders(SecurityHeaders)

	report := Run(scenario)

	if len(report.Findings) != 0 {
		t.Fatalf("attendu 0 finding, obtenu %d : %+v", len(report.Findings), report.Findings)
	}
}

func TestRun_NoTarget(t *testing.T) {
	report := Run(NewScenario("no-target"))
	if !report.HasCritical() {
		t.Fatal("attendu un finding critique quand aucune target n'est définie")
	}
}
