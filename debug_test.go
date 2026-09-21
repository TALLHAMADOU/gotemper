package gotemper

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRun_DebugEndpointExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OPENAI_API_KEY=sk-super-secret-value-here"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 not found"))
	}))
	defer srv.Close()

	report := Run(NewScenario("debug-check").Target(srv.URL).CheckDebugEndpoints())

	if len(report.Findings) != 1 {
		t.Fatalf("attendu 1 finding (.env exposé), obtenu %+v", report.Findings)
	}
	f := report.Findings[0]
	if f.Severity != SeverityCritical || !strings.Contains(f.Message, "/.env") {
		t.Fatalf("finding inattendu : %+v", f)
	}
}

func TestRun_DebugEndpointProtected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 not found"))
	}))
	defer srv.Close()

	report := Run(NewScenario("debug-check").Target(srv.URL).CheckDebugEndpoints())

	if len(report.Findings) != 1 || report.Findings[0].Severity != SeverityInfo {
		t.Fatalf("attendu 1 finding info (endpoint protégé), obtenu %+v", report.Findings)
	}
}

func TestRun_DebugEndpointsCleanServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 not found"))
	}))
	defer srv.Close()

	report := Run(NewScenario("debug-check").Target(srv.URL).CheckDebugEndpoints())

	if len(report.Findings) != 0 {
		t.Fatalf("attendu 0 finding sur un serveur sain, obtenu %+v", report.Findings)
	}
}

func TestRun_DebugEndpointsSPACatchAll(t *testing.T) {
	// Un serveur SPA qui répond 200 avec la même page pour toute route ne
	// doit déclencher aucun faux positif, car il répond pareil à la baseline.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>My SPA shell</body></html>"))
	}))
	defer srv.Close()

	report := Run(NewScenario("debug-check").Target(srv.URL).CheckDebugEndpoints())

	if len(report.Findings) != 0 {
		t.Fatalf("attendu 0 finding sur un catch-all SPA, obtenu %+v", report.Findings)
	}
}
