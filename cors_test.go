package gotemper

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRun_CORSReflectsAnyOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	report := Run(NewScenario("cors-check").Target(srv.URL).CheckCORS())

	if len(report.Findings) != 1 || report.Findings[0].Severity != SeverityHigh {
		t.Fatalf("attendu 1 finding high (reflet d'origine), obtenu %+v", report.Findings)
	}
}

func TestRun_CORSReflectsWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	report := Run(NewScenario("cors-check").Target(srv.URL).CheckCORS())

	if len(report.Findings) != 1 || report.Findings[0].Severity != SeverityHigh {
		t.Fatalf("attendu 1 finding high mentionnant les credentials, obtenu %+v", report.Findings)
	}
}

func TestRun_CORSWildcardWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	report := Run(NewScenario("cors-check").Target(srv.URL).CheckCORS())

	if !report.HasCritical() {
		t.Fatalf("attendu un finding critique (wildcard + credentials), obtenu %+v", report.Findings)
	}
}

func TestRun_CORSWildcardOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	report := Run(NewScenario("cors-check").Target(srv.URL).CheckCORS())

	if len(report.Findings) != 1 || report.Findings[0].Severity != SeverityInfo {
		t.Fatalf("attendu 1 finding info (wildcard sans credentials), obtenu %+v", report.Findings)
	}
}

func TestRun_CORSValidatedOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	report := Run(NewScenario("cors-check").Target(srv.URL).CheckCORS())

	if len(report.Findings) != 0 {
		t.Fatalf("attendu 0 finding pour une origine validée, obtenu %+v", report.Findings)
	}
}

func TestRun_CORSNotConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	report := Run(NewScenario("cors-check").Target(srv.URL).CheckCORS())

	if len(report.Findings) != 0 {
		t.Fatalf("attendu 0 finding en l'absence de headers CORS, obtenu %+v", report.Findings)
	}
}
