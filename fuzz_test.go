package gotemper

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRun_FuzzReflectedXSS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "you searched for: %s", r.URL.Query().Get(defaultFuzzParam))
	}))
	defer srv.Close()

	scenario := NewScenario("fuzz-check").
		Target(srv.URL).
		FuzzInputs([]Payload{{"script_tag", "<script>alert(1)</script>"}})

	report := Run(scenario)

	if len(report.Findings) != 1 || report.Findings[0].Severity != SeverityHigh {
		t.Fatalf("attendu 1 finding high (reflet XSS), obtenu %+v", report.Findings)
	}
}

func TestRun_FuzzServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get(defaultFuzzParam) == "-1" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	scenario := NewScenario("fuzz-check").
		Target(srv.URL).
		FuzzInputs([]Payload{{"negative_number", "-1"}})

	report := Run(scenario)

	if !report.HasCritical() {
		t.Fatalf("attendu un finding critique sur 500, obtenu %+v", report.Findings)
	}
}

func TestRun_FuzzErrorLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "oops: panic: index out of range [3] with length 2")
	}))
	defer srv.Close()

	scenario := NewScenario("fuzz-check").
		Target(srv.URL).
		FuzzInputs([]Payload{{"empty", ""}})

	report := Run(scenario)

	if len(report.Findings) != 1 || report.Findings[0].Severity != SeverityHigh {
		t.Fatalf("attendu 1 finding high (fuite d'erreur), obtenu %+v", report.Findings)
	}
}

func TestRun_FuzzClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "all good")
	}))
	defer srv.Close()

	scenario := NewScenario("fuzz-check").
		Target(srv.URL).
		FuzzInputs(CommonEdgeCases)

	report := Run(scenario)

	if len(report.Findings) != 0 {
		t.Fatalf("attendu 0 finding sur un service qui ignore les payloads, obtenu %+v", report.Findings)
	}
}

func TestRun_FuzzCustomParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "q=%s", r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	scenario := NewScenario("fuzz-check").
		Target(srv.URL).
		FuzzInputs([]Payload{{"script_tag", "<script>alert(1)</script>"}}).
		FuzzParam("q")

	report := Run(scenario)

	if len(report.Findings) != 1 {
		t.Fatalf("attendu 1 finding via le paramètre personnalisé, obtenu %+v", report.Findings)
	}
}
