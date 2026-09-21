package gotemper

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRun_RateLimitThrottles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// 1 requête initiale (header check) + 3 payloads de fuzz = 4 requêtes.
	// Avec 1 requête/50ms, les 3 dernières attendent chacune la fenêtre
	// suivante : on attend au moins ~3*50ms au total.
	scenario := NewScenario("rate-check").
		Target(srv.URL).
		FuzzInputs([]Payload{{"a", "x"}, {"b", "y"}, {"c", "z"}}).
		RateLimit(1, 50*time.Millisecond)

	start := time.Now()
	Run(scenario)
	elapsed := time.Since(start)

	if elapsed < 120*time.Millisecond {
		t.Fatalf("attendu au moins ~150ms avec un rate limit de 1/50ms sur 4 requêtes, obtenu %s", elapsed)
	}
}

func TestRun_RateLimitUnderQuotaIsFast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	scenario := NewScenario("rate-check").
		Target(srv.URL).
		FuzzInputs([]Payload{{"a", "x"}, {"b", "y"}, {"c", "z"}}).
		RateLimit(100, 50*time.Millisecond)

	start := time.Now()
	Run(scenario)
	elapsed := time.Since(start)

	if elapsed > 40*time.Millisecond {
		t.Fatalf("attendu une exécution quasi instantanée sous le quota, obtenu %s", elapsed)
	}
}

func TestRun_NoRateLimitIsFast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	scenario := NewScenario("rate-check").
		Target(srv.URL).
		FuzzInputs([]Payload{{"a", "x"}, {"b", "y"}, {"c", "z"}})

	start := time.Now()
	Run(scenario)
	elapsed := time.Since(start)

	if elapsed > 40*time.Millisecond {
		t.Fatalf("attendu une exécution quasi instantanée sans rate limit, obtenu %s", elapsed)
	}
}
