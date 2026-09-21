package gotemper

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// DebugEndpoint is a well-known path that should never be reachable on a
// production service.
type DebugEndpoint struct {
	Path     string
	Severity Severity
	Note     string
}

// DebugEndpoints is a curated list of debug, admin, and secret-adjacent
// paths commonly left exposed by misconfigured deployments.
var DebugEndpoints = []DebugEndpoint{
	{"/.env", SeverityCritical, "fichier d'environnement potentiellement exposé (secrets, clés API)"},
	{"/.git/config", SeverityCritical, "dépôt Git exposé (historique de code, éventuels secrets)"},
	{"/.git/HEAD", SeverityCritical, "dépôt Git exposé"},
	{"/.aws/credentials", SeverityCritical, "identifiants AWS potentiellement exposés"},
	{"/wp-config.php.bak", SeverityCritical, "sauvegarde de configuration exposée"},
	{"/actuator/env", SeverityHigh, "Spring Boot Actuator env exposé (variables d'environnement)"},
	{"/actuator", SeverityHigh, "Spring Boot Actuator exposé"},
	{"/debug/pprof/", SeverityHigh, "profiler Go (net/http/pprof) exposé publiquement"},
	{"/debug/vars", SeverityHigh, "expvar Go exposé (métriques internes)"},
	{"/phpinfo.php", SeverityHigh, "phpinfo() exposé (configuration serveur détaillée)"},
	{"/server-status", SeverityHigh, "mod_status Apache exposé"},
	{"/_profiler", SeverityHigh, "profiler Symfony exposé en production"},
	{"/swagger.json", SeverityInfo, "documentation API exposée publiquement"},
	{"/swagger-ui.html", SeverityInfo, "interface Swagger exposée publiquement"},
	{"/graphql", SeverityInfo, "endpoint GraphQL détecté — vérifier que l'introspection est désactivée en prod"},
	{"/metrics", SeverityInfo, "endpoint Prometheus /metrics exposé — vérifier l'absence de données sensibles"},
}

// checkDebugEndpoints probes each DebugEndpoint against the target's host
// and flags the ones that respond differently from a random, known-missing
// path — which is used as a baseline to avoid false positives on servers
// that return 200 (or a custom error page) for everything.
func checkDebugEndpoints(client *http.Client, targetURL string) []Finding {
	base, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	baseStatus, baseLen, err := probe(client, base, "/gotemper-probe-"+randomSuffix())
	if err != nil {
		return nil
	}

	var findings []Finding
	for _, ep := range DebugEndpoints {
		status, length, err := probe(client, base, ep.Path)
		if err != nil {
			continue
		}

		switch {
		case status >= 200 && status < 300 && (status != baseStatus || length != baseLen):
			findings = append(findings, Finding{
				Severity: ep.Severity,
				Message:  fmt.Sprintf("endpoint exposé %s (%d) — %s", ep.Path, status, ep.Note),
			})
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			findings = append(findings, Finding{
				Severity: SeverityInfo,
				Message:  fmt.Sprintf("endpoint %s trouvé mais protégé (%d) — %s", ep.Path, status, ep.Note),
			})
		}
	}

	return findings
}

func probe(client *http.Client, base *url.URL, path string) (status int, bodyLen int, err error) {
	u := *base
	u.Path = path
	u.RawQuery = ""

	resp, err := client.Get(u.String())
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, len(body), nil
}

func randomSuffix() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "fallback"
	}
	return hex.EncodeToString(buf)
}
