package gotemper

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Payload is a single edge-case value sent during fuzzing.
type Payload struct {
	Name  string
	Value string
}

// CommonEdgeCases is a curated set of values known to expose fragile input
// handling: empty/oversized strings, control characters, path traversal,
// and markup/SQL-shaped strings. They're used to check whether the target
// reflects input unescaped or leaks internal errors — not to exploit it.
var CommonEdgeCases = []Payload{
	{"empty", ""},
	{"very_long", strings.Repeat("A", 10000)},
	{"null_byte", "\x00"},
	{"sql_quote", "' OR '1'='1"},
	{"script_tag", "<script>alert(1)</script>"},
	{"path_traversal", "../../../../etc/passwd"},
	{"format_string", "%s%s%s%n"},
	{"negative_number", "-1"},
	{"unicode_rtl_override", "‮txt.exe"},
}

// defaultFuzzParam is used when Scenario.FuzzParam was never called.
const defaultFuzzParam = "input"

// errorSignatures are substrings that indicate a leaked stack trace or
// internal error message rather than a handled, user-facing response.
var errorSignatures = []string{
	"Traceback (most recent call last)",
	"Exception in thread",
	"at java.",
	"System.NullReferenceException",
	"Fatal error:",
	"You have an error in your SQL syntax",
	"ORA-01756",
	"panic:",
	"goroutine ",
}

// fuzzOne sends one payload as the given query parameter and inspects the
// response for crashes, reflected markup, and leaked error details.
func fuzzOne(client *http.Client, targetURL, param string, p Payload) []Finding {
	var findings []Finding

	u, err := url.Parse(targetURL)
	if err != nil {
		return findings
	}
	q := u.Query()
	q.Set(param, p.Value)
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		findings = append(findings, Finding{
			Severity: SeverityCritical,
			Message:  fmt.Sprintf("payload %q (%s=...) fait échouer la requête : %v", p.Name, param, err),
		})
		return findings
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	text := string(body)

	if resp.StatusCode >= 500 {
		findings = append(findings, Finding{
			Severity: SeverityCritical,
			Message:  fmt.Sprintf("payload %q (%s=...) déclenche une erreur serveur %d", p.Name, param, resp.StatusCode),
		})
	}

	if p.Value != "" && strings.ContainsAny(p.Value, "<>") && strings.Contains(text, p.Value) {
		findings = append(findings, Finding{
			Severity: SeverityHigh,
			Message:  fmt.Sprintf("payload %q (%s=...) réfléchi tel quel dans la réponse — XSS potentiel", p.Name, param),
		})
	}

	for _, sig := range errorSignatures {
		if strings.Contains(text, sig) {
			findings = append(findings, Finding{
				Severity: SeverityHigh,
				Message:  fmt.Sprintf("payload %q (%s=...) fait fuiter une trace d'erreur interne (%q)", p.Name, param, sig),
			})
			break
		}
	}

	return findings
}
