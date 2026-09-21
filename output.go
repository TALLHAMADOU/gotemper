package gotemper

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
)

// Summary tallies findings by severity.
type Summary struct {
	Total    int `json:"total_findings"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Info     int `json:"info"`
}

// Summary computes the per-severity breakdown of the report's findings.
func (r *Report) Summary() Summary {
	s := Summary{Total: len(r.Findings)}
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityInfo:
			s.Info++
		}
	}
	return s
}

// exportView is the shared shape rendered by both JSON and HTML output.
type exportView struct {
	Scenario string    `json:"scenario"`
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
}

func (r *Report) view() exportView {
	return exportView{Scenario: r.Scenario, Summary: r.Summary(), Findings: r.Findings}
}

// JSON renders the report as indented JSON, with a per-severity summary
// alongside the raw findings — suitable for CI artifacts or further tooling.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r.view(), "", "  ")
}

// WriteJSON writes the JSON report to w.
func (r *Report) WriteJSON(w io.Writer) error {
	data, err := r.JSON()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// htmlReportTemplate uses html/template (not text/template) so that finding
// messages — which can contain raw fuzzing payloads like "<script>...</script>"
// reflected back from a target — are escaped rather than rendered as markup.
const htmlReportTemplate = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>GoTemper — rapport {{.Scenario}}</title>
<style>
  body { font-family: -apple-system, Segoe UI, sans-serif; margin: 2rem auto; max-width: 900px; background:#0b0f14; color:#e6edf3; }
  h1 { font-size:1.3rem; }
  .summary { display:flex; gap:.75rem; margin:1rem 0 2rem; flex-wrap:wrap; }
  .badge { padding:.4rem .8rem; border-radius:6px; font-weight:600; font-size:.9rem; }
  .badge.critical { background:#5c1f1f; color:#ff8080; }
  .badge.high { background:#5c3d1f; color:#ffb066; }
  .badge.info { background:#1f3d5c; color:#66b0ff; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:.6rem; border-bottom:1px solid #22292f; vertical-align:top; }
  th { color:#9aa7b0; font-size:.85rem; text-transform:uppercase; }
  tr.critical td:first-child { border-left:3px solid #ff4d4d; }
  tr.high td:first-child { border-left:3px solid #ffa64d; }
  tr.info td:first-child { border-left:3px solid #4da6ff; }
  code { background:#161b22; padding:.1rem .3rem; border-radius:4px; }
</style>
</head>
<body>
  <h1>🔨 GoTemper — {{.Scenario}}</h1>
  <div class="summary">
    <span class="badge critical">{{.Summary.Critical}} critique(s)</span>
    <span class="badge high">{{.Summary.High}} élevé(s)</span>
    <span class="badge info">{{.Summary.Info}} info</span>
  </div>
  {{if .Findings}}
  <table>
    <tr><th>Sévérité</th><th>Message</th></tr>
    {{range .Findings}}
    <tr class="{{.Severity}}">
      <td>{{.Severity}}</td>
      <td>{{.Message}}</td>
    </tr>
    {{end}}
  </table>
  {{else}}
  <p>✅ Aucun finding.</p>
  {{end}}
</body>
</html>
`

var htmlReportTmpl = template.Must(template.New("report").Parse(htmlReportTemplate))

// HTML renders the report as a standalone, dark-themed HTML page.
func (r *Report) HTML() (string, error) {
	var buf bytes.Buffer
	if err := htmlReportTmpl.Execute(&buf, r.view()); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// WriteHTML writes the HTML report to w.
func (r *Report) WriteHTML(w io.Writer) error {
	html, err := r.HTML()
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, html)
	return err
}
