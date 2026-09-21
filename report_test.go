package gotemper

import "testing"

func TestReport_FindingsAtOrAbove(t *testing.T) {
	r := &Report{
		Findings: []Finding{
			{Severity: SeverityInfo, Message: "info finding"},
			{Severity: SeverityHigh, Message: "high finding"},
			{Severity: SeverityCritical, Message: "critical finding"},
		},
	}

	cases := []struct {
		threshold Severity
		want      int
	}{
		{SeverityInfo, 3},
		{SeverityHigh, 2},
		{SeverityCritical, 1},
		{Severity("bogus"), 0},
	}

	for _, c := range cases {
		got := r.findingsAtOrAbove(c.threshold)
		if len(got) != c.want {
			t.Errorf("findingsAtOrAbove(%q) = %d findings, attendu %d", c.threshold, len(got), c.want)
		}
	}
}

func TestReport_HasCritical(t *testing.T) {
	clean := &Report{Findings: []Finding{{Severity: SeverityHigh, Message: "x"}}}
	if clean.HasCritical() {
		t.Fatal("HasCritical() ne devrait pas être vrai sans finding critique")
	}

	dirty := &Report{Findings: []Finding{{Severity: SeverityCritical, Message: "x"}}}
	if !dirty.HasCritical() {
		t.Fatal("HasCritical() devrait être vrai avec un finding critique")
	}
}
