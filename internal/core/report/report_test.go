package report

import (
	"strings"
	"testing"
	"time"

	"github.com/soc-tool/internal/core/finding"
)

func sampleInput() Input {
	return Input{
		Meta: Metadata{
			Operator: "cli",
			When:     time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC),
			ToolName: "nettools",
			Version:  "0.1.0-dev",
			Targets:  []string{"example.com:443", "example.com:8443"},
		},
		Findings: []finding.Finding{
			{Kind: "dns-caa", Severity: finding.SeverityMedium, What: "no CAA record", Because: "no CAA record was found"},
			{Kind: "tls-hostname", Severity: finding.SeverityCritical, What: "hostname mismatch", Because: "cert does not cover host", Detail: "dns_names=[example.org]"},
			{Kind: "dns-a", Severity: finding.SeverityInfo, What: "a=192.0.2.1", Because: "an A record exists"},
		},
	}
}

func TestWriteTextHasAllSections(t *testing.T) {
	out, err := WriteTextString(sampleInput())
	if err != nil {
		t.Fatalf("WriteTextString: %v", err)
	}
	for _, section := range []string{
		"=== SUMMARY ===", "=== SCOPE ===", "=== FINDINGS ===",
		"=== REMEDIATION ===", "=== METHODOLOGY ===",
	} {
		if !strings.Contains(out, section) {
			t.Errorf("report missing section %q", section)
		}
	}
}

func TestWriteTextMetadataPresent(t *testing.T) {
	// FR-R5: operator, timestamp, targets, tool version.
	out, err := WriteTextString(sampleInput())
	if err != nil {
		t.Fatalf("WriteTextString: %v", err)
	}
	for _, want := range []string{"operator:   cli", "nettools 0.1.0-dev", "targets:    2", "example.com:443", "example.com:8443", "started:    2026-10-11"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing metadata %q", want)
		}
	}
}

func TestWriteTextFindingsSortedBySeverity(t *testing.T) {
	// FR-S7: severity shown for each finding; FR-R4: grouped most-severe first.
	out, err := WriteTextString(sampleInput())
	if err != nil {
		t.Fatalf("WriteTextString: %v", err)
	}
	criticalIdx := strings.Index(out, "-- CRITICAL --")
	mediumIdx := strings.Index(out, "-- MEDIUM --")
	infoIdx := strings.Index(out, "-- INFO --")
	if criticalIdx == -1 || mediumIdx == -1 || infoIdx == -1 {
		t.Fatalf("severity groups missing: crit=%d med=%d info=%d", criticalIdx, mediumIdx, infoIdx)
	}
	if !(criticalIdx < mediumIdx && mediumIdx < infoIdx) {
		t.Errorf("severity groups out of order in output")
	}
	if !strings.Contains(out, "hostname mismatch") {
		t.Error("report missing finding text")
	}
}

func TestWriteTextRemediationPerKind(t *testing.T) {
	// FR-R6: guidance per finding kind; deduplicated.
	out, err := WriteTextString(sampleInput())
	if err != nil {
		t.Fatalf("WriteTextString: %v", err)
	}
	if !strings.Contains(out, "Issue a certificate that covers the requested hostname") {
		t.Error("missing tls-hostname remediation")
	}
	if !strings.Contains(out, "Publish CAA records") {
		t.Error("missing dns-caa remediation")
	}
	if strings.Count(out, "Renew the certificate") != 0 {
		t.Error("no tls-expiry finding should not produce renewal guidance")
	}
}

func TestWriteTextEmptyRun(t *testing.T) {
	in := Input{Meta: Metadata{ToolName: "nettools", Version: "x", Operator: "cli"}}
	out, err := WriteTextString(in)
	if err != nil {
		t.Fatalf("WriteTextString: %v", err)
	}
	if !strings.Contains(out, "targets:    0") || !strings.Contains(out, "findings:   0 total") {
		t.Errorf("empty-run summary wrong:\n%s", out)
	}
	if !strings.Contains(out, "(no targets)") || !strings.Contains(out, "(none)") {
		t.Error("empty-run placeholders missing")
	}
	if strings.Contains(out, "- ") && strings.Contains(out, "=== REMEDIATION ===\n  -") {
		t.Error("empty run must not list remediation bullets")
	}
}

func TestWriteTextRequiresToolName(t *testing.T) {
	_, err := WriteTextString(Input{Meta: Metadata{Version: "v"}})
	if err == nil {
		t.Error("expected error when ToolName missing (FR-R5)")
	}
}

func TestRemediationDeduplicated(t *testing.T) {
	fs := []finding.Finding{
		{Kind: "tls-expiry", Severity: finding.SeverityCritical},
		{Kind: "tls-expiry", Severity: finding.SeverityHigh},
	}
	lines := remediationLines(fs)
	if len(lines) != 1 {
		t.Errorf("dedup failed: %v", lines)
	}
}
