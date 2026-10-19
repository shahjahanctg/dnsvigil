package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/report"
)

func TestExportReportWritesPDF(t *testing.T) {
	// FR-R3: PDF is the last export format in the tiering, and it must be a
	// real PDF file on disk, not a renamed text file.
	dir := t.TempDir()
	in := report.Input{
		Meta: report.Metadata{
			Operator: "cli",
			When:     time.Now(),
			ToolName: "nettools",
			Version:  "test",
			Targets:  []string{"example.test:443"},
		},
		Findings: []finding.Finding{{
			Kind: "dns-a", Severity: finding.SeverityInfo,
			What: "a=192.0.2.10", Because: "an A record exists for example.test",
		}},
	}

	path, err := exportReport(in, headlessOptions{ExportFormat: "pdf", ReportDir: dir})
	if err != nil {
		t.Fatalf("exportReport(pdf): %v", err)
	}
	if !strings.HasSuffix(path, ".pdf") {
		t.Errorf("exported path = %q, want a .pdf suffix", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("%PDF-1.4")) {
		t.Errorf("export is not a PDF: %q", string(data[:min(16, len(data))]))
	}
	if !bytes.Contains(data, []byte("a=192.0.2.10")) {
		t.Error("the PDF must contain the finding")
	}

	if _, err := exportReport(in, headlessOptions{ExportFormat: "docx", ReportDir: dir}); err == nil {
		t.Error("an unknown format must still be rejected")
	}
}

func TestNormalizeResolver(t *testing.T) {
	ok := []struct{ in, want string }{
		{"", ""},
		{"1.1.1.1", "1.1.1.1:53"},
		{"1.1.1.1:53", "1.1.1.1:53"},
		{"8.8.8.8:5353", "8.8.8.8:5353"},
		{"dns.example.com", "dns.example.com:53"},
		{" 1.1.1.1 ", "1.1.1.1:53"},
		{"2606:4700:4700::1111", "[2606:4700:4700::1111]:53"},
		{"[2606:4700:4700::1111]:53", "[2606:4700:4700::1111]:53"},
	}
	for _, tc := range ok {
		got, err := normalizeResolver(tc.in)
		if err != nil {
			t.Errorf("normalizeResolver(%q) returned error %v, want %q", tc.in, err, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeResolver(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	bad := []string{"not a host", "1.1.1.1:abc", ":53", "1.1.1.1:"}
	for _, in := range bad {
		if got, err := normalizeResolver(in); err == nil {
			t.Errorf("normalizeResolver(%q) = %q, want an error", in, got)
		}
	}
}

func TestReorderHeadlessArgsMovesFlagsBeforeTargets(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"flags first unchanged", []string{"--expiry-warn", "68", "example.com"}, []string{"--expiry-warn", "68", "example.com"}},
		{"flag after target", []string{"example.com", "--expiry-warn", "68"}, []string{"--expiry-warn", "68", "example.com"}},
		{"inline value after target", []string{"example.com", "--expiry-warn=68"}, []string{"--expiry-warn=68", "example.com"}},
		{"bool flag after target", []string{"example.com", "--log-findings"}, []string{"--log-findings", "example.com"}},
		{"mixed flags and two targets", []string{"a.com", "--operator", "soc", "b.com", "--enumerate"}, []string{"--operator", "soc", "--enumerate", "a.com", "b.com"}},
		{"double dash ends flags", []string{"--operator", "soc", "--", "--weird.example"}, []string{"--operator", "soc", "--weird.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reorderHeadlessArgs(tc.in)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("reorderHeadlessArgs(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseHeadlessInputsEmptyErrors(t *testing.T) {
	_, err := parseHeadlessInputs(nil)
	if err == nil {
		t.Fatal("no targets must produce an error")
	}
	if !strings.Contains(err.Error(), "no targets") || !strings.Contains(err.Error(), "usage") {
		t.Errorf("error should point the operator at the usage line: %v", err)
	}
}

func TestParseHeadlessInputsReturnsTargets(t *testing.T) {
	in := []string{"example.com", "example.com:8443"}
	got, err := parseHeadlessInputs(in)
	if err != nil {
		t.Fatalf("valid args returned error: %v", err)
	}
	if len(got) != 2 || got[0] != in[0] || got[1] != in[1] {
		t.Errorf("parseHeadlessInputs = %v, want %v (order preserved)", got, in)
	}
}
