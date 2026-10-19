package report

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/soc-tool/internal/core/finding"
)

func pdfTestInput() Input {
	return Input{
		Meta: Metadata{
			Operator: "cli",
			When:     time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC),
			ToolName: "nettools",
			Version:  "0.1.0-dev",
			Targets:  []string{"example.com:443"},
		},
		Findings: []finding.Finding{
			{
				Kind:     "tls-hostname",
				Severity: finding.SeverityCritical,
				What:     "hostname mismatch (pdf coverage marker)",
				Because:  "the certificate does not cover\r\nthe requested host",
				Detail:   "cn=other.test",
			},
			{
				Kind:     "dns-a",
				Severity: finding.SeverityInfo,
				What:     "a=192.0.2.10",
				Because:  "an A record exists",
			},
		},
	}
}

// pdfObjectOffsets returns the byte offset of every object in the xref table.
func pdfObjectOffsets(t *testing.T, out []byte) []int {
	t.Helper()
	idx := bytes.LastIndex(out, []byte("\nxref\n"))
	if idx < 0 {
		t.Fatal("no xref table in output")
	}
	table := out[idx+len("\nxref\n"):]
	// The subsection header ("0 N") is the first line after "xref"; the N
	// entries follow it, starting with the free entry for object 0.
	lines := strings.Split(string(table), "\n")
	if len(lines) < 3 {
		t.Fatalf("xref table too short: %q", table)
	}
	header := strings.Fields(lines[0])
	if len(header) != 2 || header[0] != "0" {
		t.Fatalf("malformed xref subsection header %q", lines[0])
	}
	count, err := strconv.Atoi(header[1])
	if err != nil {
		t.Fatalf("cannot read xref count %q: %v", lines[0], err)
	}
	var offsets []int
	for i := 1; i <= count; i++ {
		if i >= len(lines) {
			t.Fatalf("xref table ended early at %d entries", i)
		}
		fields := strings.Fields(lines[i])
		if len(fields) < 3 {
			t.Fatalf("malformed xref entry %q", lines[i])
		}
		if fields[2] == "f" {
			continue
		}
		off, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("malformed xref offset %q: %v", fields[0], err)
		}
		offsets = append(offsets, off)
	}
	return offsets
}

func TestWritePDFIsStructurallyValid(t *testing.T) {
	// FR-R3: the export must be a real PDF — header, objects, a trailer whose
	// xref offsets actually point at those objects, and EOF.
	var buf bytes.Buffer
	if err := WritePDF(&buf, pdfTestInput()); err != nil {
		t.Fatalf("WritePDF: %v", err)
	}
	out := buf.Bytes()

	if !bytes.HasPrefix(out, []byte("%PDF-1.4")) {
		t.Errorf("missing PDF header: %q", out[:min(20, len(out))])
	}
	if !bytes.Contains(out, []byte("%%EOF")) {
		t.Error("missing end-of-file marker")
	}
	if !bytes.Contains(out, []byte("/Type /Catalog")) || !bytes.Contains(out, []byte("/Type /Pages")) {
		t.Error("missing catalog or pages object")
	}

	offsets := pdfObjectOffsets(t, out)
	if len(offsets) < 4 {
		t.Fatalf("expected several objects, got %d", len(offsets))
	}
	objPat := regexp.MustCompile(`^[0-9]+ 0 obj`)
	for _, off := range offsets {
		if off < 0 || off >= len(out) {
			t.Fatalf("xref offset %d outside the file (%d bytes)", off, len(out))
		}
		if !objPat.Match(out[off:]) {
			t.Errorf("xref offset %d does not point at an object: %q", off, out[off:min(off+24, len(out))])
		}
	}

	startxref := bytes.LastIndex(out, []byte("startxref"))
	if startxref < 0 {
		t.Fatal("missing startxref")
	}
	tail := strings.TrimSpace(string(out[startxref+len("startxref"):]))
	tail = strings.TrimSuffix(tail, "%%EOF")
	val, err := strconv.Atoi(strings.TrimSpace(tail))
	if err != nil {
		t.Fatalf("cannot read startxref value %q: %v", tail, err)
	}
	if string(out[val:]) != "" && !bytes.HasPrefix(out[val:], []byte("xref")) {
		t.Errorf("startxref does not point at the xref table: %q", out[val:min(val+16, len(out))])
	}
}

func TestWritePDFCarriesEveryFinding(t *testing.T) {
	// The export is evidence: every finding's assertion and reason must be in
	// the document, and text that would break a PDF string must be escaped.
	in := pdfTestInput()
	var buf bytes.Buffer
	if err := WritePDF(&buf, in); err != nil {
		t.Fatalf("WritePDF: %v", err)
	}
	out := buf.String()

	for _, f := range in.Findings {
		if !strings.Contains(out, pdfEscape(f.What)) {
			t.Errorf("finding %q missing from the PDF", f.What)
		}
	}
	if !strings.Contains(out, "nettools") || !strings.Contains(out, "cli") {
		t.Error("run metadata (tool, operator) must appear in the PDF")
	}
	if strings.Contains(out, "the certificate does not cover\r") {
		t.Error("carriage returns must be neutralised inside the content stream")
	}
	// Parentheses and backslashes inside text must be escaped, or the string
	// would end early and corrupt the document.
	escaped := pdfEscape(`a (b) \c`)
	if escaped != `a \(b\) \\c` {
		t.Errorf("pdfEscape = %q", escaped)
	}
}

func TestWritePDFPaginates(t *testing.T) {
	// A long report must not run off a single page.
	in := pdfTestInput()
	for i := 0; i < 200; i++ {
		in.Findings = append(in.Findings, finding.Finding{
			Kind:     "dns-a",
			Severity: finding.SeverityInfo,
			What:     fmt.Sprintf("filler-%03d", i),
			Because:  "a record exists",
		})
	}
	var buf bytes.Buffer
	if err := WritePDF(&buf, in); err != nil {
		t.Fatalf("WritePDF: %v", err)
	}
	out := buf.String()
	pages := strings.Count(out, "/Type /Page ")
	if pages < 2 {
		t.Errorf("a 200-finding report needs more than one page, got %d", pages)
	}
	if !strings.Contains(out, "filler-199") {
		t.Error("the last finding must survive pagination")
	}
}
