package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/soc-tool/internal/core/finding"
)

// WriteJSON writes the run as one JSON object (FR-R2).
func WriteJSON(w io.Writer, in Input) error {
	if in.Meta.ToolName == "" {
		return fmt.Errorf("report: ToolName is required (FR-R5 metadata)")
	}
	doc := struct {
		Metadata `json:"meta"`
		Findings []finding.Finding `json:"findings"`
	}{in.Meta, sortedSeverityDesc(in.Findings)}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// WriteCSV writes one row per finding (FR-R2).
func WriteCSV(w io.Writer, in Input) error {
	if in.Meta.ToolName == "" {
		return fmt.Errorf("report: ToolName is required (FR-R5 metadata)")
	}
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"operator", "started", "tool", "version", "targets",
		"kind", "severity", "what", "because", "detail",
	}); err != nil {
		return err
	}
	for _, f := range sortedSeverityDesc(in.Findings) {
		row := []string{
			in.Meta.Operator,
			in.Meta.When.Format(time.RFC3339),
			in.Meta.ToolName,
			in.Meta.Version,
			strings.Join(in.Meta.Targets, ";"),
			f.Kind, f.Severity.Name(), firstLine(f.What),
			firstLine(f.Because), firstLine(f.Detail),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteMarkdown writes a GitHub-ish Markdown report (FR-R2).
func WriteMarkdown(w io.Writer, in Input) error {
	if in.Meta.ToolName == "" {
		return fmt.Errorf("report: ToolName is required (FR-R5 metadata)")
	}
	fmt.Fprintf(w, "# %s %s — audit report\n\n", in.Meta.ToolName, in.Meta.Version)
	fmt.Fprintf(w, "- Operator: %s\n", orDash(in.Meta.Operator))
	fmt.Fprintf(w, "- Started: %s\n", in.Meta.When.Format(time.RFC3339))
	fmt.Fprintf(w, "- Targets: %s\n\n", orDash(strings.Join(in.Meta.Targets, ", ")))
	fmt.Fprintf(w, "## Findings (%d)\n\n", len(in.Findings))
	if len(in.Findings) == 0 {
		fmt.Fprintln(w, "(none)")
		return nil
	}
	fmt.Fprintln(w, "| Severity | Finding | Detail |")
	fmt.Fprintln(w, "|---|---|---|")
	for _, f := range sortedSeverityDesc(in.Findings) {
		fmt.Fprintf(w, "| %s | %s | %s |\n",
			f.Severity.Name(),
			mdCell(f.What),
			mdCell(strings.Join([]string{f.Because, f.Detail}, "\n\n")),
		)
	}
	return nil
}

// WriteHTML writes a standalone HTML report (FR-R2).
func WriteHTML(w io.Writer, in Input) error {
	if in.Meta.ToolName == "" {
		return fmt.Errorf("report: ToolName is required (FR-R5 metadata)")
	}
	fmt.Fprintln(w, "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>audit report</title>")
	fmt.Fprintln(w, "<style>table{border-collapse:collapse}td,th{border:1px solid #666;padding:.3rem .5rem}</style>")
	fmt.Fprintln(w, "</head><body>")
	fmt.Fprintf(w, "<h1>%s %s — audit report</h1>\n", html.EscapeString(in.Meta.ToolName), html.EscapeString(in.Meta.Version))
	fmt.Fprintf(w, "<ul><li>Operator: %s</li><li>Started: %s</li><li>Targets: %s</li></ul>\n",
		html.EscapeString(orDash(in.Meta.Operator)),
		html.EscapeString(in.Meta.When.Format(time.RFC3339)),
		html.EscapeString(orDash(strings.Join(in.Meta.Targets, ", "))),
	)
	fmt.Fprintf(w, "<h2>Findings (%d)</h2>\n", len(in.Findings))
	if len(in.Findings) == 0 {
		fmt.Fprintln(w, "<p>(none)</p></body></html>")
		return nil
	}
	fmt.Fprintln(w, "<table><tr><th>Kind</th><th>Severity</th><th>Finding</th><th>Why</th><th>Detail</th></tr>")
	for _, f := range sortedSeverityDesc(in.Findings) {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td></tr>\n",
			html.EscapeString(f.Kind),
			html.EscapeString(f.Severity.Name()),
			html.EscapeString(f.What),
			html.EscapeString(f.Because),
			html.EscapeString(f.Detail),
		)
	}
	fmt.Fprintln(w, "</table></body></html>")
	return nil
}

// sortedSeverityDesc is shared by every exporter so all formats list findings
// most severe first, like the text report (FR-S1/S2 parity).
func sortedSeverityDesc(in []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

// mdCell escapes pipes so Markdown tables keep their structure.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", "<br>")
}

// firstLine trims multi-line values for CSV cells.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
