// Package report renders structured run reports for the network inspection
// module. It is the single place report formats are produced; every interface
// (TUI, web UI, headless CLI) renders through these functions so output stays
// identical across front-ends (FR-S1/S2).
//
// Tier 1 output is plain text (FR-R1) with the structured sections required
// by FR-R4: summary → scope → findings by severity → remediation →
// methodology, plus run metadata (FR-R5).
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/soc-tool/internal/core/finding"
)

// Metadata describes one run (FR-R5).
type Metadata struct {
	Operator string    // who ran it
	When     time.Time // when it ran
	ToolName string
	Version  string
	Targets  []string // "host:port" per target, in run order
}

// Input is everything one report needs.
type Input struct {
	Meta     Metadata
	Findings []finding.Finding // one run's findings, all targets
}

// WriteText renders the structured text report to w and returns an error
// only if writing fails. Section order is fixed (FR-R4):
//
//  1. Summary
//  2. Scope
//  3. Findings (grouped by severity, most severe first)
//  4. Remediation
//  5. Methodology
func WriteText(w io.Writer, in Input) error {
	if in.Meta.ToolName == "" {
		return fmt.Errorf("report: ToolName is required (FR-R5 metadata)")
	}

	counts := countBySeverity(in.Findings)
	fmt.Fprintln(w, "=== SUMMARY ===")
	fmt.Fprintf(w, "tool:       %s %s\n", in.Meta.ToolName, in.Meta.Version)
	fmt.Fprintf(w, "operator:   %s\n", orDash(in.Meta.Operator))
	fmt.Fprintf(w, "started:    %s\n", in.Meta.When.Format(time.RFC3339))
	fmt.Fprintf(w, "targets:    %d\n", len(in.Meta.Targets))
	fmt.Fprintf(w, "findings:   %d total\n", len(in.Findings))
	for _, sev := range finding.SeveritiesSortedDesc() {
		if n := counts[sev]; n > 0 {
			fmt.Fprintf(w, "  %-8s %d\n", sev.Name(), n)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "=== SCOPE ===")
	if len(in.Meta.Targets) == 0 {
		fmt.Fprintln(w, "  (no targets)")
	} else {
		for _, tgt := range in.Meta.Targets {
			fmt.Fprintf(w, "  %s\n", tgt)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "=== FINDINGS ===")
	if len(in.Findings) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		sorted := make([]finding.Finding, len(in.Findings))
		copy(sorted, in.Findings)
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].Severity > sorted[j].Severity
		})
		lastSev := finding.Severity(-1)
		for _, f := range sorted {
			if f.Severity != lastSev {
				fmt.Fprintf(w, "  -- %s --\n", f.Severity.Name())
				lastSev = f.Severity
			}
			fmt.Fprintf(w, "  [%s] %s\n", f.Severity.Name(), f.What)
			if f.Because != "" {
				fmt.Fprintf(w, "    because: %s\n", f.Because)
			}
			if f.Detail != "" {
				fmt.Fprintf(w, "    detail:  %s\n", f.Detail)
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "=== REMEDIATION ===")
	remediations := remediationLines(in.Findings)
	if len(remediations) == 0 {
		fmt.Fprintln(w, "  No remediation needed for the findings above.")
	} else {
		for _, r := range remediations {
			fmt.Fprintf(w, "  - %s\n", r)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "=== METHODOLOGY ===")
	fmt.Fprintln(w, "  Checks were run only against operator-supplied targets (FR-S8).")
	fmt.Fprintln(w, "  Certificates: served chain, identity, validity/expiry, hostname coverage.")
	fmt.Fprintln(w, "  DNS: A/AAAA/CAA record resolution via public resolvers.")
	fmt.Fprintln(w, "  Evidence: results and audit entries are recorded locally per run.")
	return nil
}

// WriteTextString is a convenience wrapper for tests and simple callers.
func WriteTextString(in Input) (string, error) {
	var b strings.Builder
	if err := WriteText(&b, in); err != nil {
		return "", err
	}
	return b.String(), nil
}

// countBySeverity returns findings per severity.
func countBySeverity(fs []finding.Finding) map[finding.Severity]int {
	m := make(map[finding.Severity]int)
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}

// remediationLines derives short, plain-language remediation guidance from
// the finding kinds present (FR-R6, Tier 2-grade per-kind guidance lands later).
func remediationLines(fs []finding.Finding) []string {
	seen := make(map[string]bool)
	var out []string
	for _, f := range fs {
		var guidance string
		switch f.Kind {
		case "tls-expiry":
			guidance = "Renew the certificate before the expiry date."
		case "tls-hostname":
			guidance = "Issue a certificate that covers the requested hostname (check SAN entries)."
		case "tls-chain":
			guidance = "Install the full intermediate chain so the leaf verifies."
		case "tls-connect":
			guidance = "Confirm the service is running and reachable at the named address."
		case "dns-a":
			guidance = "Add or correct the A record for the hostname."
		case "dns-caa":
			guidance = "Publish CAA records naming the CAs allowed to issue for this zone."
		default:
			continue
		}
		if !seen[guidance] {
			seen[guidance] = true
			out = append(out, guidance)
		}
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
