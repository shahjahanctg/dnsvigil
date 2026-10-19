package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/soc-tool/internal/core/audit"

	"github.com/soc-tool/internal/core/dnscheck"
	"github.com/soc-tool/internal/core/engine"
	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/history"
	"github.com/soc-tool/internal/core/report"
	"github.com/soc-tool/internal/core/target"
	"github.com/soc-tool/internal/core/tlscheck"
)

var version = "0.1.0-dev"

// headlessOptions bundles one headless run's configuration (FR-C1/C4, FR-D12,
// FR-A1/A2/A5, FR-R5). It is a plain struct so tests can drive it directly.
type headlessOptions struct {
	Operator        string
	Timeout         time.Duration
	ExpiryWarnDays  int
	AuditPath       string
	Retention       time.Duration
	LogFindings     bool
	ExportFormat    string
	ReportDir       string
	Resolver        string
	SecondResolver  string
	Enumerate       bool
	CheckRevocation bool
}

func main() {
	// Route on the first mode flag; everything after it belongs to that
	// mode's own flag set (headless flags precede the target list).
	args := os.Args[1:]
	for i, a := range args {
		switch a {
		case "-version", "--version":
			fmt.Printf("nettools version %s\n", version)
			os.Exit(0)
		case "-headless", "--headless":
			runHeadless(args[i+1:])
			return
		case "-tui", "--tui":
			runTUI()
			return
		case "-gui", "--gui":
			runWebUI()
			return
		}
	}
	fmt.Fprintf(os.Stderr, "usage: nettools --headless|--tui|--gui [mode flags] target1 target2 ...\n")
	os.Exit(1)
}

// parseHeadlessInputs parses the positional target list, optionally followed
// by a target file (FR-C1: single entry, pasted list, imported file).
func parseHeadlessInputs(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets provided; usage: nettools --headless host1 host2 ...")
	}
	return out, nil
}

// resolveTargetList expands operator-supplied args plus every path in the
// operator's imported target files (FR-C1); blank lines and # comments are
// ignored; supports pasted multi-line text.
func resolveTargetList(args []string, files []string) ([]string, int, error) {
	var inputs []string
	inputs = append(inputs, args...)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, 0, fmt.Errorf("read target file %s: %w", file, err)
		}
		inputs = append(inputs, strings.Split(string(data), "\n")...)
	}
	var targets []string
	for _, raw := range inputs {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if len(targets) == 0 {
		return nil, 0, fmt.Errorf("no targets provided; usage: nettools --headless [--targets file] host1 host2 ...")
	}
	return targets, len(files) + len(args), nil
}

// valuedHeadlessFlags are the headless flags that consume the following
// argument as their value. Everything else in the flag set is boolean.
var valuedHeadlessFlags = map[string]bool{
	"targets":          true,
	"operator":         true,
	"timeout":          true,
	"expiry-warn":      true,
	"audit":            true,
	"retention":        true,
	"export":           true,
	"report-dir":       true,
	"resolver":         true,
	"second-resolver":  true,
	"log-findings":     false,
	"enumerate":        false,
	"check-revocation": false,
}

// reorderHeadlessArgs moves flags ahead of the positional target list so the
// documented invocation `--headless example.com --expiry-warn 68` parses its
// flags, and a flag can never be mistaken for a target (FR-S8). It understands
// `-flag value`, `-flag=value`, and `--` (end of flags).
func reorderHeadlessArgs(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue // value is inline
		}
		if valuedHeadlessFlags[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}

func runHeadless(args []string) {
	fs := flag.NewFlagSet("nettools headless", flag.ExitOnError)

	opts := headlessOptions{}
	files := fs.String("targets", "", "file of newline-separated targets to import (FR-C1)")
	fs.StringVar(&opts.Operator, "operator", "cli", "operator name recorded in report and audit (FR-R5)")
	fs.DurationVar(&opts.Timeout, "timeout", 5*time.Second, "lookup/DNS timeout")
	fs.IntVar(&opts.ExpiryWarnDays, "expiry-warn", tlscheck.DefaultExpiryWarnDays, "days-to-expiry warning threshold (FR-C4)")
	fs.StringVar(&opts.AuditPath, "audit", "audit.jsonl", "audit log path")
	fs.DurationVar(&opts.Retention, "retention", 0, "audit retention (keep entries newer than this; 0 disables) (FR-A5)")
	fs.BoolVar(&opts.LogFindings, "log-findings", false, "record full findings in audit entries (FR-A2)")
	fs.StringVar(&opts.ExportFormat, "export", "", "export the latest run to json|csv|md|html into --report-dir (FR-R2)")
	fs.StringVar(&opts.ReportDir, "report-dir", ".nettools/reports", "directory for exported reports and run history files (FR-R8)")
	fs.StringVar(&opts.Resolver, "resolver", "", "custom DNS resolver for every query, e.g. 1.1.1.1:53 (FR-D12)")
	fs.StringVar(&opts.SecondResolver, "second-resolver", "", "second resolver to compare answers against (FR-D11)")
	fs.BoolVar(&opts.Enumerate, "enumerate", false, "probe offered protocols and ciphers (FR-C15/C16; more connections per target)")
	fs.BoolVar(&opts.CheckRevocation, "check-revocation", false, "verify OCSP revocation status (FR-C10; off by default)")
	if err := fs.Parse(reorderHeadlessArgs(args)); err != nil {
		os.Exit(2)
	}

	var imported []string
	if importedFlag := *files; importedFlag != "" {
		imported = []string{importedFlag}
	}
	targets, _, err := resolveTargetList(fs.Args(), imported)
	if err != nil {
		fmt.Fprintf(os.Stderr, "headless: %v\n", err)
		os.Exit(2)
	}
	log := audit.New(opts.AuditPath, opts.Retention, opts.Retention > 0)
	hist := history.New("") // shared default dir so TUI/dashboard see the same history
	for _, inp := range targets {
		tgt, err := target.ParseTarget(inp)
		if err != nil {
			appendAudit(log, opts, audit.Entry{Operator: opts.Operator, Action: "parse-error", Target: inp, When: time.Now(), Result: "error"})
			fmt.Fprintf(os.Stderr, "headless: %v\n", err)
			continue
		}

		ctx := engine.Context{
			DNSContext: dnscheck.Context{CustomResolver: opts.Resolver,
				SecondResolver: opts.SecondResolver,
				Timeout:        opts.Timeout,
			},
			TLSContext: tlscheck.Context{
				ExpiryWarnDays:  opts.ExpiryWarnDays,
				CheckRevocation: opts.CheckRevocation,
				Enumerate:       opts.Enumerate,
			},
		}

		res := engine.Run(ctx, tgt)

		// Certificate change detection vs previous run (FR-C9) + history.
		currentFP := fingerprintOf(res.Findings)
		if prev, seen, err := hist.Last(tgt.Addr()); err == nil && seen && currentFP != "" {
			if change := history.DetectChange(tgt.Addr(), currentFP, prev); strings.HasPrefix(change, "changed") {
				res.Findings = append(res.Findings, finding.Finding{
					Kind:     "tls-cert-change",
					Severity: finding.SeverityMedium,
					What:     "certificate changed since previous run",
					Because:  change,
					Detail:   fmt.Sprintf("previous=sha256:%s\ncurrent=sha256:%s", prev, currentFP),
				})
			}
		}
		if currentFP != "" {
			_ = hist.Append(tgt.Addr(), currentFP)
		}
		rin := report.Input{
			Meta: report.Metadata{
				Operator: opts.Operator,
				When:     time.Now(),
				ToolName: "nettools",
				Version:  version,
				Targets:  []string{tgt.Addr()},
			},
			Findings: res.Findings,
		}
		entry := audit.Entry{
			Operator: opts.Operator,
			Action:   "audit",
			Target:   tgt.Addr(),
			When:     time.Now(),
			Result:   "ok",
		}
		if res.Error != nil {
			entry.Result = "error"
		}
		if opts.LogFindings {
			entry.Findings = res.Findings
		}
		appendAudit(log, opts, entry)
		if err := report.WriteText(os.Stdout, rin); err != nil {
			fmt.Fprintf(os.Stderr, "report: %v\n", err)
		}
		if opts.ExportFormat != "" {
			path, err := exportReport(rin, opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "export: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "exported: %s\n", path)
			}
		}
	}

	if err := log.Rotate(); err != nil {
		fmt.Fprintf(os.Stderr, "audit rotate: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "audit log: %s\n", opts.AuditPath)
} // appendAudit tolerates logging failures: the audit log must never bring down
// the check pass (FR-A1); the error surfaces on stderr instead.
func appendAudit(l *audit.Log, opts headlessOptions, e audit.Entry) {
	if err := l.Append(e); err != nil {
		fmt.Fprintf(os.Stderr, "audit append: %v\n", err)
	}
}

// fingerprintOf pulls the recorded SHA-256 from the fingerprint finding.
func fingerprintOf(fs []finding.Finding) string {
	for _, f := range fs {
		if f.Kind == "tls-fingerprint" {
			return history.ExtractFingerprint(f.What)
		}
	}
	return ""
}

// exportReport writes the run to a file in the requested format (FR-R2).
func exportReport(rin report.Input, opts headlessOptions) (string, error) {
	var ext string
	switch strings.ToLower(opts.ExportFormat) {
	case "json":
		ext = ".json"
	case "csv":
		ext = ".csv"
	case "md", "markdown":
		ext = ".md"
	case "html":
		ext = ".html"
	default:
		return "", fmt.Errorf("unknown export format %q (json|csv|md|html)", opts.ExportFormat)
	}
	if err := os.MkdirAll(opts.ReportDir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("nettools-%s%s", rin.Meta.When.Format("20060102-150405"), ext)
	path := filepath.Join(opts.ReportDir, name)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var werr error
	switch strings.ToLower(opts.ExportFormat) {
	case "json":
		werr = report.WriteJSON(f, rin)
	case "csv":
		werr = report.WriteCSV(f, rin)
	case "md", "markdown":
		werr = report.WriteMarkdown(f, rin)
	case "html":
		werr = report.WriteHTML(f, rin)
	}
	return path, werr
}
