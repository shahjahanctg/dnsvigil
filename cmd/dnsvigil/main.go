package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/audit"

	"github.com/dnsvigil/dnsvigil/internal/core/dnscheck"
	"github.com/dnsvigil/dnsvigil/internal/core/engine"
	"github.com/dnsvigil/dnsvigil/internal/core/finding"
	"github.com/dnsvigil/dnsvigil/internal/core/history"
	"github.com/dnsvigil/dnsvigil/internal/core/report"
	"github.com/dnsvigil/dnsvigil/internal/core/settings"
	"github.com/dnsvigil/dnsvigil/internal/core/target"
	"github.com/dnsvigil/dnsvigil/internal/core/tlscheck"
)

var version = "0.1.0-dev"

// headlessOptions bundles one headless run's configuration (FR-C1/C4, FR-D12,
// FR-A1/A2/A5, FR-R5). It is a plain struct so tests can drive it directly.
type headlessOptions struct {
	Operator         string
	Timeout          time.Duration
	ExpiryWarnDays   int
	AuditPath        string
	Retention        time.Duration
	HistoryRetention time.Duration
	LogFindings      bool
	ExportFormat     string
	ReportDir        string
	Resolver         string
	SecondResolver   string
	Enumerate        bool
	CheckRevocation  bool
	Deep             bool
	UseDoH           bool
	DoHProvider      string
	WordlistPath     string
	DiscoverWordlist bool
	DiscoverCT       bool
	ZoneTransfer     bool
	Budget           time.Duration
}

func main() {
	// Route on the first mode flag; everything after it belongs to that
	// mode's own flag set (headless flags precede the target list).
	args := os.Args[1:]
	for i, a := range args {
		switch a {
		case "-version", "--version":
			fmt.Printf("dnsvigil version %s\n", version)
			os.Exit(0)
		case "-headless", "--headless":
			runHeadless(args[i+1:])
			return
		case "-tui", "--tui":
			runTUI()
			return
		case "-gui", "--gui":
			runWebUI(args[i+1:])
			return
		}
	}
	fmt.Fprintf(os.Stderr, "usage: dnsvigil --headless|--tui|--gui [mode flags] target1 target2 ...\n")
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
		return nil, fmt.Errorf("no targets provided; usage: dnsvigil --headless host1 host2 ...")
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
		return nil, 0, fmt.Errorf("no targets provided; usage: dnsvigil --headless [--targets file] host1 host2 ...")
	}
	return targets, len(files) + len(args), nil
}

// normalizeResolver validates an operator-supplied resolver and fills in the
// default DNS port (FR-D12). An empty value means "use the built-in defaults".
func normalizeResolver(value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", nil
	}
	if strings.ContainsAny(v, " \t") {
		return "", fmt.Errorf("%q is not a host or host:port", value)
	}
	host, port := v, "53"
	if ip := net.ParseIP(v); ip == nil {
		if h, p, err := net.SplitHostPort(v); err == nil {
			host, port = h, p
		} else if strings.Count(v, ":") == 1 {
			return "", fmt.Errorf("%q is not a host or host:port", value)
		}
	}
	if host == "" {
		return "", fmt.Errorf("%q has no host", value)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("port in %q is not a number", value)
	}
	return net.JoinHostPort(host, port), nil
}

// valuedHeadlessFlags are the headless flags that consume the following
// argument as their value. Everything else in the flag set is boolean.
var valuedHeadlessFlags = map[string]bool{
	"targets":           true,
	"operator":          true,
	"timeout":           true,
	"expiry-warn":       true,
	"audit":             true,
	"retention":         true,
	"history-retention": true,
	"export":            true,
	"report-dir":        true,
	"resolver":          true,
	"second-resolver":   true,
	"log-findings":      false,
	"enumerate":         false,
	"check-revocation":  false,
	"deep":              false,
	"doh":               false,
	"discover":          false,
	"discover-ct":       false,
	"axfr":              false,
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

// settingsDefaults seeds the headless flags from the shared settings file (FR-S1/S2).
func settingsDefaults() headlessOptions {
	st, _, _ := settings.Load("")
	return headlessOptions{
		Operator:         st.Operator,
		Timeout:          time.Duration(st.Timeout),
		ExpiryWarnDays:   st.ExpiryWarnDays,
		Retention:        time.Duration(st.AuditRetention),
		HistoryRetention: time.Duration(st.HistoryRetention),
		Resolver:         st.Resolver,
		SecondResolver:   st.SecondResolver,
		Budget:           time.Duration(st.Budget),
		DoHProvider:      st.DoHProvider,
		Enumerate:        st.Enumerate,
		Deep:             st.Deep,
		UseDoH:           st.UseDoH,
		DiscoverWordlist: st.DiscoverWordlist,
		DiscoverCT:       st.DiscoverCT,
		ZoneTransfer:     st.ZoneTransfer,
		CheckRevocation:  st.CheckRevocation,
	}
}

func runHeadless(args []string) {
	fs := flag.NewFlagSet("dnsvigil headless", flag.ExitOnError)

	// A settings file (written on the web Settings page) provides the defaults;
	// an explicit flag still wins (FR-S1/S2).
	opts := settingsDefaults()
	files := fs.String("targets", "", "file of newline-separated targets to import (FR-C1)")
	fs.StringVar(&opts.Operator, "operator", opts.Operator, "operator name recorded in report and audit (FR-R5)")
	fs.DurationVar(&opts.Timeout, "timeout", opts.Timeout, "per-query DNS timeout and per-attempt TLS connect/handshake bound")
	fs.IntVar(&opts.ExpiryWarnDays, "expiry-warn", opts.ExpiryWarnDays, "days-to-expiry warning threshold (FR-C4)")
	fs.StringVar(&opts.AuditPath, "audit", "audit.jsonl", "audit log path")
	fs.DurationVar(&opts.Retention, "retention", opts.Retention, "audit retention (keep entries newer than this; 0 disables) (FR-A5)")
	fs.DurationVar(&opts.HistoryRetention, "history-retention", opts.HistoryRetention, "prune run history older than this; 0 disables (default 30 days)")
	fs.BoolVar(&opts.LogFindings, "log-findings", false, "record full findings in audit entries (FR-A2)")
	fs.StringVar(&opts.ExportFormat, "export", "", "export the latest run to json|csv|md|html|pdf into --report-dir (FR-R2/R3)")
	fs.StringVar(&opts.ReportDir, "report-dir", ".dnsvigil/reports", "directory for exported reports and run history files (FR-R8)")
	fs.StringVar(&opts.Resolver, "resolver", opts.Resolver, "custom DNS resolver for every query, e.g. 1.1.1.1:53 (FR-D12)")
	fs.StringVar(&opts.SecondResolver, "second-resolver", opts.SecondResolver, "second resolver to compare answers against (FR-D11)")
	fs.DurationVar(&opts.Budget, "budget", opts.Budget, "bound on the whole run per target; negative disables it (NFR-3)")
	fs.StringVar(&opts.WordlistPath, "wordlist", "", "file of names to probe with --discover, one name or label per line (FR-D14)")
	fs.StringVar(&opts.DoHProvider, "doh-provider", opts.DoHProvider, "DNS-over-HTTPS provider for --doh: cloudflare|google|quad9 or an https URL (FR-D13)")
	fs.BoolVar(&opts.Enumerate, "enumerate", opts.Enumerate, "probe offered protocols and ciphers (FR-C15/C16) and SNI names (FR-C20); more connections per target")
	fs.BoolVar(&opts.Deep, "deep", opts.Deep, "run the extra DNS checks: SRV, DKIM, TLSA, MTA-STS, TLS-RPT, reverse DNS, TTL, delegation (FR-D2/D6/D7/D8/D19/D22/D23)")
	fs.BoolVar(&opts.UseDoH, "doh", opts.UseDoH, "also resolve over DNS-over-HTTPS and compare (FR-D13)")
	fs.BoolVar(&opts.DiscoverWordlist, "discover", opts.DiscoverWordlist, "probe a built-in subdomain wordlist under each target domain (FR-D14)")
	fs.BoolVar(&opts.DiscoverCT, "discover-ct", opts.DiscoverCT, "ask Certificate Transparency logs for subdomains (FR-D15)")
	fs.BoolVar(&opts.ZoneTransfer, "axfr", opts.ZoneTransfer, "attempt a zone transfer against each authoritative server (FR-D16)")
	fs.BoolVar(&opts.CheckRevocation, "check-revocation", opts.CheckRevocation, "verify OCSP revocation status (FR-C10; off by default)")
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
	// A mistyped resolver must fail loudly: silently falling back would turn a
	// typo into "no A record" findings about a host that is actually fine.
	resolver, err := normalizeResolver(opts.Resolver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "headless: invalid --resolver: %v\n", err)
		os.Exit(2)
	}
	secondResolver, err := normalizeResolver(opts.SecondResolver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "headless: invalid --second-resolver: %v\n", err)
		os.Exit(2)
	}

	log := audit.New(opts.AuditPath, opts.Retention, opts.Retention > 0)
	// Shared default dir so the dashboard sees the same history; retention keeps
	// old runs from accumulating (0 disables automatic pruning).
	hist := history.New("", history.WithRetention(opts.HistoryRetention))
	for _, inp := range targets {
		tgt, err := target.ParseTarget(inp)
		if err != nil {
			appendAudit(log, opts, audit.Entry{Operator: opts.Operator, Action: "parse-error", Target: inp, When: time.Now(), Result: "error"})
			fmt.Fprintf(os.Stderr, "headless: %v\n", err)
			continue
		}

		ctx := engine.Context{
			DNSContext: dnscheck.Context{CustomResolver: resolver,
				SecondResolver:   secondResolver,
				Timeout:          opts.Timeout,
				Deep:             opts.Deep,
				UseDoH:           opts.UseDoH,
				DoHProvider:      opts.DoHProvider,
				WordlistPath:     opts.WordlistPath,
				DiscoverWordlist: opts.DiscoverWordlist,
				DiscoverCT:       opts.DiscoverCT,
				ZoneTransfer:     opts.ZoneTransfer,
			},
			TLSContext: tlscheck.Context{
				ExpiryWarnDays:  opts.ExpiryWarnDays,
				CheckRevocation: opts.CheckRevocation,
				Enumerate:       opts.Enumerate,
				Timeout:         opts.Timeout,
			},
			Budget: opts.Budget,
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
			// Record the findings alongside the fingerprint so the file-based
			// history/dashboard can show past results, not just change (FR-R8).
			_ = hist.AppendEntry(history.Entry{
				Target:      tgt.Addr(),
				Fingerprint: currentFP,
				Findings:    res.Findings,
			})
		}
		rin := report.Input{
			Meta: report.Metadata{
				Operator: opts.Operator,
				When:     time.Now(),
				ToolName: "dnsvigil",
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
	case "pdf":
		ext = ".pdf"
	default:
		return "", fmt.Errorf("unknown export format %q (json|csv|md|html|pdf)", opts.ExportFormat)
	}
	if err := os.MkdirAll(opts.ReportDir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("dnsvigil-%s%s", rin.Meta.When.Format("20060102-150405"), ext)
	path := filepath.Join(opts.ReportDir, name)
	// Reports can carry sensitive findings; keep them owner-only like the audit
	// log and history (FR-A6), never world-readable.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
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
	case "pdf":
		werr = report.WritePDF(f, rin)
	}
	return path, werr
}
