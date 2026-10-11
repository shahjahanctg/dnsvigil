package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/soc-tool/internal/core/audit"
	"github.com/soc-tool/internal/core/dnscheck"
	"github.com/soc-tool/internal/core/engine"
	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/target"
	"github.com/soc-tool/internal/core/tlscheck"
)

var (
	headless    = false
	showVersion = false
	version     = "dev"
)

func main() {
	fs := flag.NewFlagSet("nettools", flag.ExitOnError)
	fs.BoolVar(&headless, "headless", false, "headless / CLI mode")
	fs.BoolVar(&showVersion, "version", false, "print version")

	fs.Parse(os.Args[1:])

	if showVersion {
		fmt.Printf("nettools version %s\n", version)
		os.Exit(0)
	}
	if headless {
		runHeadless(fs.Args())
		return
	}
	fmt.Fprintf(os.Stderr, "usage: nettools --headless host1 host2 ...\n")
	os.Exit(1)
}

func severityIdx(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 4
	case finding.SeverityHigh:
		return 3
	case finding.SeverityMedium:
		return 2
	case finding.SeverityLow:
		return 1
	default:
		return 0
	}
}

func parseHeadlessInputs(args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no targets provided; usage: nettools --headless host1 host2 ...")
	}
	return args, nil
}

func printReport(findings []finding.Finding, result *engine.Result) {
	fmt.Println("=== Findings ===")
	for _, f := range findings {
		fmt.Printf("  [%s] %s\n", f.Severity.Name(), f.What)
		if f.Because != "" {
			fmt.Printf("    because: %s\n", f.Because)
		}
		if f.Detail != "" {
			fmt.Printf("    detail:  %s\n", f.Detail)
		}
	}
	if result != nil {
		fmt.Printf("---\ntarget: %s\n", result.Target.Addr())
		if result.Error != nil {
			fmt.Printf("error: %v\n", result.Error)
		} else {
			fmt.Printf("checkedAt: %s\n", time.Now().Format(time.RFC3339))
		}
	}
	if len(findings) > 0 {
		jsonData, err := json.MarshalIndent(findings, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json marshal: %v\n", err)
			return
		}
		fmt.Printf("\nJSON:\n%s\n", string(jsonData))
	}
}

func runHeadless(args []string) {
	fs := flag.NewFlagSet("nettools headless", flag.ExitOnError)
	fs.Parse(args)

	inputs, err := parseHeadlessInputs(fs.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "headless: %v\n", err)
		os.Exit(2)
	}

	log := audit.New("audit.jsonl", 5*time.Minute, false)

	for _, inp := range inputs {
		tgt, err := target.ParseTarget(inp)
		if err != nil {
			log.Append(audit.Entry{Operator: "cli", Action: "parse-error", Target: inp, When: time.Now()})
			fmt.Fprintf(os.Stderr, "headless: %v\n", err)
			continue
		}

		ctx := engine.Context{
			DNSContext: dnscheck.Context{},
			TLSContext: tlscheck.Context{},
		}

		res := engine.Run(ctx, tgt)

		sorted := make([]finding.Finding, len(res.Findings))
		copy(sorted, res.Findings)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Severity < sorted[j].Severity
		})

		printReport(sorted, &res)
		log.Append(audit.Entry{Operator: "cli", Action: "tls-check", Target: tgt.Addr(), When: time.Now(), Result: "ok"})
	}

	fmt.Fprintf(os.Stderr, "audit log: audit.jsonl\n")
}
