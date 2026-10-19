// Package webui is the embedded local web interface (FR-S1, FR-S2, FR-A8/A9).
// It renders the same finding.Finding model as the TUI and CLI — query:
// operator-supplied targets only; the server binds to loopback only.
package webui

import (
	"embed"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/soc-tool/internal/core/dnscheck"
	"github.com/soc-tool/internal/core/engine"
	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/history"
	"github.com/soc-tool/internal/core/report"
	"github.com/soc-tool/internal/core/target"
	"github.com/soc-tool/internal/core/tlscheck"
)

//go:embed assets
var assets embed.FS

const defaultAddr = "127.0.0.1:8089"

// Server is a local web interface instance.
type Server struct {
	addr string
	http *http.Server
}

type pageData struct {
	Title    string
	Targets  string
	Error    string
	Findings []finding.Finding
	History  []history.Entry
}

var pageTmpl = template.Must(template.ParseFS(assets, "assets/index.html"))

// New returns a Server bound to the loopback interface only (FR-A9).
func New(addr string) *Server {
	if addr == "" {
		addr = defaultAddr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		addr = defaultAddr
	} else if host != "127.0.0.1" && host != "localhost" {
		addr = "127.0.0.1:" + port
	}
	s := &Server{addr: addr}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/run", s.handleRun)
	s.http = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return s
}

// Start runs the server; it never returns on success.
func (s *Server) Start() error { return s.http.ListenAndServe() }

// Addr returns the bound address.
func (s *Server) Addr() string { return s.addr }

func (s *Server) render(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	entries, _ := history.New("").List() // FR-R8/R9: file-based history on the dashboard
	s.render(w, pageData{Title: "nettools — local web interface", History: entries})
}

// handleRun performs the checks for operator-supplied targets and renders the
// same findings the CLI report shows (FR-S2: shared core, no exclusive
// capability). Severity text labels are always shown (FR-S5).
func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.render(w, pageData{Title: "nettools", Error: err.Error()})
		return
	}
	raw := r.FormValue("targets")
	if strings.TrimSpace(raw) == "" {
		s.render(w, pageData{Title: "nettools", Error: "no targets provided"})
		return
	}

	var findings []finding.Finding
	runTargets := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tgt, err := target.ParseTarget(line)
		if err != nil {
			s.render(w, pageData{Title: "nettools", Targets: raw, Error: err.Error()})
			return
		}
		runTargets++
		res := engine.Run(engine.Context{
			DNSContext: dnscheck.Context{},
			TLSContext: tlscheck.Context{},
		}, tgt)
		findings = append(findings, res.Findings...)
	}
	if runTargets == 0 {
		s.render(w, pageData{Title: "nettools", Targets: raw, Error: "no targets provided"})
		return
	}

	s.render(w, pageData{
		Title:    "nettools — results",
		Targets:  raw,
		Findings: sortedFindings(findings),
	})
}

// sortedFindings lists findings most severe first, same order as the report.
func sortedFindings(in []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

// reportText returns the plain-text report for a results set, reused for the
// downloadable evidence output (FR-R1/R2 tiering: text today).
func ReportText(findings []finding.Finding, operator, targets string) (string, error) {
	return report.WriteTextString(report.Input{
		Meta: report.Metadata{
			Operator: operator,
			When:     time.Now(),
			ToolName: "nettools",
			Version:  "0.1.0-dev",
			Targets:  strings.Split(strings.ReplaceAll(targets, ",", "\n"), "\n"),
		},
		Findings: findings,
	})
}

// Run starts a blocking local web session.
func Run() {
	s := New(defaultAddr)
	fmt.Printf("webui serving on http://%s (loopback only; Ctrl-C ends it)\n", s.Addr())
	if err := s.Start(); err != nil {
		fmt.Printf("webui: %v\n", err)
	}
}
