// Package webui is the embedded local web interface (FR-S1, FR-S2, FR-A8/A9).
// It renders the same finding.Finding model as the TUI and CLI — query:
// operator-supplied targets only; the server binds to loopback only.
package webui

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/dnscheck"
	"github.com/dnsvigil/dnsvigil/internal/core/engine"
	"github.com/dnsvigil/dnsvigil/internal/core/finding"
	"github.com/dnsvigil/dnsvigil/internal/core/history"
	"github.com/dnsvigil/dnsvigil/internal/core/report"
	"github.com/dnsvigil/dnsvigil/internal/core/settings"
	"github.com/dnsvigil/dnsvigil/internal/core/target"
	"github.com/dnsvigil/dnsvigil/internal/core/tlscheck"
)

//go:embed assets
var assets embed.FS

// runEngine is the shared-core entry point. Tests replace it so the web
// handlers can be exercised offline against fixed findings (FR-S2).
var runEngine = engine.Run

const defaultAddr = "127.0.0.1:8089"

// Server is a local web interface instance.
type Server struct {
	addr string
	http *http.Server
	// historyDir roots the run history on disk. "" means history.DefaultDir
	// (the working directory). Tests point it at a temp dir.
	historyDir string
	// retention is how long run history is kept before automatic pruning.
	retention time.Duration
}

type pageData struct {
	Title    string
	Targets  string
	Error    string
	Findings []finding.Finding

	// View selects the page body: "" renders the run form/results, "history"
	// renders the dedicated history page (FR-R8/R9).
	View string

	// History holds the runs shown on the current page (newest first): the
	// last few on the home dashboard, or the full (filtered) set on /history.
	History []historyRow

	// History page summary and controls.
	Filter        string
	TotalRuns     int
	UniqueTargets int
	HasRange      bool
	FirstWhen     time.Time
	LastWhen      time.Time
	ClearedCount  int
	Retention     string

	// Selective clear: dropdown state and the pre-delete preview.
	ClearTargets   []history.TargetCount
	Ages           []agePreset
	ClearMode      string
	ClearTarget    string
	ClearAge       string
	PreviewPending bool
	PreviewCount   int

	// Settings page: current values and the "saved" banner.
	Settings settings.Settings
	Saved    bool

	// Check switches, mirroring the CLI flags so the web interface has no
	// exclusive capability and a re-render keeps the operator's selection
	// (FR-S1/S2).
	Deep             bool
	Enumerate        bool
	CheckRevocation  bool
	UseDoH           bool
	DoHProvider      string
	WordlistPath     string
	Budget           string
	DiscoverWordlist bool
	DiscoverCT       bool
	ZoneTransfer     bool
}

// historyRow is one recorded run prepared for display, with a shortened
// fingerprint so the table stays readable.
type historyRow struct {
	When        time.Time
	Target      string
	Fingerprint string
	Findings    []finding.Finding
}

// ShortFP is the display form of the fingerprint, elided in the middle.
func (h historyRow) ShortFP() string {
	if len(h.Fingerprint) > 16 {
		return h.Fingerprint[:16] + "…"
	}
	return h.Fingerprint
}

// historyPreview is how many recent runs the home dashboard shows.
const historyPreview = 5

// historyMaxRows caps the /history table so a large history stays fast.
const historyMaxRows = 200

// agePreset is one "older than" choice in the clear-history age dropdown. Value
// is a Go duration string so parsing and rendering stay in sync.
type agePreset struct {
	Value string
	Label string
}

var agePresets = []agePreset{
	{"24h", "1 day"},
	{"168h", "7 days"},
	{"720h", "30 days"},
	{"2160h", "90 days"},
	{"8760h", "1 year"},
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
	s := &Server{addr: addr, retention: history.DefaultRetention}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/run", s.handleRun)
	mux.HandleFunc("/export/", s.handleExport)
	mux.HandleFunc("/history", s.handleHistory)
	mux.HandleFunc("/history/clear", s.handleHistoryClear)
	mux.HandleFunc("/settings", s.handleSettings)
	s.http = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return s
}

// NewWithRetention is New with an explicit history retention (0 disables
// automatic pruning).
func NewWithRetention(addr string, retention time.Duration) *Server {
	s := New(addr)
	s.retention = retention
	return s
}

// effectiveRetention is the history retention in force: a settings file (edited
// on the Settings page) wins, else the value passed at startup
// (--history-retention).
func (s *Server) effectiveRetention() time.Duration {
	if st, found, err := settings.Load(s.historyDir); err == nil && found {
		return time.Duration(st.HistoryRetention)
	}
	return s.retention
}

// store returns the history store for this server, honouring its retention.
func (s *Server) store() *history.Store {
	return history.New(s.historyDir, history.WithRetention(s.effectiveRetention()))
}

// loadSettings returns the shared run defaults, falling back to built-ins.
func (s *Server) loadSettings() settings.Settings {
	st, _, err := settings.Load(s.historyDir)
	if err != nil {
		return settings.Default()
	}
	return st
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
	entries, _ := s.store().List() // FR-R8/R9: file-based history on the dashboard
	rows := toHistoryRows(entries)
	total := len(rows)
	if len(rows) > historyPreview {
		rows = rows[:historyPreview]
	}
	// The shared settings file seeds the run form so both interfaces agree on
	// defaults (FR-S1/S2).
	st := s.loadSettings()
	s.render(w, pageData{
		Title:            "dnsvigil — local web interface",
		History:          rows,
		TotalRuns:        total,
		Deep:             st.Deep,
		Enumerate:        st.Enumerate,
		CheckRevocation:  st.CheckRevocation,
		UseDoH:           st.UseDoH,
		DoHProvider:      st.DoHProvider,
		Budget:           st.Budget.String(),
		DiscoverWordlist: st.DiscoverWordlist,
		DiscoverCT:       st.DiscoverCT,
		ZoneTransfer:     st.ZoneTransfer,
	})
}

// historyPage carries the history page's ephemeral UI state across the clear
// preview/confirm round-trip.
type historyPage struct {
	filter      string
	clearMode   string
	clearTarget string
	clearAge    string
	preview     bool
	count       int
	cleared     int
}

// handleHistory renders the dedicated history page: every recorded run, newest
// first, each expandable to its findings, a target filter, and the selective
// clear controls (FR-R8/R9).
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cleared := 0
	if v := r.URL.Query().Get("cleared"); v != "" {
		cleared, _ = strconv.Atoi(v)
	}
	s.renderHistory(w, historyPage{filter: r.URL.Query().Get("target"), cleared: cleared})
}

// renderHistory loads the history and renders the history page with any
// in-progress clear state (filter, preview, or success count).
func (s *Server) renderHistory(w http.ResponseWriter, hp historyPage) {
	store := s.store()
	entries, err := store.List()
	if err != nil {
		s.render(w, pageData{View: "history", Title: "dnsvigil — history", Error: err.Error()})
		return
	}
	targets, _ := store.Targets()

	rows := toHistoryRows(entries)
	filter := strings.TrimSpace(hp.filter)
	if filter != "" {
		rows = filterRows(rows, filter)
	}
	total := len(rows)
	unique := map[string]struct{}{}
	for _, row := range rows {
		unique[row.Target] = struct{}{}
	}
	if len(rows) > historyMaxRows {
		rows = rows[:historyMaxRows]
	}

	mode := hp.clearMode
	if mode == "" {
		mode = "all"
	}
	age := hp.clearAge
	if age == "" {
		age = "720h"
	}
	data := pageData{
		View:           "history",
		Title:          "dnsvigil — history",
		History:        rows,
		Filter:         filter,
		TotalRuns:      total,
		UniqueTargets:  len(unique),
		ClearedCount:   hp.cleared,
		Retention:      humanRetention(s.effectiveRetention()),
		ClearTargets:   targets,
		Ages:           agePresets,
		ClearMode:      mode,
		ClearTarget:    hp.clearTarget,
		ClearAge:       age,
		PreviewPending: hp.preview,
		PreviewCount:   hp.count,
	}
	if len(rows) > 0 {
		data.HasRange = true
		data.FirstWhen = rows[len(rows)-1].When // oldest shown
		data.LastWhen = rows[0].When            // newest shown
	}
	s.render(w, data)
}

// handleHistoryClear powers the selective clear. Without confirm=yes it is a
// preview: it counts what the chosen criteria would remove and re-renders the
// page for confirmation. With confirm=yes it deletes and redirects. POST-only,
// and cross-origin submissions are rejected.
func (s *Server) handleHistoryClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mode := r.FormValue("mode")
	target := history.NormalizeTarget(r.FormValue("target"))
	age := strings.TrimSpace(r.FormValue("age"))
	criteria, err := clearCriteria(mode, target, age)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.FormValue("confirm") != "yes" {
		n, err := s.store().CountMatching(criteria)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.renderHistory(w, historyPage{clearMode: mode, clearTarget: target, clearAge: age, preview: true, count: n})
		return
	}

	n, err := s.store().ClearMatching(criteria)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/history?cleared=%d", n), http.StatusSeeOther)
}

// clearCriteria turns the operator's dropdown choices into a history filter.
func clearCriteria(mode, target, age string) (history.ClearCriteria, error) {
	switch mode {
	case "all":
		return history.ClearCriteria{}, nil
	case "target":
		if target == "" {
			return history.ClearCriteria{}, fmt.Errorf("choose a target to clear")
		}
		return history.ClearCriteria{Target: target}, nil
	case "age":
		d, err := parseAge(age)
		if err != nil {
			return history.ClearCriteria{}, err
		}
		return history.ClearCriteria{OlderThan: d}, nil
	case "target-age":
		if target == "" {
			return history.ClearCriteria{}, fmt.Errorf("choose a target to clear")
		}
		d, err := parseAge(age)
		if err != nil {
			return history.ClearCriteria{}, err
		}
		return history.ClearCriteria{Target: target, OlderThan: d}, nil
	default:
		return history.ClearCriteria{}, fmt.Errorf("unknown clear mode %q", mode)
	}
}

// parseAge accepts only the offered age presets so a request cannot smuggle a
// surprising window.
func parseAge(age string) (time.Duration, error) {
	for _, p := range agePresets {
		if p.Value == age {
			return time.ParseDuration(age)
		}
	}
	return 0, fmt.Errorf("choose a valid age")
}

// humanRetention renders a retention window for the history page note.
func humanRetention(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	if d%(24*time.Hour) == 0 {
		days := int(d / (24 * time.Hour))
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	return d.String()
}

// handleSettings renders and saves the shared run defaults (FR-S1/S2). File
// paths are deliberately absent so a browser form cannot point the tool at
// arbitrary files.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.render(w, pageData{
			View:     "settings",
			Title:    "dnsvigil — settings",
			Settings: s.loadSettings(),
			Saved:    r.URL.Query().Get("saved") == "1",
		})
	case http.MethodPost:
		if !sameOrigin(r) {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		st, err := settingsFromForm(r)
		if err != nil {
			s.render(w, pageData{View: "settings", Title: "dnsvigil — settings", Settings: s.loadSettings(), Error: err.Error()})
			return
		}
		if err := settings.Save(s.historyDir, st); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// settingsFromForm reads the settings form. Blank duration fields keep their
// default rather than becoming zero.
func settingsFromForm(r *http.Request) (settings.Settings, error) {
	def := settings.Default()
	s := def
	s.Operator = strings.TrimSpace(r.FormValue("operator"))
	if s.Operator == "" {
		s.Operator = def.Operator
	}
	dur := func(name string, fallback settings.Duration) (settings.Duration, error) {
		raw := strings.TrimSpace(r.FormValue(name))
		if raw == "" {
			return fallback, nil
		}
		d, err := time.ParseDuration(raw)
		if err != nil {
			return 0, fmt.Errorf("invalid %s %q: %v", name, raw, err)
		}
		return settings.Duration(d), nil
	}
	var err error
	if s.Timeout, err = dur("timeout", def.Timeout); err != nil {
		return s, err
	}
	if s.Budget, err = dur("budget", def.Budget); err != nil {
		return s, err
	}
	if s.AuditRetention, err = dur("audit-retention", def.AuditRetention); err != nil {
		return s, err
	}
	if s.HistoryRetention, err = dur("history-retention", def.HistoryRetention); err != nil {
		return s, err
	}
	if v := strings.TrimSpace(r.FormValue("expiry-warn")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return s, fmt.Errorf("invalid expiry-warn %q", v)
		}
		s.ExpiryWarnDays = n
	}
	s.Resolver = strings.TrimSpace(r.FormValue("resolver"))
	s.SecondResolver = strings.TrimSpace(r.FormValue("second-resolver"))
	s.DoHProvider = strings.TrimSpace(r.FormValue("doh-provider"))
	s.Deep = r.FormValue("deep") != ""
	s.Enumerate = r.FormValue("enumerate") != ""
	s.CheckRevocation = r.FormValue("check-revocation") != ""
	s.UseDoH = r.FormValue("doh") != ""
	s.DiscoverWordlist = r.FormValue("discover") != ""
	s.DiscoverCT = r.FormValue("discover-ct") != ""
	s.ZoneTransfer = r.FormValue("axfr") != ""
	return s, nil
}

// sameOrigin reports whether a state-changing request came from the local UI.
// Non-browser clients (curl, tests) send no Origin and are allowed; a browser
// cross-site request is rejected.
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// toHistoryRows converts stored entries (oldest first) into display rows, newest
// first.
func toHistoryRows(entries []history.Entry) []historyRow {
	rows := make([]historyRow, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		rows = append(rows, historyRow{
			When:        e.When,
			Target:      e.Target,
			Fingerprint: e.Fingerprint,
			Findings:    e.Findings,
		})
	}
	return rows
}

// filterRows keeps rows whose target contains the filter, case-insensitively.
func filterRows(rows []historyRow, filter string) []historyRow {
	needle := strings.ToLower(filter)
	out := rows[:0:0]
	for _, row := range rows {
		if strings.Contains(strings.ToLower(row.Target), needle) {
			out = append(out, row)
		}
	}
	return out
}

// handleExport writes the current run's findings to the requested format as a
// download. It accepts the same form fields as /run so the browser can hand
// back the operator's current selection (FR-R1/R2).
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	format := strings.TrimPrefix(r.URL.Path, "/export/")
	ext, ctype, ok := exportFormat(format)
	if !ok {
		http.Error(w, "unknown export format (json|csv|md|html)", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw := r.FormValue("targets")
	if strings.TrimSpace(raw) == "" {
		http.Error(w, "no targets provided", http.StatusBadRequest)
		return
	}

	st := s.loadSettings()
	operator := strings.TrimSpace(r.FormValue("operator"))
	if operator == "" {
		operator = st.Operator
	}
	checks := parseCheckSwitches(r)
	findings, err := s.runChecks(raw, checks, st)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	in := report.Input{
		Meta: report.Metadata{
			Operator: operator,
			When:     time.Now(),
			ToolName: "dnsvigil",
			Version:  "0.1.0-dev",
			Targets:  splitTargetLines(raw),
		},
		Findings: sortedFindings(findings),
	}

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=dnsvigil-%s.%s", time.Now().Format("20060102-150405"), ext))
	if err := writeExport(w, format, in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// exportFormat maps an operator-facing format name to its file extension and
// content type. ok is false for anything unsupported.
func exportFormat(format string) (ext, ctype string, ok bool) {
	switch strings.ToLower(format) {
	case "json":
		return "json", "application/json", true
	case "csv":
		return "csv", "text/csv", true
	case "md", "markdown":
		return "md", "text/markdown", true
	case "html":
		return "html", "text/html; charset=utf-8", true
	default:
		return "", "", false
	}
}

// writeExport dispatches to the shared report writers so the web download and
// the CLI export produce identical bytes (FR-S1/S2).
func writeExport(w io.Writer, format string, in report.Input) error {
	switch strings.ToLower(format) {
	case "json":
		return report.WriteJSON(w, in)
	case "csv":
		return report.WriteCSV(w, in)
	case "md", "markdown":
		return report.WriteMarkdown(w, in)
	case "html":
		return report.WriteHTML(w, in)
	default:
		return fmt.Errorf("unknown export format %q", format)
	}
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
		s.render(w, pageData{Title: "dnsvigil", Error: err.Error()})
		return
	}
	raw := r.FormValue("targets")
	if strings.TrimSpace(raw) == "" {
		s.render(w, pageData{Title: "dnsvigil", Error: "no targets provided"})
		return
	}

	st := s.loadSettings()
	checks := parseCheckSwitches(r)
	// The settings budget is the default; a form value overrides it. An
	// unusable budget is reported rather than silently ignored.
	budgetText := strings.TrimSpace(r.FormValue("budget"))
	checks.budget = time.Duration(st.Budget)
	if budgetText != "" {
		parsed, err := time.ParseDuration(budgetText)
		if err != nil {
			s.render(w, pageData{Title: "dnsvigil", Targets: raw, Error: "invalid budget " + budgetText + ": " + err.Error(), Budget: budgetText, WordlistPath: checks.wordlistPath, DoHProvider: checks.doHProvider})
			return
		}
		checks.budget = parsed
	}

	findings, err := s.runChecks(raw, checks, st)
	if err != nil {
		s.render(w, pageData{Title: "dnsvigil", Targets: raw, Error: err.Error(), Deep: checks.deep, Enumerate: checks.enumerate, CheckRevocation: checks.checkRevocation, UseDoH: checks.useDoH, DiscoverWordlist: checks.discoverWordlist, DiscoverCT: checks.discoverCT, ZoneTransfer: checks.zoneTransfer})
		return
	}

	// Record this run with its full findings so the dashboard can show history
	// beyond fingerprints (FR-R8/R9) and change detection keeps working (FR-C9).
	store := s.store()
	_ = store.AppendEntry(history.Entry{
		Target:      raw,
		Fingerprint: fingerprintOf(findings),
		When:        time.Now(),
		Findings:    findings,
	})

	s.render(w, pageData{
		Title:            "dnsvigil — results",
		Targets:          raw,
		Findings:         sortedFindings(findings),
		Deep:             checks.deep,
		Enumerate:        checks.enumerate,
		CheckRevocation:  checks.checkRevocation,
		UseDoH:           checks.useDoH,
		DiscoverWordlist: checks.discoverWordlist,
		DiscoverCT:       checks.discoverCT,
		ZoneTransfer:     checks.zoneTransfer,
		DoHProvider:      checks.doHProvider,
		WordlistPath:     checks.wordlistPath,
		Budget:           budgetText,
	})
}

// parseCheckSwitches reads the check toggles and their values from a submitted
// form, so /run and /export interpret the same fields identically (FR-S1/S2).
func parseCheckSwitches(r *http.Request) checkSwitches {
	return checkSwitches{
		deep:             r.FormValue("deep") != "",
		enumerate:        r.FormValue("enumerate") != "",
		checkRevocation:  r.FormValue("check-revocation") != "",
		useDoH:           r.FormValue("doh") != "",
		discoverWordlist: r.FormValue("discover") != "",
		discoverCT:       r.FormValue("discover-ct") != "",
		zoneTransfer:     r.FormValue("axfr") != "",
		doHProvider:      r.FormValue("doh-provider"),
		wordlistPath:     strings.TrimSpace(r.FormValue("wordlist")),
	}
}

// splitTargetLines parses the textarea into clean targets, honouring blank
// lines and # comments (FR-C1).
func splitTargetLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// runChecks runs the shared engine over each operator-supplied target and
// returns the combined findings (FR-S2: no interface-exclusive capability).
func (s *Server) runChecks(raw string, checks checkSwitches, st settings.Settings) ([]finding.Finding, error) {
	lines := splitTargetLines(raw)
	if len(lines) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}
	var findings []finding.Finding
	for _, line := range lines {
		tgt, err := target.ParseTarget(line)
		if err != nil {
			return nil, err
		}
		res := runEngine(engine.Context{
			DNSContext: dnscheck.Context{
				CustomResolver:   st.Resolver,
				SecondResolver:   st.SecondResolver,
				Timeout:          time.Duration(st.Timeout),
				Deep:             checks.deep,
				UseDoH:           checks.useDoH,
				DoHProvider:      checks.doHProvider,
				WordlistPath:     checks.wordlistPath,
				DiscoverWordlist: checks.discoverWordlist,
				DiscoverCT:       checks.discoverCT,
				ZoneTransfer:     checks.zoneTransfer,
			},
			TLSContext: tlscheck.Context{
				ExpiryWarnDays:  st.ExpiryWarnDays,
				Timeout:         time.Duration(st.Timeout),
				Enumerate:       checks.enumerate,
				CheckRevocation: checks.checkRevocation,
			},
			Budget: checks.budget,
		}, tgt)
		findings = append(findings, res.Findings...)
	}
	return findings, nil
}

// fingerprintOf pulls the recorded SHA-256 out of the fingerprint finding, the
// same value the CLI records for change detection (FR-C8/C9).
func fingerprintOf(fs []finding.Finding) string {
	for _, f := range fs {
		if f.Kind == "tls-fingerprint" {
			return history.ExtractFingerprint(f.What)
		}
	}
	return ""
}

// checkSwitches is the set of check toggles a form submission carries, plus
// the values that go with them.
type checkSwitches struct {
	deep             bool
	enumerate        bool
	checkRevocation  bool
	useDoH           bool
	discoverWordlist bool
	discoverCT       bool
	zoneTransfer     bool
	doHProvider      string
	wordlistPath     string
	budget           time.Duration
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
			ToolName: "dnsvigil",
			Version:  "0.1.0-dev",
			Targets:  strings.Split(strings.ReplaceAll(targets, ",", "\n"), "\n"),
		},
		Findings: findings,
	})
}

// Run starts a blocking local web session, keeping run history for retention
// (0 disables automatic pruning).
func Run(retention time.Duration) {
	s := NewWithRetention(defaultAddr, retention)
	fmt.Printf("webui serving on http://%s (loopback only; Ctrl-C ends it)\n", s.Addr())
	if err := s.Start(); err != nil {
		fmt.Printf("webui: %v\n", err)
	}
}
