// Package tui is the Bubble Tea front-end over the shared core (FR-S1, FR-S3,
// FR-S4, FR-S5). It renders the same finding.Finding model the CLI and web UI
// consume; no capability is TUI-exclusive.
package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/soc-tool/internal/core/dnscheck"
	"github.com/soc-tool/internal/core/engine"
	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/target"
	"github.com/soc-tool/internal/core/tlscheck"
)

// runCheck is the shared-core entry point (FR-S2). Tests replace it so the
// keyboard acceptance flow runs offline against fixed findings.
var runCheck = engine.Run

// Options mirrors the check switches the CLI exposes as flags, so the TUI has
// no exclusive capability (FR-S1/S2). Zero value = the default run.
type Options struct {
	Deep             bool
	UseDoH           bool
	DoHProvider      string
	WordlistPath     string
	DiscoverWordlist bool
	DiscoverCT       bool
	ZoneTransfer     bool
	AXFR             bool
	Enumerate        bool
	CheckRevocation  bool
	Budget          string
}

// Model is the single Bubble Tea state model.
type Model struct {
	input    string // current target entry
	results  []runResult
	selected int // index into results of the detail view
	quitting bool
	err      string
	opts     Options
	// pathEntry is true while the operator is typing the wordlist path.
	pathEntry bool
}

// runResult is one target's merged result plus its canonical address.
type runResult struct {
	address  string
	findings []finding.Finding
	errText  string
}

// New returns the initialised model.
func New() Model { return Model{} }

// Init implements tea.Model.
func (m Model) Init() tea.Cmd { return nil }
var doHProviders = []string{"", "cloudflare", "google", "quad9"}

// nextDoHProvider rotates through the provider list (ctrl+p).
func nextDoHProvider(current string) string {
	for i, p := range doHProviders {
		if p == current {
			return doHProviders[(i+1)%len(doHProviders)]
		}
	}
	return doHProviders[0]
}

// New returns the initialised model.

// Update handles input keys; 'enter' runs the check, 'q' quits (FR-S4:
// keyboard-only). Check execution is synchronous and bounded per run.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+p":
			m.opts.DoHProvider = nextDoHProvider(m.opts.DoHProvider)
			return m, nil
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "enter":
			m.runTarget(strings.TrimSpace(m.input))
			m.input = ""
			return m, nil
		case "backspace":
			if len(m.input) > 0 {
				m.input = m.input[:len(m.input)-1]
			}
			return m, nil
		case "up":
			if m.selected > 0 {
				m.selected--
			}
			return m, nil
		case "down":
			if m.selected < len(m.results)-1 {
				m.selected++
			}
			return m, nil
		// Check switches use ctrl combinations so a printable letter can still
		// be typed into the target entry (FR-S4: keyboard only).
		case "ctrl+d":
			m.opts.Deep = !m.opts.Deep
			return m, nil
		case "ctrl+o":
			m.opts.UseDoH = !m.opts.UseDoH
			return m, nil
		case "ctrl+w":
			m.opts.DiscoverWordlist = !m.opts.DiscoverWordlist
			return m, nil
		case "ctrl+t":
			m.opts.DiscoverCT = !m.opts.DiscoverCT
			return m, nil
		case "ctrl+x":
			m.opts.ZoneTransfer = !m.opts.ZoneTransfer
			return m, nil
		case "ctrl+b":
			m.opts.Budget = ""
			return m, nil
		case "ctrl+r":
			m.opts.CheckRevocation = !m.opts.CheckRevocation
			return m, nil
		case "ctrl+e":
			m.opts.Enumerate = !m.opts.Enumerate
			return m, nil
		case "ctrl+l":
			// Enter the wordlist path; while it is open, typing appends to the
			// path rather than the target entry.
			m.pathEntry = true
			return m, nil
		case "esc":
			m.pathEntry = false
			return m, nil
		}
		// Printable characters append to the target entry.
		m.input += msg.String()
		return m, nil
	}
	return m, nil
}

// runTarget parses and checks a single operator-supplied target (FR-S8:
// operator-supplied targets only).
func (m *Model) runTarget(addr string) {
	if addr == "" {
		return
	}
	t, err := target.ParseTarget(addr)
	if err != nil {
		m.err = err.Error()
		return
	}
	m.err = ""
	res := runCheck(m.context(), t)
	entry := runResult{address: t.Addr(), findings: res.Findings}
	if res.Error != nil {
		entry.errText = res.Error.Error()
	}
	m.results = append(m.results, entry)
	m.selected = len(m.results) - 1
}

// context turns the current switches into a shared-core run context.
func (m Model) context() engine.Context {
	return engine.Context{
		DNSContext: dnscheck.Context{
			Deep:             m.opts.Deep,
			UseDoH:           m.opts.UseDoH,
			DiscoverWordlist: m.opts.DiscoverWordlist,
			DiscoverCT:       m.opts.DiscoverCT,
			ZoneTransfer:     m.opts.ZoneTransfer,
		},
		TLSContext: tlscheck.Context{Enumerate: m.opts.Deep},
	}
}

// optionsLine renders every switch with its state in words, so the interface
// never relies on colour or position to convey meaning (FR-S5).
func (m Model) optionsLine() string {
	onoff := func(on bool) string {
		if on {
			return "on"
		}
		return "off"
	}
	return fmt.Sprintf(
		"checks: deep(ctrl+d)=%s doh(ctrl+o)=%s wordlist(ctrl+w)=%s ct-log(ctrl+t)=%s axfr(ctrl+x)=%s\n\n",
		onoff(m.opts.Deep), onoff(m.opts.UseDoH), onoff(m.opts.DiscoverWordlist),
		onoff(m.opts.DiscoverCT), onoff(m.opts.ZoneTransfer))
}

// View renders the whole interface with text labels only (FR-S5: no meaning
// conveyed by colour alone; the plain output works without a colour terminal).
func (m Model) View() string {
	if m.quitting {
		return "nettools closed.\n"
	}
	var b strings.Builder
	b.WriteString("nettools — certificate + DNS audit\n")
	b.WriteString("type a target (host or host:port), press enter; q quits\n")
	b.WriteString(m.optionsLine())

	b.WriteString("target: ")
	b.WriteString(m.input)
	b.WriteString("_\n\n")

	if m.err != "" {
		b.WriteString("error: " + m.err + "\n\n")
	}

	if len(m.results) == 0 {
		b.WriteString("(no runs yet)\n")
		return b.String()
	}

	for i, r := range m.results {
		cursor := " "
		if i == m.selected {
			cursor = ">"
		}
		b.WriteString(fmt.Sprintf("%s %s\n", cursor, r.address))
		if i != m.selected {
			continue
		}
		if r.errText != "" {
			b.WriteString("  connection error: " + r.errText + "\n")
		}
		b.WriteString(m.renderFindings(r.findings))
	}
	return b.String()
}

// renderFindings prints every finding with severity + plain-language reason
// (FR-S7's interface requirement) grouped most severe first, like the report.
func (m *Model) renderFindings(fs []finding.Finding) string {
	var b strings.Builder
	if len(fs) == 0 {
		b.WriteString("  (no findings)\n")
		return b.String()
	}
	ordered := make([]finding.Finding, len(fs))
	copy(ordered, fs)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Severity < ordered[j].Severity })
	// Most severe first: iterate reversed.
	for i := len(ordered) - 1; i >= 0; i-- {
		f := ordered[i]
		b.WriteString(fmt.Sprintf("  [%s] %s\n", f.Severity.Name(), f.What))
		if f.Because != "" {
			b.WriteString("    because: " + f.Because + "\n")
		}
	}
	return b.String()
}

// Run starts the TUI session.
func Run() {
	if _, err := tea.NewProgram(New()).Run(); err != nil {
		fmt.Printf("tui error: %v\n", err)
	}
}
