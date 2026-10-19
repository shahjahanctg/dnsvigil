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

// Model is the single Bubble Tea state model.
type Model struct {
	input    string // current target entry
	results  []runResult
	selected int // index into results of the detail view
	quitting bool
	err      string
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

// Update handles input keys; 'enter' runs the check, 'q' quits (FR-S4:
// keyboard-only). Check execution is synchronous and bounded per run.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
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
	res := engine.Run(engine.Context{
		DNSContext: dnscheck.Context{},
		TLSContext: tlscheck.Context{},
	}, t)
	entry := runResult{address: t.Addr(), findings: res.Findings}
	if res.Error != nil {
		entry.errText = res.Error.Error()
	}
	m.results = append(m.results, entry)
	m.selected = len(m.results) - 1
}

// View renders the whole interface with text labels only (FR-S5: no meaning
// conveyed by colour alone; the plain output works without a colour terminal).
func (m Model) View() string {
	if m.quitting {
		return "nettools closed.\n"
	}
	var b strings.Builder
	b.WriteString("nettools — certificate + DNS audit\n")
	b.WriteString("type a target (host or host:port), press enter; q quits\n\n")

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
