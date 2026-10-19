package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/soc-tool/internal/core/finding"
)

// teaKey builds a KeyMsg sent when a rune or single key is typed.
func teaKey(name string) tea.KeyMsg {
	switch name {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(name)}
	}
}

func TestViewEmptyState(t *testing.T) {
	out := New().View()
	if !strings.Contains(out, "nettools") || !strings.Contains(out, "(no runs yet)") {
		t.Errorf("empty view unexpected: %s", out)
	}
}

func TestQuitViaQ(t *testing.T) {
	um, _ := New().Update(teaKey("q"))
	m := um.(Model)
	if v := m.View(); !strings.Contains(v, "closed") {
		t.Errorf("q should present the closed state: %s", v)
	}
}

func TestRunTargetBadPortShowsError(t *testing.T) {
	m := New()
	m.input = "example.test:99999"
	um, _ := m.Update(teaKey("enter"))
	m = um.(Model)
	if got := m.View(); m.err == "" || !strings.Contains(got, "error:") {
		t.Errorf("out-of-range port must surface an error (FR-S7); view=%s", got)
	}
	// No result entry is added for a target that failed to parse.
	if len(m.results) != 0 {
		t.Errorf("failed parse must not add a run: %+v", m.results)
	}
}

func TestRenderFindingsSeverityLabels(t *testing.T) {
	// FR-S5/S7: severity is conveyed by text labels, never colour alone.
	m := &Model{}
	out := m.renderFindings([]finding.Finding{
		{Kind: "tls-hostname", Severity: finding.SeverityCritical, What: "hostname mismatch", Because: "covers other host"},
		{Kind: "dns-a", Severity: finding.SeverityInfo, What: "a=1.2.3.4", Because: "A record exists"},
	})
	if !strings.Contains(out, "[CRITICAL]") || !strings.Contains(out, "[INFO]") {
		t.Errorf("findings must carry severity text labels: %s", out)
	}
	// Most severe appears first.
	if strings.Index(out, "[CRITICAL]") > strings.Index(out, "[INFO]") {
		t.Errorf("most severe finding must be listed first: %s", out)
	}
}
