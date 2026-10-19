package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/soc-tool/internal/core/engine"
	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/target"
)

func TestKeyboardFlowAcceptance(t *testing.T) {
	// FR-S4/S5/S7 plus FR-S1/S2 parity: a whole run is possible from the
	// keyboard alone — type a target, switch checks on, run, read severity
	// labelled findings, then quit — and every switch reaches the shared core.
	var gotCtx engine.Context
	var gotTarget target.Target
	original := runCheck
	runCheck = func(ctx engine.Context, tg target.Target) engine.Result {
		gotCtx, gotTarget = ctx, tg
		return engine.Result{Target: tg, Findings: []finding.Finding{
			{Kind: "tls-hostname", Severity: finding.SeverityCritical, What: "hostname mismatch",
				Because: "the certificate does not cover the requested host"},
			{Kind: "dns-a", Severity: finding.SeverityInfo, What: "a=192.0.2.10",
				Because: "an A record exists for the target"},
		}}
	}
	defer func() { runCheck = original }()

	var m tea.Model = New()

	// Every character of the target is a single key press.
	for _, r := range "example.test" {
		m, _ = m.Update(teaKey(string(r)))
	}
	if !strings.Contains(m.(Model).View(), "target: example.test") {
		t.Fatalf("typed target should render: %s", m.(Model).View())
	}

	// Switch two checks on with the keyboard; the state is readable as text.
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlD})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlO})
	view := m.(Model).View()
	if !strings.Contains(view, "deep(ctrl+d)=on") || !strings.Contains(view, "doh(ctrl+o)=on") {
		t.Fatalf("ctrl toggles should be visible as words: %s", view)
	}

	m, _ = m.Update(teaKey("enter"))
	view = m.(Model).View()
	for _, want := range []string{
		"example.test:443",
		"[CRITICAL] hostname mismatch",
		"because: the certificate does not cover the requested host",
		"[INFO] a=192.0.2.10",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("run output should contain %q:\n%s", want, view)
		}
	}
	if gotTarget.Addr() != "example.test:443" {
		t.Errorf("shared core received target %q", gotTarget.Addr())
	}
	if !gotCtx.DNSContext.Deep || !gotCtx.DNSContext.UseDoH || !gotCtx.TLSContext.Enumerate {
		t.Errorf("switches must reach the shared core (FR-S2): %+v", gotCtx)
	}
	if m.(Model).input != "" {
		t.Errorf("the entry should be cleared after a run, got %q", m.(Model).input)
	}

	// Navigation keys cannot move past the ends of the result list.
	m, _ = m.Update(teaKey("down"))
	m, _ = m.Update(teaKey("up"))
	m, _ = m.Update(teaKey("up"))
	if got := m.(Model).selected; got != 0 {
		t.Errorf("selected index = %d, want 0", got)
	}

	m, _ = m.Update(teaKey("q"))
	if v := m.(Model).View(); !strings.Contains(v, "closed") {
		t.Errorf("q should end the session: %s", v)
	}
}

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
