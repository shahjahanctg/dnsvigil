package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/dnsvigil/dnsvigil/internal/core/engine"
	"github.com/dnsvigil/dnsvigil/internal/core/finding"
	"github.com/dnsvigil/dnsvigil/internal/core/target"
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
	// The two toggles pressed above must reach the shared core; every other
	// switch stays at its off default (FR-S2).
	if !gotCtx.DNSContext.Deep || !gotCtx.DNSContext.UseDoH {
		t.Errorf("switches must reach the shared core (FR-S2): %+v", gotCtx)
	}
	if gotCtx.TLSContext.Enumerate || gotCtx.TLSContext.CheckRevocation ||
		gotCtx.DNSContext.DoHProvider != "" || gotCtx.DNSContext.WordlistPath != "" ||
		gotCtx.DNSContext.DiscoverWordlist || gotCtx.DNSContext.DiscoverCT || gotCtx.DNSContext.ZoneTransfer {
		t.Errorf("untouched switches must stay off: %+v", gotCtx)
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
	if !strings.Contains(out, "dnsvigil") || !strings.Contains(out, "(no runs yet)") {
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

func TestKeyboardSwitchesReachCore(t *testing.T) {
	// FR-S1/S2 parity: provider selection and the wordlist path are CLI flags,
	// so the TUI must be able to set them with the keyboard too.
	var gotCtx engine.Context
	original := runCheck
	runCheck = func(ctx engine.Context, tg target.Target) engine.Result {
		gotCtx = ctx
		return engine.Result{Target: tg}
	}
	defer func() { runCheck = original }()

	var m tea.Model = New()
	// ctrl+p cycles the DoH provider; ctrl+o turns the check on.
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlO})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
	if v := m.(Model).View(); !strings.Contains(v, "doh-provider(ctrl+p)=cloudflare") {
		t.Fatalf("provider cycle should be visible: %s", v)
	}
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
	if v := m.(Model).View(); !strings.Contains(v, "doh-provider(ctrl+p)=google") {
		t.Errorf("second ctrl+p should move to google: %s", v)
	}

	// ctrl+l opens the wordlist path; typing goes to the path, not the target.
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlL})
	for _, r := range "names.txt" {
		m, _ = m.Update(teaKey(string(r)))
	}
	if got := m.(Model).opts.WordlistPath; got != "names.txt" {
		t.Fatalf("wordlist path = %q, want names.txt", got)
	}
	if got := m.(Model).input; got != "" {
		t.Errorf("typing in path mode must not fill the target entry: %q", got)
	}
	if v := m.(Model).View(); !strings.Contains(v, "wordlist-file(ctrl+l)=names.txt") {
		t.Errorf("path entry should be visible: %s", v)
	}
	m, _ = m.Update(teaKey("enter"))
	if m.(Model).pathEntry {
		t.Error("enter should close path entry")
	}

	// A run carries both values into the shared core.
	for _, r := range "example.test" {
		m, _ = m.Update(teaKey(string(r)))
	}
	m, _ = m.Update(teaKey("enter"))
	if gotCtx.DNSContext.DoHProvider != "google" || gotCtx.DNSContext.WordlistPath != "names.txt" {
		t.Errorf("switches must reach the core: %+v", gotCtx.DNSContext)
	}
	if gotCtx.DNSContext.UseDoH != true {
		t.Errorf("doh should be on: %+v", gotCtx.DNSContext)
	}
}
