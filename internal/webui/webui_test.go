package webui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/engine"
	"github.com/dnsvigil/dnsvigil/internal/core/finding"
	"github.com/dnsvigil/dnsvigil/internal/core/history"
	"github.com/dnsvigil/dnsvigil/internal/core/settings"
	"github.com/dnsvigil/dnsvigil/internal/core/target"
)

// stubRun replaces the engine with fixed findings for offline handler tests.
func stubRun(t *testing.T) {
	t.Helper()
	original := runEngine
	runEngine = func(ctx engine.Context, tg target.Target) engine.Result {
		return engine.Result{Target: tg, Findings: []finding.Finding{
			{Kind: "tls-hostname", Severity: finding.SeverityCritical, What: "hostname mismatch", Because: "does not cover the target"},
			{Kind: "dns-a", Severity: finding.SeverityInfo, What: "a=192.0.2.10", Because: "an A record exists"},
		}}
	}
	t.Cleanup(func() { runEngine = original })
}

// exportForm builds a form body carrying targets, as the browser would submit.
func exportForm(targets string) *strings.Reader {
	return strings.NewReader(url.Values{"targets": []string{targets}}.Encode())
}

func TestHandleHomeRendersForm(t *testing.T) {
	s := New("127.0.0.1:0")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	s.handleHome(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("home status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `<form action="/run" method="POST">`) ||
		!strings.Contains(body, `name="targets"`) {
		t.Errorf("home page missing form: %s", body)
	}
}

func TestHandleRunEmptyTargetsErrors(t *testing.T) {
	s := New("127.0.0.1:0")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/run", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleRun(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("run status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no targets provided") {
		t.Errorf("empty run should error clearly: %s", w.Body.String())
	}
}

func TestHandleRunCommentOnlyErrors(t *testing.T) {
	// FR-C1: comments and blanks must not count as targets.
	s := New("127.0.0.1:0")
	w := httptest.NewRecorder()
	body := strings.NewReader("targets=%23+only+a+comment")
	r := httptest.NewRequest(http.MethodPost, "/run", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleRun(w, r)

	if !strings.Contains(w.Body.String(), "no targets provided") {
		t.Errorf("comment-only run should error: %s", w.Body.String())
	}
}

func TestHandleRunGetRedirects(t *testing.T) {
	s := New("127.0.0.1:0")
	w := httptest.NewRecorder()
	s.handleRun(w, httptest.NewRequest(http.MethodGet, "/run", nil))
	if w.Code != http.StatusSeeOther {
		t.Errorf("GET /run status = %d, want 303", w.Code)
	}
}

func TestServerBindsLoopbackOnly(t *testing.T) {
	// FR-A9: the web UI is local-only; a non-loopback bind request must be
	// forced back to 127.0.0.1.
	s := New("0.0.0.0:9999")
	if !strings.HasPrefix(s.Addr(), "127.0.0.1:") {
		t.Errorf("Server.Addr() = %q, want 127.0.0.1:...", s.Addr())
	}
}

func TestExportRoutesCarryFormatAndAttachment(t *testing.T) {
	// FR-R2: the same report writers the CLI uses are downloadable from the
	// web UI, each with the right content type and a download filename.
	stubRun(t)
	cases := []struct {
		format   string
		wantType string
		wantBody string
	}{
		{"json", "application/json", `"findings"`},
		{"csv", "text/csv", "hostname mismatch"},
		{"md", "text/markdown", "| Severity |"},
		{"html", "text/html; charset=utf-8", "<table>"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			s := New("127.0.0.1:0")
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/export/"+tc.format, exportForm("example.test"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			s.handleExport(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
			}
			if got := w.Header().Get("Content-Type"); got != tc.wantType {
				t.Errorf("Content-Type = %q, want %q", got, tc.wantType)
			}
			if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
				t.Errorf("Content-Disposition = %q, want attachment", cd)
			}
			if !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Errorf("body missing %q:\n%s", tc.wantBody, w.Body.String())
			}
		})
	}
}

func TestExportRejectsUnknownFormatAndEmptyTargets(t *testing.T) {
	stubRun(t)
	s := New("127.0.0.1:0")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/export/pdf", exportForm("example.test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleExport(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("unknown format status = %d, want 400", w.Code)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/export/json", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleExport(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty targets status = %d, want 400", w.Code)
	}
}

func TestHomeShowsExportButtons(t *testing.T) {
	s := New("127.0.0.1:0")
	s.historyDir = t.TempDir()
	w := httptest.NewRecorder()
	s.handleHome(w, httptest.NewRequest(http.MethodGet, "/", nil))
	body := w.Body.String()
	for _, want := range []string{"Download JSON", "Download CSV", "Download Markdown", "Download HTML", "/export/"} {
		if !strings.Contains(body, want) {
			t.Errorf("home page missing %q", want)
		}
	}
}

// seedHistory writes one run to dir and returns dir.
func seedHistory(t *testing.T, target string, findings ...finding.Finding) string {
	t.Helper()
	dir := t.TempDir()
	if err := history.New(dir).AppendEntry(history.Entry{
		Target: target, When: time.Now(), Findings: findings,
	}); err != nil {
		t.Fatalf("seed history: %v", err)
	}
	return dir
}

func TestHomeShowsRecentActivityPreview(t *testing.T) {
	// FR-R8/R9: the dashboard previews past runs and links to the full history.
	dir := seedHistory(t, "old.example:443", finding.Finding{
		Kind: "tls-expiry", Severity: finding.SeverityCritical, What: "certificate expired", Because: "notAfter in the past",
	})

	s := New("127.0.0.1:0")
	s.historyDir = dir
	w := httptest.NewRecorder()
	s.handleHome(w, httptest.NewRequest(http.MethodGet, "/", nil))
	body := w.Body.String()

	for _, want := range []string{"Recent activity", "old.example:443", `href="/history"`, "View all 1 run(s)"} {
		if !strings.Contains(body, want) {
			t.Errorf("home preview missing %q:\n%s", want, body)
		}
	}
}

func TestHistoryPageShowsRunsAndFindings(t *testing.T) {
	// FR-R8/R9: the history page lists runs newest-first and exposes findings.
	dir := seedHistory(t, "old.example:443", finding.Finding{
		Kind: "tls-expiry", Severity: finding.SeverityCritical, What: "certificate expired", Because: "notAfter in the past",
	})

	s := New("127.0.0.1:0")
	s.historyDir = dir
	w := httptest.NewRecorder()
	s.handleHistory(w, httptest.NewRequest(http.MethodGet, "/history", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("history status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"History", "old.example:443", "certificate expired", "Clear history", "/history/clear"} {
		if !strings.Contains(body, want) {
			t.Errorf("history page missing %q:\n%s", want, body)
		}
	}
}

func TestHistoryPageEmptyState(t *testing.T) {
	s := New("127.0.0.1:0")
	s.historyDir = t.TempDir()
	w := httptest.NewRecorder()
	s.handleHistory(w, httptest.NewRequest(http.MethodGet, "/history", nil))
	body := w.Body.String()
	if !strings.Contains(body, "No history yet") {
		t.Errorf("empty history should say so:\n%s", body)
	}
	if strings.Contains(body, "Clear history") {
		t.Errorf("no clear button when there is nothing to clear:\n%s", body)
	}
}

func TestHistoryPageFiltersByTarget(t *testing.T) {
	dir := t.TempDir()
	store := history.New(dir)
	_ = store.AppendEntry(history.Entry{Target: "alpha.example:443", When: time.Now()})
	_ = store.AppendEntry(history.Entry{Target: "beta.example:443", When: time.Now()})

	s := New("127.0.0.1:0")
	s.historyDir = dir
	w := httptest.NewRecorder()
	s.handleHistory(w, httptest.NewRequest(http.MethodGet, "/history?target=alpha", nil))
	body := w.Body.String()
	if !strings.Contains(body, "alpha.example:443") {
		t.Errorf("filter should keep the matching target:\n%s", body)
	}
	if strings.Contains(body, "beta.example:443") {
		t.Errorf("filter should drop non-matching targets:\n%s", body)
	}
}

func TestClearHistoryRequiresPost(t *testing.T) {
	s := New("127.0.0.1:0")
	s.historyDir = t.TempDir()
	w := httptest.NewRecorder()
	s.handleHistoryClear(w, httptest.NewRequest(http.MethodGet, "/history/clear", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /history/clear status = %d, want 405", w.Code)
	}
}

func TestClearHistoryPreviewCountsAndDeletesNothing(t *testing.T) {
	// Without confirm=yes the request is a dry run: it shows the count and
	// removes nothing.
	dir := seedHistory(t, "old.example:443")
	s := New("127.0.0.1:0")
	s.historyDir = dir

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/history/clear", strings.NewReader("mode=all"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleHistoryClear(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "This will delete 1 run(s).") || !strings.Contains(body, "Confirm delete") {
		t.Errorf("preview should show the count and a confirm button:\n%s", body)
	}
	if _, err := os.Stat(dir + "/history.jsonl"); err != nil {
		t.Errorf("preview must not delete anything: %v", err)
	}
}

func TestClearHistoryRejectsCrossOrigin(t *testing.T) {
	dir := seedHistory(t, "old.example:443")
	s := New("127.0.0.1:0")
	s.historyDir = dir

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/history/clear", strings.NewReader("mode=all&confirm=yes"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://evil.example")
	s.handleHistoryClear(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin clear status = %d, want 403", w.Code)
	}
	if _, err := os.Stat(dir + "/history.jsonl"); err != nil {
		t.Errorf("history must survive a cross-origin clear: %v", err)
	}
}

func TestClearHistoryRejectsBadSelection(t *testing.T) {
	dir := seedHistory(t, "old.example:443")
	s := New("127.0.0.1:0")
	s.historyDir = dir

	for _, body := range []string{
		"mode=bogus&confirm=yes",
		"mode=target&confirm=yes",     // target mode needs a target
		"mode=age&age=3h&confirm=yes", // 3h is not an offered preset
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/history/clear", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		s.handleHistoryClear(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, w.Code)
		}
	}
	if _, err := os.Stat(dir + "/history.jsonl"); err != nil {
		t.Errorf("rejected clears must not delete: %v", err)
	}
}

func TestClearHistoryEverythingRedirects(t *testing.T) {
	dir := seedHistory(t, "old.example:443")
	s := New("127.0.0.1:0")
	s.historyDir = dir

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/history/clear", strings.NewReader("mode=all&confirm=yes"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://example.com") // matches httptest default Host
	s.handleHistoryClear(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("clear status = %d, want 303 (body %s)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/history?cleared=1" {
		t.Errorf("redirect = %q, want /history?cleared=1", loc)
	}
	if _, err := os.Stat(dir + "/history.jsonl"); !os.IsNotExist(err) {
		t.Errorf("history.jsonl should be gone, stat err = %v", err)
	}

	// The cleared state renders an empty page with the deletion count.
	w = httptest.NewRecorder()
	s.handleHistory(w, httptest.NewRequest(http.MethodGet, "/history?cleared=1", nil))
	body := w.Body.String()
	if !strings.Contains(body, "Deleted 1 run(s).") || !strings.Contains(body, "No history yet") {
		t.Errorf("cleared history page should confirm and show empty state:\n%s", body)
	}
}

func TestClearHistoryByTarget(t *testing.T) {
	dir := t.TempDir()
	store := history.New(dir)
	_ = store.AppendEntry(history.Entry{Target: "alpha.example:443", When: time.Now()})
	_ = store.AppendEntry(history.Entry{Target: "alpha.example:443", When: time.Now()})
	_ = store.AppendEntry(history.Entry{Target: "beta.example:443", When: time.Now()})

	s := New("127.0.0.1:0")
	s.historyDir = dir
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/history/clear", strings.NewReader("mode=target&target=alpha.example&confirm=yes"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleHistoryClear(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (body %s)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/history?cleared=2" {
		t.Errorf("redirect = %q, want /history?cleared=2", loc)
	}
	entries, _ := history.New(dir).List()
	if len(entries) != 1 || entries[0].Target != "beta.example:443" {
		t.Errorf("only beta should remain: %+v", entries)
	}
}

func TestClearHistoryByAge(t *testing.T) {
	dir := t.TempDir()
	store := history.New(dir)
	_ = store.AppendEntry(history.Entry{Target: "old.example:443", When: time.Now().Add(-10 * 24 * time.Hour)})
	_ = store.AppendEntry(history.Entry{Target: "new.example:443", When: time.Now()})

	s := New("127.0.0.1:0")
	s.historyDir = dir
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/history/clear", strings.NewReader("mode=age&age=168h&confirm=yes"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleHistoryClear(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (body %s)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/history?cleared=1" {
		t.Errorf("redirect = %q, want /history?cleared=1", loc)
	}
	entries, _ := history.New(dir).List()
	if len(entries) != 1 || entries[0].Target != "new.example:443" {
		t.Errorf("only the recent run should remain: %+v", entries)
	}
}

func TestHistoryPageShowsClearControls(t *testing.T) {
	dir := t.TempDir()
	_ = history.New(dir).AppendEntry(history.Entry{Target: "Example.com:443", When: time.Now()})
	s := New("127.0.0.1:0")
	s.historyDir = dir

	w := httptest.NewRecorder()
	s.handleHistory(w, httptest.NewRequest(http.MethodGet, "/history", nil))
	body := w.Body.String()
	for _, want := range []string{
		`name="mode"`, "Everything", "By target (domain)", "Older than", "Target + older than",
		`name="target"`, "example.com (1)", `name="age"`, "30 days",
		"Runs older than 30 days are pruned automatically.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("history clear controls missing %q:\n%s", want, body)
		}
	}
}

func TestRunRecordsFindingsInHistory(t *testing.T) {
	// FR-C8/C9/R8: a web run persists its findings so change detection and the
	// dashboard both see them.
	stubRun(t)
	dir := t.TempDir()
	s := New("127.0.0.1:0")
	s.historyDir = dir

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/run", exportForm("example.test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleRun(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("run status = %d", w.Code)
	}

	entries, err := history.New(dir).List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || len(entries[0].Findings) != 2 {
		t.Fatalf("run findings not recorded: %+v", entries)
	}
}

func TestSettingsPageRendersForm(t *testing.T) {
	s := New("127.0.0.1:0")
	s.historyDir = t.TempDir()

	w := httptest.NewRecorder()
	s.handleSettings(w, httptest.NewRequest(http.MethodGet, "/settings", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("settings status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		`action="/settings"`, `name="operator"`, `name="timeout"`, `name="history-retention"`,
		`name="resolver"`, `name="deep"`, `name="doh-provider"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page missing %q:\n%s", want, body)
		}
	}
}

func TestSettingsSavePersistsAndRedirects(t *testing.T) {
	dir := t.TempDir()
	s := New("127.0.0.1:0")
	s.historyDir = dir

	form := url.Values{
		"operator":          {"alice"},
		"timeout":           {"7s"},
		"expiry-warn":       {"45"},
		"budget":            {"90s"},
		"audit-retention":   {"48h"},
		"history-retention": {"240h"},
		"resolver":          {"9.9.9.9:53"},
		"second-resolver":   {"1.1.1.1:53"},
		"doh-provider":      {"quad9"},
		"deep":              {"1"},
		"enumerate":         {"1"},
	}
	r := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleSettings(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (body %s)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/settings?saved=1" {
		t.Errorf("redirect = %q, want /settings?saved=1", loc)
	}

	got, found, err := settings.Load(dir)
	if err != nil || !found {
		t.Fatalf("settings not persisted: found=%v err=%v", found, err)
	}
	if got.Operator != "alice" || time.Duration(got.Timeout) != 7*time.Second ||
		got.ExpiryWarnDays != 45 || time.Duration(got.Budget) != 90*time.Second ||
		time.Duration(got.AuditRetention) != 48*time.Hour ||
		time.Duration(got.HistoryRetention) != 240*time.Hour ||
		got.Resolver != "9.9.9.9:53" || got.SecondResolver != "1.1.1.1:53" ||
		got.DoHProvider != "quad9" || !got.Deep || !got.Enumerate {
		t.Errorf("saved settings mismatch: %+v", got)
	}

	info, err := os.Stat(settings.Path(dir))
	if err != nil {
		t.Fatalf("stat settings: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("settings file perm = %o, want 600 (FR-A6)", perm)
	}
}

func TestSettingsRejectsCrossOrigin(t *testing.T) {
	s := New("127.0.0.1:0")
	s.historyDir = t.TempDir()

	r := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader("operator=x"))
	r.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	s.handleSettings(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestSettingsRejectsBadDuration(t *testing.T) {
	dir := t.TempDir()
	s := New("127.0.0.1:0")
	s.historyDir = dir

	r := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader("timeout=soon"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleSettings(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "invalid timeout") {
		t.Fatalf("bad duration: status %d body %s", w.Code, w.Body.String())
	}
	if _, found, _ := settings.Load(dir); found {
		t.Errorf("a bad form must not write a settings file")
	}
}

func TestHomePrefillsSettingsDefaults(t *testing.T) {
	dir := t.TempDir()
	st := settings.Default()
	st.Deep = true
	st.Budget = settings.Duration(33 * time.Second)
	if err := settings.Save(dir, st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	s := New("127.0.0.1:0")
	s.historyDir = dir

	w := httptest.NewRecorder()
	s.handleHome(w, httptest.NewRequest(http.MethodGet, "/", nil))
	body := w.Body.String()
	if !strings.Contains(body, `name="deep" value="1" checked`) {
		t.Errorf("home did not pre-check deep from settings:\n%s", body)
	}
	if !strings.Contains(body, `value="33s"`) {
		t.Errorf("home did not prefill budget from settings:\n%s", body)
	}
}

func TestStoreUsesSettingsRetention(t *testing.T) {
	// A settings file's retention is authoritative over the startup value.
	dir := t.TempDir()
	st := settings.Default()
	st.HistoryRetention = settings.Duration(0) // disable pruning
	if err := settings.Save(dir, st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	s := NewWithRetention("127.0.0.1:0", 24*time.Hour)
	s.historyDir = dir

	old := history.Entry{Target: "old.example:443", When: time.Now().Add(-10 * 24 * time.Hour)}
	if err := s.store().AppendEntry(old); err != nil {
		t.Fatalf("AppendEntry: %v", err)
	}
	entries, _ := history.New(dir).List()
	if len(entries) != 1 {
		t.Errorf("settings retention (0 = disabled) should keep the old run, got %+v", entries)
	}
}

func TestExportDoesNotWriteToDisk(t *testing.T) {
	// Exports stream to the browser; they must not create history files.
	stubRun(t)
	dir := t.TempDir()
	s := New("127.0.0.1:0")
	s.historyDir = dir

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/export/json", exportForm("example.test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleExport(w, r)

	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("export must not write history files, found %v", entries)
	}
}
