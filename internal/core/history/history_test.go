package history

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/finding"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "history-test")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	return dir
}

func TestDetectChange(t *testing.T) {
	if changed := DetectChange("t", "fp1", ""); changed != "" {
		t.Errorf("no previous run must produce no finding text, got %q", changed)
	}
	if changed := DetectChange("t", "fp1", "fp1"); changed != "unchanged" {
		t.Errorf("same fingerprint should report unchanged, got %q", changed)
	}
	result := DetectChange("t", strings.Repeat("a", 64), "b")
	if !strings.HasPrefix(result, "changed from") {
		t.Errorf("different fingerprint should report change, got %q", result)
	}
}

func TestExtractFingerprint(t *testing.T) {
	if got := ExtractFingerprint("sha256=deadbeef"); got != "deadbeef" {
		t.Errorf("ExtractFingerprint = %q", got)
	}
	if got := ExtractFingerprint("subject=x"); got != "" {
		t.Errorf("non-fingerprint What must extract nothing, got %q", got)
	}
}

func TestListSkipsTornLines(t *testing.T) {
	dir := tempDir(t)
	store := New(dir)
	_ = store.Append("a:443", "fp1")
	_ = store.Append("b:443", "fp2")

	// Corrupt the file with a torn line (simulated crash mid-write).
	p := dir + "/history.jsonl"
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	// Append a partial JSON line (truncated mid-write).
	partial := []byte(`{"target":"c:443"}{"tar`)
	newData := append(data, partial...)
	if err := os.WriteFile(p, newData, 0o600); err != nil {
		t.Fatalf("write torn line: %v", err)
	}

	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// List should keep the two valid entries and skip torn ones.
	if len(entries) != 2 {
		t.Errorf("List should keep the two valid entries and skip torn ones, got %d: %+v", len(entries), entries)
	}
}

func TestEntriesCarryTime(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	before := time.Now().Add(-time.Second)
	_ = s.Append("t:443", "fp")
	entries, _ := s.List()
	if len(entries) != 1 || entries[0].When.Before(before) {
		t.Errorf("entry timestamp not recorded: %+v", entries)
	}
}

func TestAppendEntryStoresFindings(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	want := []finding.Finding{
		{Kind: "dns-a", Severity: finding.SeverityInfo, What: "a=192.0.2.1", Because: "A record exists"},
		{Kind: "tls-expiry", Severity: finding.SeverityCritical, What: "certificate expired", Because: "notAfter in the past"},
	}
	if err := s.AppendEntry(Entry{Target: "example.test:443", Fingerprint: "fp1", Findings: want}); err != nil {
		t.Fatalf("AppendEntry: %v", err)
	}

	hist, err := s.RecentFindings(0)
	if err != nil {
		t.Fatalf("RecentFindings: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("RecentFindings returned %d, want 2: %+v", len(hist), hist)
	}
	if hist[0].Target != "example.test:443" || hist[0].Finding.Kind != "dns-a" {
		t.Errorf("findings should carry target attribution: %+v", hist[0])
	}
}

func TestRecentFindingsNewestFirstAndLimit(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	_ = s.AppendEntry(Entry{Target: "old:443", When: time.Now().Add(-time.Hour), Findings: []finding.Finding{{Kind: "dns-a", Severity: finding.SeverityInfo, What: "old"}}})
	_ = s.AppendEntry(Entry{Target: "new:443", When: time.Now(), Findings: []finding.Finding{
		{Kind: "dns-a", Severity: finding.SeverityInfo, What: "new-1"},
		{Kind: "dns-mx", Severity: finding.SeverityInfo, What: "new-2"},
	}})

	hist, err := s.RecentFindings(2)
	if err != nil {
		t.Fatalf("RecentFindings: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("limit not applied, got %d", len(hist))
	}
	// The most recent run's findings must come before the older run's.
	if hist[0].Target != "new:443" || hist[1].Target != "new:443" {
		t.Errorf("newest run's findings must come first: %+v", hist)
	}
}

func TestClearRemovesHistory(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	_ = s.AppendEntry(Entry{Target: "example.test:443", Fingerprint: "fp1", Findings: []finding.Finding{
		{Kind: "dns-a", Severity: finding.SeverityInfo, What: "a=192.0.2.1"},
	}})

	if err := s.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List after Clear: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Clear should leave no entries, got %+v", entries)
	}
	if _, err := os.Stat(dir + "/history.jsonl"); !os.IsNotExist(err) {
		t.Errorf("Clear should remove history.jsonl, stat err = %v", err)
	}
	// Reading a cleared store must not error (change detection still works).
	if _, ok, err := s.Last("example.test:443"); err != nil || ok {
		t.Errorf("Last after Clear = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestClearMissingFileIsNoop(t *testing.T) {
	s := New(tempDir(t))
	if err := s.Clear(); err != nil {
		t.Errorf("Clear on empty store should be a no-op, got %v", err)
	}
}

func TestAppendEntryWithoutFindingsStillReadsBack(t *testing.T) {
	// Older entries written via Append have no findings; List must still parse
	// them so fingerprint history keeps working (FR-C8/C9).
	dir := tempDir(t)
	s := New(dir)
	_ = s.Append("legacy:443", "fp-legacy")
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Fingerprint != "fp-legacy" || len(entries[0].Findings) != 0 {
		t.Errorf("legacy entry should round-trip without findings: %+v", entries)
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"Example.COM:443":      "example.com",
		"example.com":          "example.com",
		"[2001:db8::1]:443":    "2001:db8::1",
		"sub.example.org:8443": "sub.example.org",
		"":                     "",
	}
	for in, want := range cases {
		if got := NormalizeTarget(in); got != want {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClearMatchingByTarget(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	_ = s.Append("alpha.example:443", "a1")
	_ = s.Append("alpha.example:443", "a2")
	_ = s.Append("beta.example:443", "b1")

	n, err := s.ClearMatching(ClearCriteria{Target: "alpha.example"})
	if err != nil {
		t.Fatalf("ClearMatching: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}
	entries, _ := s.List()
	if len(entries) != 1 || entries[0].Target != "beta.example:443" {
		t.Errorf("only beta should remain: %+v", entries)
	}
}

func TestClearMatchingByAge(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	_ = s.AppendEntry(Entry{Target: "old:443", When: time.Now().Add(-10 * 24 * time.Hour)})
	_ = s.AppendEntry(Entry{Target: "new:443", When: time.Now()})

	n, err := s.ClearMatching(ClearCriteria{OlderThan: 24 * time.Hour})
	if err != nil {
		t.Fatalf("ClearMatching: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1", n)
	}
	entries, _ := s.List()
	if len(entries) != 1 || entries[0].Target != "new:443" {
		t.Errorf("only the recent run should remain: %+v", entries)
	}
}

func TestClearMatchingTargetAndAge(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	_ = s.AppendEntry(Entry{Target: "alpha:443", When: time.Now().Add(-10 * 24 * time.Hour)})
	_ = s.AppendEntry(Entry{Target: "alpha:443", When: time.Now()})
	_ = s.AppendEntry(Entry{Target: "beta:443", When: time.Now().Add(-10 * 24 * time.Hour)})

	n, err := s.ClearMatching(ClearCriteria{Target: "alpha", OlderThan: 24 * time.Hour})
	if err != nil {
		t.Fatalf("ClearMatching: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1 (only alpha's old run)", n)
	}
	entries, _ := s.List()
	if len(entries) != 2 {
		t.Errorf("two runs should remain: %+v", entries)
	}
}

func TestClearMatchingEverythingRemovesFile(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	_ = s.Append("a:443", "a")
	_ = s.Append("b:443", "b")

	n, err := s.ClearMatching(ClearCriteria{})
	if err != nil {
		t.Fatalf("ClearMatching: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}
	if _, err := os.Stat(dir + "/history.jsonl"); !os.IsNotExist(err) {
		t.Errorf("clearing everything should remove the file, stat err = %v", err)
	}
}

func TestCountMatchingAgreesWithClear(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	_ = s.AppendEntry(Entry{Target: "alpha:443", When: time.Now().Add(-10 * 24 * time.Hour)})
	_ = s.AppendEntry(Entry{Target: "alpha:443", When: time.Now()})
	_ = s.AppendEntry(Entry{Target: "beta:443", When: time.Now()})

	c := ClearCriteria{Target: "alpha", OlderThan: 24 * time.Hour}
	got, err := s.CountMatching(c)
	if err != nil {
		t.Fatalf("CountMatching: %v", err)
	}
	deleted, err := s.ClearMatching(c)
	if err != nil {
		t.Fatalf("ClearMatching: %v", err)
	}
	if got != deleted {
		t.Errorf("CountMatching = %d but ClearMatching deleted %d", got, deleted)
	}
}

func TestAutoPruneOnAppend(t *testing.T) {
	dir := tempDir(t)
	s := New(dir, WithRetention(24*time.Hour))
	_ = s.AppendEntry(Entry{Target: "old:443", When: time.Now().Add(-48 * time.Hour), Fingerprint: "old"})
	// A fresh append triggers retention pruning.
	_ = s.AppendEntry(Entry{Target: "new:443", When: time.Now(), Fingerprint: "new"})

	entries, _ := s.List()
	if len(entries) != 1 || entries[0].Target != "new:443" {
		t.Errorf("append should prune entries older than retention: %+v", entries)
	}
}

func TestRetentionDisabledKeepsOldEntries(t *testing.T) {
	dir := tempDir(t)
	s := New(dir, WithRetention(0))
	_ = s.AppendEntry(Entry{Target: "old:443", When: time.Now().Add(-100 * 24 * time.Hour)})
	_ = s.AppendEntry(Entry{Target: "new:443", When: time.Now()})

	entries, _ := s.List()
	if len(entries) != 2 {
		t.Errorf("retention 0 must keep everything: %+v", entries)
	}
}

func TestTargetsDistinctAndCounted(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	_ = s.Append("Example.com:443", "a")
	_ = s.Append("example.com", "b")
	_ = s.Append("beta.example:443", "c")

	targets, err := s.Targets()
	if err != nil {
		t.Fatalf("Targets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("want 2 distinct targets, got %+v", targets)
	}
	if targets[0].Target != "beta.example" || targets[0].Count != 1 {
		t.Errorf("first target = %+v, want beta.example x1", targets[0])
	}
	if targets[1].Target != "example.com" || targets[1].Count != 2 {
		t.Errorf("second target = %+v, want example.com x2", targets[1])
	}
}
