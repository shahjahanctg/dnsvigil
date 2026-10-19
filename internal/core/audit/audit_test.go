package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppendWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	log := New(path, time.Minute, false)

	when := time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)
	err := log.Append(Entry{
		Operator: "cli",
		Action:   "tls-check",
		Target:   "example.com:443",
		When:     when,
		Result:   "ok",
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	line := strings.TrimSpace(string(data))
	if !strings.Contains(line, `"op":"cli"`) ||
		!strings.Contains(line, `"act":"tls-check"`) ||
		!strings.Contains(line, `"tgt":"example.com:443"`) ||
		!strings.Contains(line, `"res":"ok"`) {
		t.Errorf("JSONL line missing expected fields: %s", line)
	}
	if strings.HasSuffix(line, "\n") {
		t.Errorf("JSONL line must not contain embedded newline")
	}
	if strings.Count(string(data), "\n") != 1 {
		t.Errorf("expected exactly one JSONL line, got: %q", string(data))
	}
}

func TestAppendTwoEntriesProducesTwoLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	log := New(path, time.Minute, false)

	if err := log.Append(Entry{Operator: "cli", Action: "a", When: time.Now()}); err != nil {
		t.Fatalf("first Append: %v", err)
	}
	if err := log.Append(Entry{Operator: "cli", Action: "b", When: time.Now()}); err != nil {
		t.Fatalf("second Append: %v", err)
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 JSONL lines, got %d: %q", len(lines), string(data))
	}
}

func TestAppendConcurrentWritesAreAllRecorded(t *testing.T) {
	// Append is documented as safe for concurrent use.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	log := New(path, time.Minute, false)

	const n = 20
	done := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			done <- log.Append(Entry{Operator: "cli", Action: "concurrent", When: time.Now(), Result: "r"})
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent Append: %v", err)
		}
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != n {
		t.Errorf("expected %d JSONL lines after concurrent writes, got %d", n, len(lines))
	}
}

func TestNewDefaultsToAuditJSONL(t *testing.T) {
	// New("") must fall back to audit.jsonl in the working directory.
	log := New("", time.Minute, false)
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Skipf("cannot get wd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Skipf("cannot chdir: %v", err)
	}
	defer os.Chdir(old) //nolint:errcheck

	if err := log.Append(Entry{Operator: "cli", Action: "default-path", When: time.Now()}); err != nil {
		t.Fatalf("Append with default path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.jsonl")); err != nil {
		t.Errorf("default path audit.jsonl was not created: %v", err)
	}
}

func TestRotateRemovesOldEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	log := New(path, time.Hour, true)

	old := time.Now().Add(-2 * time.Hour)
	fresh := time.Now()

	if err := log.Append(Entry{Operator: "cli", Action: "old", When: old}); err != nil {
		t.Fatalf("Append old: %v", err)
	}
	if err := log.Append(Entry{Operator: "cli", Action: "fresh", When: fresh}); err != nil {
		t.Fatalf("Append fresh: %v", err)
	}
	if err := log.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), `"act":"old"`) {
		t.Errorf("Rotate did not remove the entry older than keep: %s", string(data))
	}
	if !strings.Contains(string(data), `"act":"fresh"`) {
		t.Errorf("Rotate removed the fresh entry: %s", string(data))
	}
}

func TestAppendFailurePathProducesValidJSONL(t *testing.T) {
	// FR-A1/A3: the failure path (e.g. a target that failed to parse before
	// any checks ran) must still be logged as valid JSONL with the standard
	// fields, no result, and no findings array.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	log := New(path, time.Minute, false)

	when := time.Date(2026, time.October, 12, 9, 30, 0, 0, time.UTC)
	if err := log.Append(Entry{
		Operator: "cli",
		Action:   "parse-error",
		Target:   "not a target",
		When:     when,
	}); err != nil {
		t.Fatalf("Append parse-error entry: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	line := strings.TrimSpace(string(data))
	if !strings.Contains(line, `"op":"cli"`) ||
		!strings.Contains(line, `"act":"parse-error"`) ||
		!strings.Contains(line, `"tgt":"not a target"`) {
		t.Errorf("failure-path JSONL line missing expected fields: %s", line)
	}
	if strings.Contains(line, `"findings"`) {
		t.Errorf("failure-path entry must not carry findings: %s", line)
	}
	if strings.Count(string(data), "\n") != 1 || !strings.HasSuffix(string(data), "\n") {
		t.Errorf("file must contain exactly one complete JSONL line: %q", string(data))
	}
}

func TestRotateDisabledKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	log := New(path, time.Nanosecond, false) // rotate disabled

	if err := log.Append(Entry{Operator: "cli", Action: "kept", When: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := log.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"act":"kept"`) {
		t.Errorf("Rotate must not delete anything when disabled: %s", string(data))
	}
}
