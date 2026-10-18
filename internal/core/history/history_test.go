package history

import (
	"os"
	"strings"
	"testing"
	"time"
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