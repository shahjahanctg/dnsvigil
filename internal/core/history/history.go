// Package history keeps the file-based run history on disk — no database
// (decision D5) — and provides the previous-run fingerprint comparison used
// for certificate change detection (FR-C9, FR-R8).
package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultDir is the relative location of the on-disk history.
const DefaultDir = ".nettools"

// Entry is one recorded run against one target.
type Entry struct {
	Target      string    `json:"target"`
	Fingerprint string    `json:"sha256"`
	When        time.Time `json:"ts"`
}

// Store is an append-only JSONL history file.
type Store struct {
	mu  sync.Mutex
	dir string
}

// New returns a store rooted at dir ("" → DefaultDir).
func New(dir string) *Store {
	if dir == "" {
		dir = DefaultDir
	}
	return &Store{dir: dir}
}

// path is the history file inside the store directory.
func (s *Store) path() string { return filepath.Join(s.dir, "history.jsonl") }

// Append records one run (thread-safe, never crashes the run).
func (s *Store) Append(target, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(Entry{Target: target, Fingerprint: fingerprint, When: time.Now()})
}

// Last returns the most recent fingerprint recorded for target.
func (s *Store) Last(target string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path())
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	var last *Entry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // torn/partial lines are skipped, not fatal
		}
		if e.Target == target {
			eCopy := e
			last = &eCopy
		}
	}
	if last == nil {
		return "", false, nil
	}
	return last.Fingerprint, true, nil
}

// List returns all entries, oldest first.
func (s *Store) List() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Entry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// ExtractFingerprint pulls the recorded SHA-256 out of the fingerprint
// finding produced by tlscheck.
func ExtractFingerprint(what string) string {
	const prefix = "sha256="
	if !strings.HasPrefix(what, prefix) {
		return ""
	}
	return strings.TrimPrefix(what, prefix)
}

// DetectChange compares the current fingerprint against the previous run's
// and returns the finding to display ("" means nothing to say).
func DetectChange(target, current, previous string) string {
	switch {
	case previous == "", current == "":
		return ""
	case previous == current:
		return "unchanged"
	case previous != current:
		return fmt.Sprintf("changed from %s to %s", short(previous), short(current))
	}
	return ""
}

func short(fp string) string {
	if len(fp) > 12 {
		return fp[:12] + "…"
	}
	return fp
}
