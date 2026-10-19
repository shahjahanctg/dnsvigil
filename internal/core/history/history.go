// Package history keeps the file-based run history on disk — no database
// (decision D5) — and provides the previous-run fingerprint comparison used
// for certificate change detection (FR-C9, FR-R8).
package history

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/finding"
)

// DefaultDir is the relative location of the on-disk history.
const DefaultDir = ".dnsvigil"

// DefaultRetention is how long recorded runs are kept before the store prunes
// them automatically (30 days). A retention of 0 disables pruning.
const DefaultRetention = 30 * 24 * time.Hour

// Entry is one recorded run against one target.
type Entry struct {
	Target      string            `json:"target"`
	Fingerprint string            `json:"sha256,omitempty"`
	When        time.Time         `json:"ts"`
	Findings    []finding.Finding `json:"findings,omitempty"`
}

// fileMu serialises all history file access across Store instances. Stores are
// created per request, so a per-instance mutex cannot stop a concurrent append
// and prune/clear from interleaving.
var fileMu sync.Mutex

// Store is an append-only JSONL history file.
type Store struct {
	dir       string
	retention time.Duration
}

// Option configures a Store.
type Option func(*Store)

// WithRetention sets how long entries are kept. d <= 0 disables pruning.
func WithRetention(d time.Duration) Option {
	return func(s *Store) { s.retention = d }
}

// New returns a store rooted at dir ("" → DefaultDir). Retention defaults to
// DefaultRetention; pass WithRetention(0) to disable pruning.
func New(dir string, opts ...Option) *Store {
	if dir == "" {
		dir = DefaultDir
	}
	s := &Store{dir: dir, retention: DefaultRetention}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// path is the history file inside the store directory.
func (s *Store) path() string { return filepath.Join(s.dir, "history.jsonl") }

// Append records one run (thread-safe, never crashes the run).
func (s *Store) Append(target, fingerprint string) error {
	return s.AppendEntry(Entry{Target: target, Fingerprint: fingerprint, When: time.Now()})
}

// AppendEntry records one full run, including its findings when supplied. After
// writing it prunes entries older than the store's retention (best effort).
func (s *Store) AppendEntry(e Entry) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if e.When.IsZero() {
		e.When = time.Now()
	}
	f, err := os.OpenFile(s.path(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encErr := json.NewEncoder(f).Encode(e)
	closeErr := f.Close()
	if encErr != nil {
		return encErr
	}
	if closeErr != nil {
		return closeErr
	}
	if s.retention > 0 {
		// Retention must never fail a recorded run.
		_, _ = s.pruneLocked(time.Now().Add(-s.retention))
	}
	return nil
}

// Clear removes the whole recorded run history. A missing file is not an error.
func (s *Store) Clear() error {
	fileMu.Lock()
	defer fileMu.Unlock()
	if err := os.Remove(s.path()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ClearCriteria selects which runs a selective clear removes. A zero value
// (no target, no age) matches every entry — the "everything" case.
type ClearCriteria struct {
	// Target matches entries whose normalized target equals it. "" = any.
	Target string
	// OlderThan removes only entries strictly older than now-OlderThan.
	// <= 0 means "any age".
	OlderThan time.Duration
}

// matches reports whether e is selected by the criteria at time now.
func (c ClearCriteria) matches(e Entry, now time.Time) bool {
	if c.Target != "" && NormalizeTarget(e.Target) != c.Target {
		return false
	}
	if c.OlderThan > 0 {
		if e.When.IsZero() || !e.When.Before(now.Add(-c.OlderThan)) {
			return false
		}
	}
	return true
}

// CountMatching returns how many entries the criteria would remove, without
// changing anything (used for the web UI's pre-delete preview).
func (s *Store) CountMatching(c ClearCriteria) (int, error) {
	fileMu.Lock()
	defer fileMu.Unlock()
	entries, err := s.readLocked()
	if err != nil {
		return 0, err
	}
	now := time.Now()
	n := 0
	for _, e := range entries {
		if c.matches(e, now) {
			n++
		}
	}
	return n, nil
}

// ClearMatching removes the entries selected by the criteria and returns how
// many were deleted. Torn lines are dropped as a side effect of rewriting.
func (s *Store) ClearMatching(c ClearCriteria) (int, error) {
	fileMu.Lock()
	defer fileMu.Unlock()
	entries, err := s.readLocked()
	if err != nil {
		return 0, err
	}
	now := time.Now()
	keep := make([]Entry, 0, len(entries))
	deleted := 0
	for _, e := range entries {
		if c.matches(e, now) {
			deleted++
		} else {
			keep = append(keep, e)
		}
	}
	if deleted == 0 {
		return 0, nil
	}
	if len(keep) == 0 {
		if err := os.Remove(s.path()); err != nil && !os.IsNotExist(err) {
			return deleted, err
		}
		return deleted, nil
	}
	if err := s.writeLocked(keep); err != nil {
		return deleted, err
	}
	return deleted, nil
}

// NormalizeTarget reduces a target to its comparable base form: lower-cased and
// with any port removed. Subdomains are kept distinct (no public-suffix list).
func NormalizeTarget(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(t); err == nil {
		return host
	}
	return t
}

// TargetCount is one distinct target and how many runs it has.
type TargetCount struct {
	Target string
	Count  int
}

// Targets lists the distinct normalized targets in the history, sorted, with
// their run counts (for the web UI's target dropdown).
func (s *Store) Targets() ([]TargetCount, error) {
	fileMu.Lock()
	defer fileMu.Unlock()
	entries, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, e := range entries {
		if t := NormalizeTarget(e.Target); t != "" {
			counts[t]++
		}
	}
	out := make([]TargetCount, 0, len(counts))
	for t, n := range counts {
		out = append(out, TargetCount{Target: t, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out, nil
}

// Last returns the most recent fingerprint recorded for target.
func (s *Store) Last(target string) (string, bool, error) {
	fileMu.Lock()
	defer fileMu.Unlock()
	entries, err := s.readLocked()
	if err != nil {
		return "", false, err
	}
	var last *Entry
	for i := range entries {
		if entries[i].Target == target {
			last = &entries[i]
		}
	}
	if last == nil {
		return "", false, nil
	}
	return last.Fingerprint, true, nil
}

// List returns all entries, oldest first.
func (s *Store) List() ([]Entry, error) {
	fileMu.Lock()
	defer fileMu.Unlock()
	return s.readLocked()
}

// RecentFindings returns the findings from recorded runs, newest first, with
// each finding attributed to its run's target. limit <= 0 means no limit.
func (s *Store) RecentFindings(limit int) ([]Historical, error) {
	entries, err := s.List()
	if err != nil {
		return nil, err
	}
	var out []Historical
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		for _, f := range e.Findings {
			out = append(out, Historical{Target: e.Target, When: e.When, Finding: f})
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// readLocked parses the history file, skipping torn/partial lines. A missing
// file yields no entries and no error. Callers must hold fileMu.
func (s *Store) readLocked() ([]Entry, error) {
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
			continue // torn/partial lines are skipped, not fatal
		}
		out = append(out, e)
	}
	return out, nil
}

// writeLocked replaces the history file with entries, owner-only (FR-A6). It
// writes a temp file and renames it into place so a crash cannot half-write the
// history. Callers must hold fileMu.
func (s *Store) writeLocked(entries []Entry) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, "history-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	enc := json.NewEncoder(tmp)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, s.path()); err != nil {
		// Windows cannot rename over an existing file; remove then retry.
		if os.Remove(s.path()) == nil {
			if err = os.Rename(tmpName, s.path()); err == nil {
				return nil
			}
		}
		os.Remove(tmpName)
		return err
	}
	return nil
}

// pruneLocked drops entries older than cutoff and rewrites the file if anything
// was removed. Entries without a timestamp are kept. Callers must hold fileMu.
func (s *Store) pruneLocked(cutoff time.Time) (int, error) {
	entries, err := s.readLocked()
	if err != nil {
		return 0, err
	}
	keep := make([]Entry, 0, len(entries))
	dropped := 0
	for _, e := range entries {
		if e.When.IsZero() || !e.When.Before(cutoff) {
			keep = append(keep, e)
		} else {
			dropped++
		}
	}
	if dropped == 0 {
		return 0, nil
	}
	if err := s.writeLocked(keep); err != nil {
		return 0, err
	}
	return dropped, nil
}

// Historical is one finding from a past run, paired with its attribution.
type Historical struct {
	Target  string          `json:"target"`
	When    time.Time       `json:"ts"`
	Finding finding.Finding `json:"finding"`
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
