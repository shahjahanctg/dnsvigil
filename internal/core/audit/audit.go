package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/soc-tool/internal/core/finding"
)

// auditEntry is a deprecated struct kept for older callers.
// Use audit.Entry directly; both share the same JSON shape for compatibility.
type auditEntry = Entry

// Entry is one audit event.
type Entry struct {
	Operator string            `json:"op"`
	Action   string            `json:"act"`
	Target   string            `json:"tgt,omitempty"`
	When     time.Time         `json:"ts"`
	Result   string            `json:"res,omitempty"`
	Findings []finding.Finding `json:"findings,omitempty"`
}

// Log is a file-based JSONL audit log.
type Log struct {
	mu     sync.Mutex
	path   string
	rotate bool
	keep   time.Duration
}

// New returns a log writer. If rotate is false, files are never deleted.
func New(path string, keep time.Duration, rotate bool) *Log {
	if path == "" {
		path = "audit.jsonl"
	}
	return &Log{path: path, rotate: rotate, keep: keep}
}

// Append writes one entry as a JSONL line. It is safe for concurrent use.
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if err := enc.Encode(e); err != nil {
		return err
	}
	return nil
}

// Rotate removes entries older than keep, if rotation is enabled.
func (l *Log) Rotate() error {
	if !l.rotate || l.keep == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return pruneLinesOlderThan(l.path, l.keep)
}

// pruneLinesOlderThan is a simple, portable line-retention pass.
// Full production implementations would use a proper log rotation library.
func pruneLinesOlderThan(path string, keep time.Duration) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	now := time.Now()
	var kept []string
	for _, line := range splitLines(string(data)) {
		tm, err := readTimeFromLine(line)
		if err != nil {
			kept = append(kept, line)
			continue
		}
		if now.Sub(tm) <= keep {
			kept = append(kept, line)
		}
	}
	return os.WriteFile(path, bytesJoin(kept), 0o600)
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func readTimeFromLine(line string) (time.Time, error) {
	var e struct {
		When time.Time `json:"ts"`
	}
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		return time.Time{}, err
	}
	return e.When, nil
}

func bytesJoin(lines []string) []byte {
	if len(lines) == 0 {
		return []byte{}
	}
	var b []byte
	for _, l := range lines {
		b = append(b, l...)
		b = append(b, '\n')
	}
	return b
}
