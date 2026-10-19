// Package settings holds the operator's on-disk run defaults, shared by the
// CLI and the web UI so both interfaces behave the same (FR-S1/S2). It is a
// small JSON file under the working directory — no database (decision D5).
package settings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/engine"
	"github.com/dnsvigil/dnsvigil/internal/core/history"
	"github.com/dnsvigil/dnsvigil/internal/core/tlscheck"
)

// DirName is the default directory holding the settings file.
const DirName = ".dnsvigil"

const fileName = "settings.json"

// Duration is a time.Duration that serialises as a human-readable string
// ("5s", "720h") rather than a nanosecond count.
type Duration time.Duration

func (d Duration) String() string { return time.Duration(d).String() }

// MarshalJSON writes the duration in Go's "5s" form.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON accepts the "5s" form (and a bare nanosecond number for
// robustness).
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		var n int64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return err
		}
		*d = Duration(time.Duration(n))
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// Settings are the shared defaults for a run plus retention windows. File paths
// (audit path, report dir, wordlist) are intentionally absent: they stay on the
// command line so a browser form can never point the tool at arbitrary files.
type Settings struct {
	Operator       string   `json:"operator"`
	Timeout        Duration `json:"timeout"`
	ExpiryWarnDays int      `json:"expiry_warn_days"`
	Resolver       string   `json:"resolver"`
	SecondResolver string   `json:"second_resolver"`
	Budget         Duration `json:"budget"`

	AuditRetention   Duration `json:"audit_retention"`
	HistoryRetention Duration `json:"history_retention"`

	Deep             bool   `json:"deep"`
	Enumerate        bool   `json:"enumerate"`
	CheckRevocation  bool   `json:"check_revocation"`
	UseDoH           bool   `json:"doh"`
	DoHProvider      string `json:"doh_provider"`
	DiscoverWordlist bool   `json:"discover"`
	DiscoverCT       bool   `json:"discover_ct"`
	ZoneTransfer     bool   `json:"axfr"`
}

// Default returns the built-in defaults, matching the CLI's own defaults.
func Default() Settings {
	return Settings{
		Operator:         "cli",
		Timeout:          Duration(5 * time.Second),
		ExpiryWarnDays:   tlscheck.DefaultExpiryWarnDays,
		Budget:           Duration(engine.DefaultBudget),
		AuditRetention:   0,
		HistoryRetention: Duration(history.DefaultRetention),
	}
}

// Path is the settings file location for a store directory ("" → DirName).
func Path(dir string) string {
	if dir == "" {
		dir = DirName
	}
	return filepath.Join(dir, fileName)
}

// Load reads the settings file, starting from Default so missing fields keep
// their default. found reports whether a file existed.
func Load(dir string) (s Settings, found bool, err error) {
	s = Default()
	data, err := os.ReadFile(Path(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return s, false, nil
		}
		return s, false, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return Default(), true, err
	}
	return s, true, nil
}

// Save writes the settings atomically, owner-only (FR-A6).
func Save(dir string, s Settings) error {
	if dir == "" {
		dir = DirName
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, "settings-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, Path(dir)); err != nil {
		if os.Remove(Path(dir)) == nil {
			if err = os.Rename(name, Path(dir)); err == nil {
				return nil
			}
		}
		os.Remove(name)
		return err
	}
	return nil
}
