package settings

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadWithoutFileReturnsDefaults(t *testing.T) {
	s, found, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if found {
		t.Error("found should be false when no settings file exists")
	}
	if s.Timeout != Duration(5*time.Second) || s.HistoryRetention != Duration(720*time.Hour) {
		t.Errorf("defaults not applied: %+v", s)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := Default()
	want.Operator = "soc"
	want.Timeout = Duration(9 * time.Second)
	want.HistoryRetention = Duration(0)
	want.Deep = true
	want.DoHProvider = "quad9"

	if err := Save(dir, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, found, err := Load(dir)
	if err != nil || !found {
		t.Fatalf("Load: found=%v err=%v", found, err)
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestLoadPartialFileKeepsDefaults(t *testing.T) {
	// A file with only some fields must not zero the others.
	dir := t.TempDir()
	if err := os.WriteFile(Path(dir), []byte(`{"operator":"ops","timeout":"12s"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s, found, err := Load(dir)
	if err != nil || !found {
		t.Fatalf("Load: found=%v err=%v", found, err)
	}
	if s.Operator != "ops" || s.Timeout != Duration(12*time.Second) {
		t.Errorf("explicit fields not applied: %+v", s)
	}
	if s.HistoryRetention != Duration(720*time.Hour) || s.Budget == 0 {
		t.Errorf("defaults should survive a partial file: %+v", s)
	}
}

func TestSaveIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, Default()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(Path(dir))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("settings file perm = %o, want 600", perm)
	}
}

func TestPathDefaultsToNettools(t *testing.T) {
	got := Path("")
	want := filepath.Join(DirName, fileName)
	if got != want {
		t.Errorf("Path(\"\") = %q, want %q", got, want)
	}
}
