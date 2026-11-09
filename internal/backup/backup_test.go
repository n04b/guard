package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTrip(t *testing.T) {
	src := t.TempDir()
	s := Sources{
		RauthyBackups: filepath.Join(src, "rauthy/state_machine/backups"),
		Secrets:       filepath.Join(src, "secrets"),
		CaddyData:     filepath.Join(src, "caddy"),
		StateFile:     filepath.Join(src, "guard/state.json"),
		ConfigDir:     filepath.Join(src, "config"),
	}
	write(t, filepath.Join(s.RauthyBackups, "backup_old"), "old")
	write(t, filepath.Join(s.RauthyBackups, "backup_new"), "new-db")
	old := time.Now().Add(-time.Hour)
	os.Chtimes(filepath.Join(s.RauthyBackups, "backup_old"), old, old)
	write(t, filepath.Join(s.Secrets, "rauthy-enc-key"), "k1/abc")
	write(t, filepath.Join(s.Secrets, "clients/app.secret"), "cs")
	write(t, filepath.Join(s.CaddyData, "pki/authorities/local/root.crt"), "ROOT")
	write(t, filepath.Join(s.CaddyData, "locks/x.lock"), "lock")
	write(t, s.StateFile, `{"rp_id":"auth.example.com"}`)
	write(t, filepath.Join(s.ConfigDir, "guard.yml"), "server: {}")

	out := filepath.Join(src, "backups", ArchiveName(time.Now()))
	m, err := Create(s, out, "test")
	if err != nil {
		t.Fatal(err)
	}
	if m.Database != "backup_new" {
		t.Errorf("should take the newest db backup, got %s", m.Database)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Errorf("archive mode = %v", st.Mode().Perm())
	}

	dst := t.TempDir()
	tg := Targets{
		RauthyData:     filepath.Join(dst, "rauthy"),
		Secrets:        filepath.Join(dst, "secrets"),
		CaddyData:      filepath.Join(dst, "caddy"),
		StateFile:      filepath.Join(dst, "guard/state.json"),
		RestoreDir:     filepath.Join(dst, "guard/restore"),
		RestorePending: filepath.Join(dst, "guard/restore-pending"),
		ConfigOut:      filepath.Join(dst, "restored-config"),
	}
	os.MkdirAll(filepath.Join(dst, "guard"), 0o700)
	if _, err := Restore(out, tg, false); err != nil {
		t.Fatal(err)
	}
	check := func(path, want string) {
		b, err := os.ReadFile(path)
		if err != nil || string(b) != want {
			t.Errorf("%s = %q (%v), want %q", path, b, err, want)
		}
	}
	check(filepath.Join(tg.Secrets, "clients/app.secret"), "cs")
	check(filepath.Join(tg.CaddyData, "pki/authorities/local/root.crt"), "ROOT")
	check(tg.StateFile, `{"rp_id":"auth.example.com"}`)
	check(filepath.Join(tg.ConfigOut, "guard.yml"), "server: {}")
	check(filepath.Join(tg.RestoreDir, "backup_new"), "new-db")
	check(tg.RestorePending, "file:"+filepath.Join(tg.RestoreDir, "backup_new")+"\n")
	if _, err := os.Stat(filepath.Join(tg.CaddyData, "locks/x.lock")); err == nil {
		t.Error("lock files must not be archived")
	}

	// A volume with data is refused without --force.
	write(t, filepath.Join(tg.RauthyData, "x"), "live")
	if _, err := Restore(out, tg, false); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("expected refusal, got %v", err)
	}
	if _, err := Restore(out, tg, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tg.RauthyData, "x")); err == nil {
		t.Error("--force should clear the old database")
	}
}

func TestCreateWithoutDBBackup(t *testing.T) {
	dir := t.TempDir()
	_, err := Create(Sources{RauthyBackups: filepath.Join(dir, "none")}, filepath.Join(dir, "x.tar.gz"), "v")
	if err == nil || !strings.Contains(err.Error(), "no database backup") {
		t.Fatalf("got %v", err)
	}
}

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		write(t, filepath.Join(dir, ArchiveName(time.Date(2026, 1, 1, i, 0, 0, 0, time.UTC))), "x")
	}
	removed, err := Prune(dir, 2)
	if err != nil || len(removed) != 3 {
		t.Fatalf("removed %v, %v", removed, err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.tar.gz"))
	if len(left) != 2 || !strings.Contains(left[1], "040000") {
		t.Errorf("kept %v", left)
	}
}
