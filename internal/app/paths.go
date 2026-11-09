// Package app wires configuration, Rauthy and Caddy together and
// implements the guard-sync commands.
package app

import (
	"os"
	"path/filepath"
)

// Paths are the directories guard-sync works with. Defaults match the
// container layout; every one can be overridden by an environment variable.
type Paths struct {
	ConfigDir string // GUARD_CONFIG_DIR, read-only YAML (default /config)
	DataDir   string // GUARD_DATA_DIR, the persistent volume (default /data)
}

func PathsFromEnv() Paths {
	return Paths{
		ConfigDir: envOr("GUARD_CONFIG_DIR", "/config"),
		DataDir:   envOr("GUARD_DATA_DIR", "/data"),
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (p Paths) Secrets() string { return filepath.Join(p.DataDir, "secrets") }

// RauthyData is Hiqlite's data dir.
func (p Paths) RauthyData() string { return filepath.Join(p.DataDir, "rauthy") }

// RauthyBackups is where Hiqlite writes its automatic backups.
func (p Paths) RauthyBackups() string {
	return filepath.Join(p.RauthyData(), "state_machine", "backups")
}

// Caddy uses $XDG_DATA_HOME/caddy; the image sets XDG_DATA_HOME=/data.
func (p Paths) CaddyData() string { return filepath.Join(p.DataDir, "caddy") }

func (p Paths) CADir() string {
	return filepath.Join(p.CaddyData(), "pki", "authorities", "local")
}

func (p Paths) GuardDir() string { return filepath.Join(p.DataDir, "guard") }

// Caddyfile is the last configuration Caddy accepted. Caddy starts with it.
func (p Paths) Caddyfile() string { return filepath.Join(p.GuardDir(), "Caddyfile") }

func (p Paths) RauthyDir() string { return filepath.Join(p.GuardDir(), "rauthy") }

// RauthyConfig is the rendered config.toml (contains secrets, 0600).
func (p Paths) RauthyConfig() string { return filepath.Join(p.RauthyDir(), "config.toml") }

func (p Paths) BootstrapDir() string { return filepath.Join(p.RauthyDir(), "bootstrap") }

// StartupEnv holds variables for Rauthy's next start (first-boot admin
// password, backup restore). Removed once they are no longer needed.
func (p Paths) StartupEnv() string { return filepath.Join(p.RauthyDir(), "startup.env") }

// RestoreDir holds a database file waiting to be restored.
func (p Paths) RestoreDir() string { return filepath.Join(p.GuardDir(), "restore") }

func (p Paths) RestorePending() string { return filepath.Join(p.GuardDir(), "restore-pending") }

// Backups holds archives made by "guard-sync backup".
func (p Paths) Backups() string { return filepath.Join(p.DataDir, "backups") }
