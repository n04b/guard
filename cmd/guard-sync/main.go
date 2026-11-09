// guard-sync keeps Rauthy and Caddy in line with Guard's YAML configuration
// and provides the maintenance commands.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/n04b/guard/internal/app"
	"github.com/n04b/guard/internal/backup"
	"github.com/n04b/guard/internal/caddy"
	"github.com/n04b/guard/internal/config"
	"github.com/n04b/guard/internal/state"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `guard-sync — configuration manager of the Guard auth server

Usage:
  guard-sync run                      keep Rauthy and Caddy in sync with /config (service)
  guard-sync init                     prepare secrets and configs before the services start
  guard-sync check [--caddyfile]      validate /config and print a summary (or the Caddyfile)
  guard-sync healthcheck              exit 0 if Guard is up (Docker HEALTHCHECK)
  guard-sync backup [--keep N] [--output FILE]
                                      archive the database, secrets, certificates and config
  guard-sync restore ARCHIVE [--force]
                                      restore an archive into this volume (Rauthy restores the
                                      database on its next start)
  guard-sync user add EMAIL [--admin] [--role R] [--group G] [--given-name N] [--family-name N] [--lang L]
                                      create a user and print a one-time password
  guard-sync user set-password EMAIL  issue a new one-time password
  guard-sync version

Environment: GUARD_CONFIG_DIR (default /config), GUARD_DATA_DIR (default /data).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	p := app.PathsFromEnv()
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "run":
		err = cmdRun(p)
	case "init":
		err = app.Init(p, serviceLogger())
	case "check":
		err = cmdCheck(p, args)
	case "healthcheck":
		err = cmdHealthcheck()
	case "backup":
		err = cmdBackup(p, args)
	case "restore":
		err = cmdRestore(p, args)
	case "user":
		err = cmdUser(p, args)
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// serviceLogger prefixes every line with [sync] so it can be told apart
// from Rauthy and Caddy in the combined container log.
func serviceLogger() *slog.Logger {
	level := slog.LevelInfo
	if os.Getenv("GUARD_DEBUG") != "" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(&prefixWriter{w: os.Stdout, prefix: []byte("[sync] ")},
		&slog.HandlerOptions{Level: level}))
}

type prefixWriter struct {
	w      io.Writer
	prefix []byte
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	lines := bytes.SplitAfter(b, []byte("\n"))
	var out bytes.Buffer
	for _, l := range lines {
		if len(l) == 0 {
			continue
		}
		out.Write(p.prefix)
		out.Write(l)
	}
	if _, err := p.w.Write(out.Bytes()); err != nil {
		return 0, err
	}
	return len(b), nil
}

func cmdRun(p app.Paths) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log := serviceLogger()
	log.Info("guard-sync starting", "version", version)
	return app.NewDaemon(p, log, version).Run(ctx)
}

func cmdCheck(p app.Paths, args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	printCaddy := fs.Bool("caddyfile", false, "print the generated Caddyfile")
	fs.Parse(args)

	st, err := state.NewStore(p.DataDir).Load()
	if err != nil {
		st = &state.State{}
	}
	cfg, err := app.LoadChecked(p, st)
	if err != nil {
		return err
	}
	mode := cfg.ResolveTLSMode()
	if *printCaddy {
		fmt.Print(caddy.Render(caddy.Input{Cfg: cfg, Mode: mode, CADir: p.CADir(), HealthAddr: app.HealthAddr}))
		return nil
	}
	fmt.Printf("configuration OK (%s)\n\n", p.ConfigDir)
	fmt.Printf("auth server   %s\n", cfg.PublicURL())
	fmt.Printf("issuer        %s/auth/v1/\n", cfg.PublicURL())
	fmt.Printf("webauthn      rp_id=%s\n", cfg.Server.WebAuthn.RPID)
	fmt.Printf("tls           %s", mode)
	if cfg.TLS.TLS.Mode == config.TLSAuto {
		fmt.Print(" (auto)")
	}
	fmt.Printf("\nregistration  %s\n", cfg.Security.Registration.Mode)
	fmt.Printf("smtp          %v\n\n", cfg.Server.SMTP.Enabled)
	if len(cfg.Applications) == 0 {
		fmt.Println("no applications configured")
	}
	for _, a := range cfg.Applications {
		fmt.Printf("%-14s https://%s -> %s://%s:%d  auth=%s", a.Name, a.Domain, a.Upstream.Scheme, a.Upstream.Host, a.Upstream.Port, a.Auth.Mode)
		if a.Auth.Mode != config.ModeNone {
			fmt.Printf(" client_id=%s", a.Auth.ClientID)
		}
		fmt.Println()
	}
	return nil
}

func cmdHealthcheck() error {
	c := &http.Client{Timeout: 8 * time.Second}
	resp, err := c.Get("http://" + app.HealthAddr + "/health/detail")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var r struct {
		Status   string   `json:"status"`
		Problems []string `json:"problems"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	if r.Status == "down" || resp.StatusCode >= 500 {
		return fmt.Errorf("guard is down: %s", strings.Join(r.Problems, "; "))
	}
	fmt.Println(r.Status)
	return nil
}

func cmdBackup(p app.Paths, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	out := fs.String("output", "", "archive path (default /data/backups/guard-<time>.tar.gz)")
	keep := fs.Int("keep", 10, "archives to keep in /data/backups (0 keeps all)")
	fs.Parse(args)
	path := *out
	if path == "" {
		path = filepath.Join(p.Backups(), backup.ArchiveName(time.Now()))
	}
	m, err := backup.Create(backup.Sources{
		RauthyBackups: p.RauthyBackups(),
		Secrets:       p.Secrets(),
		CaddyData:     p.CaddyData(),
		StateFile:     state.NewStore(p.DataDir).Path(),
		ConfigDir:     p.ConfigDir,
	}, path, version)
	if err != nil {
		return err
	}
	fmt.Printf("backup written: %s\ndatabase snapshot: %s (%s)\n", path, m.Database, m.DatabaseTime.Format(time.RFC3339))
	fmt.Println("the archive contains secrets — store it encrypted")
	if *out == "" && *keep > 0 {
		removed, err := backup.Prune(p.Backups(), *keep)
		if err != nil {
			return err
		}
		for _, r := range removed {
			fmt.Println("removed old archive:", r)
		}
	}
	return nil
}

func cmdRestore(p app.Paths, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	force := fs.Bool("force", false, "replace an existing database")
	// Accept the flag before or after the archive path.
	var rest []string
	for _, a := range args {
		if a == "--force" || a == "-force" {
			*force = true
		} else {
			rest = append(rest, a)
		}
	}
	fs.Parse(rest)
	if fs.NArg() != 1 {
		return errors.New("usage: guard-sync restore ARCHIVE [--force]")
	}
	m, err := backup.Restore(fs.Arg(0), backup.Targets{
		RauthyData:     p.RauthyData(),
		Secrets:        p.Secrets(),
		CaddyData:      p.CaddyData(),
		StateFile:      state.NewStore(p.DataDir).Path(),
		RestoreDir:     p.RestoreDir(),
		RestorePending: p.RestorePending(),
		ConfigOut:      filepath.Join(p.DataDir, "restored-config"),
	}, *force)
	if err != nil {
		return err
	}
	fmt.Printf("restored archive from %s (database snapshot %s)\n", m.CreatedAt.Format(time.RFC3339), m.DatabaseTime.Format(time.RFC3339))
	fmt.Printf("the archived configuration is in %s — copy it to your config directory if needed\n", filepath.Join(p.DataDir, "restored-config"))
	fmt.Println("start the container: Rauthy restores the database on its first start")
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdUser(p app.Paths, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: guard-sync user add|set-password EMAIL [flags]")
	}
	sub, email := args[0], args[1]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var pw string
	var err error
	switch sub {
	case "add":
		fs := flag.NewFlagSet("user add", flag.ExitOnError)
		var o app.UserOptions
		var roles, groups multiFlag
		fs.BoolVar(&o.Admin, "admin", false, "make the user a Rauthy admin")
		fs.Var(&roles, "role", "role (repeatable)")
		fs.Var(&groups, "group", "group (repeatable)")
		fs.StringVar(&o.GivenName, "given-name", "", "given name")
		fs.StringVar(&o.FamilyName, "family-name", "", "family name")
		fs.StringVar(&o.Language, "lang", "en", "UI language: en, de, ru, ...")
		fs.Parse(args[2:])
		o.Roles, o.Groups = roles, groups
		pw, err = app.UserAdd(ctx, p, email, o)
	case "set-password":
		pw, err = app.UserSetPassword(ctx, p, email)
	default:
		return fmt.Errorf("unknown user command %q", sub)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "one-time password for %s (shown only now; ask the user to add a passkey after the first login):\n", email)
	fmt.Println(pw)
	return nil
}
