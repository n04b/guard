package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/n04b/guard/internal/caddy"
	"github.com/n04b/guard/internal/config"
	"github.com/n04b/guard/internal/rauthy"
	"github.com/n04b/guard/internal/secrets"
	"github.com/n04b/guard/internal/state"
)

// Changing the WebAuthn RP ID breaks every passkey. It is only allowed
// when this variable has exactly this value.
const (
	AllowRPIDChangeEnv   = "GUARD_ALLOW_RP_ID_CHANGE"
	AllowRPIDChangeValue = "i-understand-passkeys-will-break"
)

// HealthAddr is guard-sync's internal health listener.
const HealthAddr = "127.0.0.1:9100"

// Init prepares everything Rauthy and Caddy need before they start:
// secrets, Rauthy's config.toml, first-start bootstrap data and the initial
// Caddyfile. It runs once per container start, before the services.
func Init(p Paths, log *slog.Logger) error {
	for _, d := range []string{p.GuardDir(), p.RauthyDir(), p.Secrets(), p.RauthyData(), p.CaddyData(), p.Backups()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}

	stStore := state.NewStore(p.DataDir)
	st, err := stStore.Load()
	if err != nil {
		return fmt.Errorf("read %s: %w", stStore.Path(), err)
	}

	cfg, cerr := LoadChecked(p, st)
	if cerr != nil {
		if fileExists(p.RauthyConfig()) && fileExists(p.Caddyfile()) {
			log.Error("configuration is invalid, starting with the last working configuration", "err", cerr)
			return nil
		}
		return fmt.Errorf("configuration is invalid and there is no previous working configuration to fall back to: %w", cerr)
	}

	sec := secrets.New(p.Secrets())
	encKey, _, err := sec.Ensure(secrets.EncKey, secrets.NewEncKey)
	if err != nil {
		return err
	}
	raft, _, err := sec.Ensure(secrets.RaftSecret, func() (string, error) { return secrets.Alnum(48) })
	if err != nil {
		return err
	}
	api, _, err := sec.Ensure(secrets.APISecret, func() (string, error) { return secrets.Alnum(48) })
	if err != nil {
		return err
	}

	restore, _ := readTrim(p.RestorePending())
	// Bootstrap data stays in place until guard-sync has seen Rauthy answer
	// once, so an interrupted first start is retried with the same values.
	firstBoot := !st.RauthyInitialized && restore == ""
	env := map[string]string{}

	if firstBoot {
		apiKey, _, err := sec.Ensure(secrets.APIKey, rauthy.NewAPIKey)
		if err != nil {
			return err
		}
		keys, err := rauthy.RenderAPIKeysJSON(apiKey)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(p.BootstrapDir(), 0o700); err != nil {
			return err
		}
		if err := secrets.WriteFileAtomic(filepath.Join(p.BootstrapDir(), "api_keys.json"), keys, 0o600); err != nil {
			return err
		}
		pw, _, err := sec.Ensure(secrets.BootstrapAdmin, func() (string, error) { return secrets.Password(24) })
		if err != nil {
			return err
		}
		env["BOOTSTRAP_ADMIN_PASSWORD_PLAIN"] = pw
		log.Info("first start: Rauthy will create the admin account",
			"email", cfg.Server.Admin.BootstrapEmail,
			"password_file", filepath.Join(p.Secrets(), secrets.BootstrapAdmin))
	} else {
		if err := os.RemoveAll(p.BootstrapDir()); err != nil {
			return err
		}
		if !sec.Exists(secrets.APIKey) {
			log.Error("no API key for Rauthy: clients cannot be synchronised. Create an API key in the Admin UI " +
				"(rights: Clients rw+delete, Groups/Roles read+create, Secrets read+update, Users read+create+update) " +
				"and save \"<name>$<secret>\" to " + filepath.Join(p.Secrets(), secrets.APIKey))
		}
	}
	if restore != "" {
		env["HQL_BACKUP_RESTORE"] = restore
		log.Warn("a database restore is pending, Rauthy will restore it on start", "source", restore)
	}
	if err := writeEnvFile(p.StartupEnv(), env); err != nil {
		return err
	}

	smtpPassword := ""
	if cfg.Server.SMTP.Enabled {
		smtpPassword = os.Getenv(cfg.Server.SMTP.PasswordEnv)
		if smtpPassword == "" && cfg.Server.SMTP.Username != "" {
			log.Warn("smtp.username is set but the password variable is empty", "env", cfg.Server.SMTP.PasswordEnv)
		}
	}
	toml, err := rauthy.RenderConfig(rauthy.RenderInput{
		Cfg: cfg, DataDir: p.RauthyData(), BootstrapDir: p.BootstrapDir(),
		EncKey: encKey, RaftSecret: raft, APISecret: api, SMTPPassword: smtpPassword,
	})
	if err != nil {
		return err
	}
	if err := secrets.WriteFileAtomic(p.RauthyConfig(), []byte(toml), 0o600); err != nil {
		return err
	}

	mode := cfg.ResolveTLSMode()
	cf := caddy.Render(caddy.Input{
		Cfg: cfg, Mode: mode, FallbackDomains: activeFallbacks(cfg, st),
		CADir: p.CADir(), HealthAddr: HealthAddr,
	})
	if err := secrets.WriteFileAtomic(p.Caddyfile(), []byte(cf), 0o600); err != nil {
		return err
	}

	st.RPID = cfg.Server.WebAuthn.RPID
	if err := stStore.Save(st); err != nil {
		return err
	}
	log.Info("configuration prepared",
		"auth", cfg.PublicURL(), "tls", mode, "applications", len(cfg.Applications), "first_start", firstBoot)
	return nil
}

// LoadChecked loads the YAML configuration and runs the checks that need
// the environment (certificate files, RP ID history).
func LoadChecked(p Paths, st *state.State) (*config.Config, error) {
	cfg, err := config.Load(p.ConfigDir)
	if err != nil {
		return nil, err
	}
	if st.RPID != "" && st.RPID != cfg.Server.WebAuthn.RPID && os.Getenv(AllowRPIDChangeEnv) != AllowRPIDChangeValue {
		return nil, fmt.Errorf("webauthn.rp_id changed from %q to %q: every registered passkey would stop working. "+
			"If this is intended, start once with %s=%s", st.RPID, cfg.Server.WebAuthn.RPID, AllowRPIDChangeEnv, AllowRPIDChangeValue)
	}
	if cfg.TLS.TLS.Mode == config.TLSCustom {
		for _, f := range []string{cfg.TLS.TLS.Custom.Certificate, cfg.TLS.TLS.Custom.PrivateKey} {
			if !fileExists(f) {
				return nil, fmt.Errorf("tls.yml: mode custom, but %s does not exist (mount it into the container)", f)
			}
		}
	}
	return cfg, nil
}

// activeFallbacks keeps only fallback domains that still exist and still
// use ACME.
func activeFallbacks(cfg *config.Config, st *state.State) map[string]bool {
	out := map[string]bool{}
	if cfg.ResolveTLSMode() != config.TLSACME || !cfg.TLS.TLS.ACME.AllowFallback {
		return out
	}
	for _, h := range cfg.AllHostnames() {
		if st.FallbackDomains[h] {
			out[h] = true
		}
	}
	return out
}

// writeEnvFile writes KEY='value' lines that a shell can source. An empty
// map removes the file.
func writeEnvFile(path string, env map[string]string) error {
	if len(env) == 0 {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Generated by guard-sync for the next Rauthy start.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, shellQuote(env[k]))
	}
	return secrets.WriteFileAtomic(path, []byte(b.String()), 0o600)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
