package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

// File names inside the configuration directory.
const (
	ServerFileName   = "server.yml"
	TLSFileName      = "tls.yml"
	SecurityFileName = "security.yml"
	AppsDirName      = "applications"
)

// Load reads, defaults and validates the configuration in dir.
//
// server.yml is required. tls.yml, security.yml and the applications
// directory are optional and fall back to defaults.
func Load(dir string) (*Config, error) {
	cfg := &Config{Dir: dir}

	if err := readYAML(filepath.Join(dir, ServerFileName), true, &cfg.Server); err != nil {
		return nil, err
	}
	if err := readYAML(filepath.Join(dir, TLSFileName), false, &cfg.TLS); err != nil {
		return nil, err
	}
	if err := readYAML(filepath.Join(dir, SecurityFileName), false, &cfg.Security); err != nil {
		return nil, err
	}

	apps, err := loadApps(filepath.Join(dir, AppsDirName))
	if err != nil {
		return nil, err
	}
	cfg.Applications = apps

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func loadApps(dir string) ([]Application, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") {
			continue
		}
		if strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	apps := make([]Application, 0, len(names))
	for _, n := range names {
		var f AppFile
		path := filepath.Join(dir, n)
		if err := readYAML(path, true, &f); err != nil {
			return nil, err
		}
		f.Application.File = filepath.Join(AppsDirName, n)
		apps = append(apps, f.Application)
	}
	return apps, nil
}

func readYAML(path string, required bool, v any) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		if required {
			return fmt.Errorf("%s is empty", path)
		}
		return nil
	}
	if err := yaml.UnmarshalWithOptions(b, v, yaml.DisallowUnknownField()); err != nil {
		return fmt.Errorf("%s: %s", filepath.Base(path), yaml.FormatError(err, false, true))
	}
	return nil
}

func (c *Config) applyDefaults() {
	s := &c.Server
	if s.Server.HTTPPort == 0 {
		s.Server.HTTPPort = 80
	}
	if s.Server.HTTPSPort == 0 {
		s.Server.HTTPSPort = 443
	}
	s.Server.Hostname = strings.ToLower(strings.TrimSpace(s.Server.Hostname))
	if s.WebAuthn.RPID == "" {
		s.WebAuthn.RPID = s.Server.Hostname
	}
	s.WebAuthn.RPID = strings.ToLower(s.WebAuthn.RPID)
	if s.WebAuthn.RPName == "" {
		s.WebAuthn.RPName = "Guard"
	}
	if len(s.Admin.AllowFrom) == 0 {
		s.Admin.AllowFrom = []string{"127.0.0.1/32", "::1/128"}
	}
	if s.Admin.RequirePasskey == nil {
		t := true
		s.Admin.RequirePasskey = &t
	}
	if s.SMTP.Port == 0 {
		s.SMTP.Port = 587
	}
	if s.SMTP.TLSMode == "" {
		s.SMTP.TLSMode = "starttls"
	}
	if s.SMTP.PasswordEnv == "" {
		s.SMTP.PasswordEnv = "GUARD_SMTP_PASSWORD"
	}
	if s.Backup.Cron == "" {
		s.Backup.Cron = "0 30 2 * * * *"
	}
	if s.Backup.KeepDays == 0 {
		s.Backup.KeepDays = 7
	}
	if s.Logging.Level == "" {
		s.Logging.Level = "info"
	}

	t := &c.TLS.TLS
	if t.Mode == "" {
		t.Mode = TLSAuto
	}
	if t.Custom.Certificate == "" {
		t.Custom.Certificate = "/certs/fullchain.pem"
	}
	if t.Custom.PrivateKey == "" {
		t.Custom.PrivateKey = "/certs/privkey.pem"
	}
	if t.ACME.FallbackAfter.Duration == 0 {
		t.ACME.FallbackAfter.Duration = 10 * time.Minute
	}

	sec := &c.Security
	if sec.Registration.Mode == "" {
		sec.Registration.Mode = RegistrationClosed
	}
	pp := &sec.PasswordPolicy
	if pp.MinLength == 0 {
		pp.MinLength = 12
	}
	if pp.MaxLength == 0 {
		pp.MaxLength = 128
	}
	if sec.Session.IdleMinutes == 0 {
		sec.Session.IdleMinutes = 60
	}
	if sec.Session.MaxHours == 0 {
		sec.Session.MaxHours = 720
	}
	h := &sec.Hashing
	if h.MemoryMiB == 0 {
		h.MemoryMiB = 32
	}
	if h.Iterations == 0 {
		h.Iterations = 3
	}
	if h.Parallelism == 0 {
		h.Parallelism = 2
	}
	if h.MaxParallelHashes == 0 {
		h.MaxParallelHashes = 2
	}

	for i := range c.Applications {
		a := &c.Applications[i]
		a.Domain = strings.ToLower(strings.TrimSpace(a.Domain))
		if a.Upstream.Scheme == "" {
			a.Upstream.Scheme = "http"
		}
		if a.Auth.Mode == "" {
			a.Auth.Mode = ModeProxy
		}
		if a.Auth.ClientID == "" {
			a.Auth.ClientID = a.Name
		}
		if a.Auth.ClientType == "" {
			if a.Auth.Mode == ModeApp {
				a.Auth.ClientType = ClientPublic
			} else {
				a.Auth.ClientType = ClientConfidential
			}
		}
		if len(a.Auth.Scopes) == 0 {
			a.Auth.Scopes = []string{"openid", "profile", "email", "groups"}
		}
		if a.Auth.AccessTokenSeconds == 0 {
			a.Auth.AccessTokenSeconds = 1800
		}
		if a.Auth.SigningAlg == "" {
			a.Auth.SigningAlg = "RS256"
		}
		if a.OnRemove == "" {
			a.OnRemove = RemoveDisable
		}
	}
}

// PublicURL returns the external base URL of the auth server, for example
// "https://auth.example.com" or "https://auth.example.com:8443".
func (c *Config) PublicURL() string {
	return "https://" + c.PublicHost()
}

// PublicHost returns host[:port] of the auth server as seen by browsers.
func (c *Config) PublicHost() string {
	return HostWithPort(c.Server.Server.Hostname, c.Server.Server.HTTPSPort)
}

// AppOrigin returns the external origin of an application.
func (c *Config) AppOrigin(a *Application) string {
	return "https://" + HostWithPort(a.Domain, c.Server.Server.HTTPSPort)
}

// HostWithPort appends the port unless it is the default HTTPS port.
func HostWithPort(host string, httpsPort int) string {
	if httpsPort == 443 || httpsPort == 0 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, httpsPort)
}

// ForwardAuthCallbackPath is the path Guard injects into proxied apps.
const ForwardAuthCallbackPath = "/.guard/callback"

// ForwardAuthLogoutPath logs the user out of Guard from any proxied app.
const ForwardAuthLogoutPath = "/.guard/logout"

// EffectiveRedirectURIs returns the redirect URIs that are registered in
// Rauthy for the application.
func (c *Config) EffectiveRedirectURIs(a *Application) []string {
	if a.Auth.Mode == ModeProxy {
		// Rauthy uses the first redirect URI as the forward-auth callback.
		return []string{c.AppOrigin(a) + ForwardAuthCallbackPath}
	}
	return a.Auth.RedirectURIs
}

// EffectiveAllowedOrigins returns the allowed origins registered in Rauthy.
func (c *Config) EffectiveAllowedOrigins(a *Application) []string {
	if a.Auth.Mode == ModeProxy {
		return []string{c.AppOrigin(a)}
	}
	if len(a.Auth.AllowedOrigins) > 0 {
		return a.Auth.AllowedOrigins
	}
	if a.Auth.ClientType == ClientPublic {
		// SPAs call the token endpoint from the browser.
		return []string{c.AppOrigin(a)}
	}
	return nil
}

// ManagedApps returns applications that need an OIDC client.
func (c *Config) ManagedApps() []*Application {
	var out []*Application
	for i := range c.Applications {
		if c.Applications[i].Auth.Mode != ModeNone {
			out = append(out, &c.Applications[i])
		}
	}
	return out
}
