package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes guard.yml into a fresh directory.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

const minimal = `
server:
  hostname: auth.example.com
admin:
  bootstrap_email: admin@example.com
`

func TestLoadMinimal(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimal))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.WebAuthn.RPID != "auth.example.com" {
		t.Errorf("rp_id default = %q", cfg.Server.WebAuthn.RPID)
	}
	if cfg.TLS.TLS.Mode != TLSAuto {
		t.Errorf("tls mode default = %q", cfg.TLS.TLS.Mode)
	}
	if cfg.Security.Registration.Mode != RegistrationClosed {
		t.Errorf("registration default = %q", cfg.Security.Registration.Mode)
	}
	if !*cfg.Server.Admin.RequirePasskey {
		t.Error("admin.require_passkey should default to true")
	}
	if cfg.PublicURL() != "https://auth.example.com" {
		t.Errorf("PublicURL = %q", cfg.PublicURL())
	}
	if len(cfg.Applications) != 0 {
		t.Errorf("apps = %d", len(cfg.Applications))
	}
}

func TestLoadFullFile(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
server:
  hostname: auth.example.com
  https_port: 8443
admin:
  bootstrap_email: admin@example.com
logging:
  level: debug

tls:
  mode: acme
  acme:
    email: admin@example.com
    fallback_after: 15m

security:
  registration: {mode: closed}
  password_policy: {min_length: 14}
  roles: [editor]
  groups: [team]

applications:
  - name: app1
    domain: App1.Example.com
    upstream: {host: app1, port: 3000}

  - name: spa
    domain: spa.example.com
    upstream: {host: spa, port: 80}
    auth:
      mode: app
      redirect_uris: [https://spa.example.com/callback]
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Logging.Level != "debug" || cfg.TLS.TLS.Mode != TLSACME ||
		cfg.TLS.TLS.ACME.FallbackAfter.Minutes() != 15 || cfg.Security.PasswordPolicy.MinLength != 14 ||
		strings.Join(cfg.Security.Roles, ",") != "editor" {
		t.Errorf("sections not decoded: %+v", cfg)
	}
	if len(cfg.Applications) != 2 {
		t.Fatalf("apps = %d", len(cfg.Applications))
	}
	a := &cfg.Applications[0]
	if a.Domain != "app1.example.com" || a.Auth.Mode != ModeProxy || a.Auth.ClientID != "app1" || a.File != "applications[0]" {
		t.Errorf("defaults not applied: %+v", a)
	}
	if got := cfg.EffectiveRedirectURIs(a); got[0] != "https://app1.example.com:8443/.guard/callback" {
		t.Errorf("proxy redirect = %v", got)
	}
	spa := &cfg.Applications[1]
	if spa.Auth.ClientType != ClientPublic {
		t.Errorf("app mode should default to public client, got %q", spa.Auth.ClientType)
	}
	if got := cfg.EffectiveAllowedOrigins(spa); len(got) != 1 || got[0] != "https://spa.example.com:8443" {
		t.Errorf("spa origins = %v", got)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	for name, content := range map[string]string{
		"top level":   minimal + "\nbogus: 1\n",
		"in tls":      minimal + "\ntls:\n  bogus: 1\n",
		"in security": minimal + "\nsecurity:\n  bogus: 1\n",
		"in app":      minimal + "\napplications:\n  - name: a\n    bogus: 1\n",
	} {
		_, err := Load(writeConfig(t, content))
		if err == nil || !strings.Contains(err.Error(), "bogus") {
			t.Errorf("%s: expected unknown field error, got %v", name, err)
		}
	}
}

func TestErrorsPointToLines(t *testing.T) {
	_, err := Load(writeConfig(t, minimal+"\napplications:\n  - name: a\n    upstream: [broken\n"))
	if err == nil || !strings.Contains(err.Error(), "guard.yml") {
		t.Fatalf("expected a located YAML error, got %v", err)
	}
}

func TestMissingAndLegacyFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "guard.yml not found") {
		t.Errorf("missing file: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "server.yml"), []byte(minimal), 0o644)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "now lives in one file") {
		t.Errorf("legacy layout should be explained, got %v", err)
	}
	if _, err := Load(writeConfig(t, "  \n")); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty file: %v", err)
	}
}

func TestValidationCollectsAllProblems(t *testing.T) {
	_, err := Load(writeConfig(t, `
server:
  hostname: "bad host"
webauthn:
  rp_id: other.com
admin:
  bootstrap_email: nope
  allow_from: [10.0.0.1]
security:
  registration: {mode: open}
  password_policy: {min_length: 4}
  roles: [Admin]
applications:
  - name: X
    domain: auth.example.com
    upstream: {host: "", port: 0}
    auth:
      mode: app
      client_id: rauthy
      redirect_uris: ["http://evil.com/cb"]
      scopes: [profile, bogus]
`))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
	want := []string{
		"server.hostname", "rp_id", "bootstrap_email", "allow_from",
		"registration.mode open needs SMTP", "security.password_policy.min_length", `security.roles: "Admin"`,
		"applications[0] (X): name", "upstream.host", "upstream.port", "rauthy is reserved",
		"plain http", `unknown scope "bogus"`, "must include openid",
	}
	msg := err.Error()
	for _, w := range want {
		if !strings.Contains(msg, w) {
			t.Errorf("missing problem %q in:\n%s", w, msg)
		}
	}
}

func TestDuplicates(t *testing.T) {
	app := "  - name: a\n    domain: a.example.com\n    upstream: {host: x, port: 1}\n    auth: {client_id: c1}\n"
	_, err := Load(writeConfig(t, minimal+"applications:\n"+app+app))
	if err == nil {
		t.Fatal("expected duplicate errors")
	}
	for _, w := range []string{
		`applications[1] (a): name "a" is already used in applications[0]`,
		`domain "a.example.com" is already used`,
		`client_id "c1" is already used`,
	} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("missing %q in %v", w, err)
		}
	}
}

func TestProxyModeRejectsManualRedirects(t *testing.T) {
	_, err := Load(writeConfig(t, minimal+`
applications:
  - name: a
    domain: a.example.com
    upstream: {host: a, port: 80}
    auth:
      mode: proxy
      redirect_uris: [https://a.example.com/cb]
`))
	if err == nil || !strings.Contains(err.Error(), "generated automatically") {
		t.Fatalf("got %v", err)
	}
}

func TestResolveTLSMode(t *testing.T) {
	base := func() *Config {
		c := &Config{}
		c.Server.Server.Hostname = "auth.example.com"
		c.TLS.TLS.Mode = TLSAuto
		c.TLS.TLS.Custom = CustomTLS{Certificate: "/c", PrivateKey: "/k"}
		return c
	}
	none := func(string) bool { return false }
	all := func(string) bool { return true }

	if m := base().resolveTLSMode(all); m != TLSCustom {
		t.Errorf("custom files present -> %s", m)
	}
	if m := base().resolveTLSMode(none); m != TLSLocalCA {
		t.Errorf("nothing configured -> %s", m)
	}
	c := base()
	c.TLS.TLS.ACME.Email = "a@example.com"
	if m := c.resolveTLSMode(none); m != TLSACME {
		t.Errorf("acme email + public -> %s", m)
	}
	c.Applications = []Application{{Domain: "nas.lan"}}
	if m := c.resolveTLSMode(none); m != TLSLocalCA {
		t.Errorf("private domain -> %s", m)
	}
}

func TestHostnames(t *testing.T) {
	for h, ok := range map[string]bool{
		"auth.example.com": true, "localhost": true, "a-b.c": true,
		"": false, "-a.com": false, "a..com": false, "a.com.": false, "A.com": false,
	} {
		if IsHostname(h) != ok {
			t.Errorf("IsHostname(%q) != %v", h, ok)
		}
	}
	for h, ok := range map[string]bool{
		"auth.example.com": true, "localhost": false, "nas.lan": false, "10.0.0.1": false, "box.home.arpa": false,
	} {
		if IsPublicHostname(h) != ok {
			t.Errorf("IsPublicHostname(%q) != %v", h, ok)
		}
	}
}

func TestExampleConfigsAreValid(t *testing.T) {
	for _, dir := range []string{"../../config.example", "../../examples/local-demo/config"} {
		if _, err := Load(dir); err != nil {
			t.Errorf("%s: %v", dir, err)
		}
	}
}
