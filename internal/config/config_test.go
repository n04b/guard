package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const minimalServer = `
server:
  hostname: auth.example.com
admin:
  bootstrap_email: admin@example.com
`

func TestLoadMinimal(t *testing.T) {
	dir := writeFiles(t, map[string]string{"server.yml": minimalServer})
	cfg, err := Load(dir)
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
}

func TestLoadApplications(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"server.yml": strings.Replace(minimalServer, "hostname: auth.example.com", "hostname: auth.example.com\n  https_port: 8443", 1),
		"applications/a.yml": `
application:
  name: app1
  domain: App1.Example.com
  upstream: {host: app1, port: 3000}
`,
		"applications/b.yaml": `
application:
  name: spa
  domain: spa.example.com
  upstream: {host: spa, port: 80}
  auth:
    mode: app
    redirect_uris: [https://spa.example.com/callback]
`,
		"applications/.hidden.yml": "garbage: [",
		"applications/readme.txt":  "ignored",
	})
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Applications) != 2 {
		t.Fatalf("apps = %d", len(cfg.Applications))
	}
	a := &cfg.Applications[0]
	if a.Domain != "app1.example.com" || a.Auth.Mode != ModeProxy || a.Auth.ClientID != "app1" {
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
	dir := writeFiles(t, map[string]string{"server.yml": minimalServer + "\nbogus: 1\n"})
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestValidationCollectsAllProblems(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"server.yml": `
server:
  hostname: "bad host"
webauthn:
  rp_id: other.com
admin:
  bootstrap_email: nope
  allow_from: [10.0.0.1]
`,
		"security.yml": `
registration: {mode: open}
password_policy: {min_length: 4}
roles: [Admin]
`,
		"applications/x.yml": `
application:
  name: X
  domain: auth.example.com
  upstream: {host: "", port: 0}
  auth:
    mode: app
    client_id: rauthy
    redirect_uris: ["http://evil.com/cb"]
    scopes: [profile, bogus]
`,
	})
	_, err := Load(dir)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
	want := []string{
		"server.hostname", "rp_id", "bootstrap_email", "allow_from",
		"registration.mode open needs SMTP", "min_length", `role "Admin"`,
		"application.name", "upstream.host", "upstream.port", "rauthy is reserved",
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
	app := func(name, domain, client string) string {
		return "application:\n  name: " + name + "\n  domain: " + domain +
			"\n  upstream: {host: x, port: 1}\n  auth: {client_id: " + client + "}\n"
	}
	dir := writeFiles(t, map[string]string{
		"server.yml":         minimalServer,
		"applications/1.yml": app("a", "a.example.com", "c1"),
		"applications/2.yml": app("a", "a.example.com", "c1"),
	})
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected duplicate errors")
	}
	for _, w := range []string{`name "a" is already used`, `domain "a.example.com" is already used`, `client_id "c1" is already used`} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("missing %q in %v", w, err)
		}
	}
}

func TestProxyModeRejectsManualRedirects(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"server.yml": minimalServer,
		"applications/a.yml": `
application:
  name: a
  domain: a.example.com
  upstream: {host: a, port: 80}
  auth:
    mode: proxy
    redirect_uris: [https://a.example.com/cb]
`,
	})
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "generated automatically") {
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
