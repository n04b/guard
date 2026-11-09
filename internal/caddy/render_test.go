package caddy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n04b/guard/internal/config"
)

func testConfig(t *testing.T, extraServer string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"server.yml": "server:\n  hostname: auth.example.com\n" + extraServer +
			"admin:\n  bootstrap_email: a@example.com\n  allow_from: [127.0.0.1/32, 100.64.0.0/10]\n",
		"applications/wiki.yml": `
application:
  name: wiki
  domain: wiki.example.com
  upstream: {host: wiki, port: 3000}
`,
		"applications/spa.yml": `
application:
  name: spa
  domain: spa.example.com
  upstream: {host: spa, port: 8443, scheme: https, tls_insecure_skip_verify: true}
  auth: {mode: app, redirect_uris: [https://spa.example.com/cb]}
`,
		"applications/pub.yml": `
application:
  name: pub
  domain: pub.example.com
  upstream: {host: pub, port: 80}
  auth: {mode: none}
`,
	}
	for n, c := range files {
		p := filepath.Join(dir, n)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(c), 0o644)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func render(cfg *config.Config, mode config.TLSMode, fallback map[string]bool) string {
	return Render(Input{Cfg: cfg, Mode: mode, FallbackDomains: fallback, CADir: "/data/caddy/pki/authorities/local", HealthAddr: "127.0.0.1:9100"})
}

// block returns the site block that starts with header.
func block(t *testing.T, out, header string) string {
	t.Helper()
	i := strings.Index(out, "\n"+header+" {\n")
	if i < 0 {
		t.Fatalf("no site block %q in:\n%s", header, out)
	}
	rest := out[i+1:]
	j := strings.Index(rest, "\n}\n")
	return rest[:j+2]
}

func TestRenderProxyApp(t *testing.T) {
	out := render(testConfig(t, ""), config.TLSACME, nil)
	wiki := block(t, out, "wiki.example.com")
	for _, want := range []string{
		"request_header -X-Guard-User",
		"handle /.guard/callback {",
		"rewrite * /auth/v1/clients/wiki/forward_auth/callback?{query}",
		"redir https://auth.example.com/auth/v1/oidc/logout 302",
		"forward_auth 127.0.0.1:8080 {",
		"uri /auth/v1/clients/wiki/forward_auth?redirect_state=302",
		"copy_headers X-Guard-User X-Guard-Email",
		"reverse_proxy http://wiki:3000",
		`Strict-Transport-Security "max-age=31536000"`,
	} {
		if !strings.Contains(wiki, want) {
			t.Errorf("wiki block misses %q:\n%s", want, wiki)
		}
	}
	// Header stripping must happen before forward_auth inside the route.
	if strings.Index(wiki, "request_header -X-Guard-User") > strings.Index(wiki, "forward_auth") {
		t.Error("headers must be stripped before forward_auth")
	}
	if strings.Contains(wiki, "tls internal") {
		t.Error("acme mode must not use internal certs")
	}
	if !strings.Contains(out, "email a@example.com") && !strings.Contains(out, "email ") {
		t.Error("acme email missing")
	}
}

func TestRenderAppAndNone(t *testing.T) {
	out := render(testConfig(t, ""), config.TLSLocalCA, nil)
	spa := block(t, out, "spa.example.com")
	if strings.Contains(spa, "forward_auth") {
		t.Error("app mode must not use forward_auth")
	}
	if !strings.Contains(spa, "reverse_proxy https://spa:8443 {") || !strings.Contains(spa, "tls_insecure_skip_verify") {
		t.Errorf("https upstream:\n%s", spa)
	}
	pub := block(t, out, "pub.example.com")
	if strings.Contains(pub, "forward_auth") || !strings.Contains(pub, "reverse_proxy http://pub:80") {
		t.Errorf("none mode:\n%s", pub)
	}
	if !strings.Contains(out, "\tlocal_certs\n") || !strings.Contains(pub, "tls internal") {
		t.Error("local-ca mode must use internal certificates")
	}
	if strings.Contains(pub, "Strict-Transport-Security") {
		t.Error("no HSTS with the local CA")
	}
	httpSite := block(t, out, "http://auth.example.com")
	if !strings.Contains(httpSite, "handle /.guard/ca.crt {") || !strings.Contains(httpSite, "redir https://auth.example.com{uri} 308") {
		t.Errorf("http site:\n%s", httpSite)
	}
}

func TestRenderAuthHost(t *testing.T) {
	out := render(testConfig(t, "  https_port: 8443\n  trusted_proxies: [10.0.0.0/8]\n"), config.TLSCustom, nil)
	auth := block(t, out, "auth.example.com")
	for _, want := range []string{
		"not client_ip 127.0.0.1/32 100.64.0.0/10",
		"path /auth/v1/admin /auth/v1/admin/*",
		"handle @admin_ui {",
		"rewrite * /health/detail",
		"rewrite * /health/public",
		"reverse_proxy 127.0.0.1:8080",
		"tls /certs/fullchain.pem /certs/privkey.pem",
	} {
		if !strings.Contains(auth, want) {
			t.Errorf("auth block misses %q:\n%s", want, auth)
		}
	}
	// Order: admin block first, catch-all last.
	if strings.Index(auth, "handle @admin_ui") > strings.Index(auth, "\t\thandle {") {
		t.Error("admin restriction must come before the catch-all")
	}
	if !strings.Contains(out, "trusted_proxies static 10.0.0.0/8") {
		t.Error("global options missing")
	}
	if strings.Contains(out, "\thttps_port ") || strings.Contains(out, "example.com:8443 {") {
		t.Error("Caddy listens on 443 inside the container; the public port only appears in URLs")
	}
	if strings.Contains(out, "handle /.guard/ca.crt") {
		t.Error("CA download only exists with the local CA")
	}
	redirect := block(t, out, "http://auth.example.com, http://pub.example.com, http://spa.example.com, http://wiki.example.com")
	if !strings.Contains(redirect, "redir https://{host}:8443{uri} 308") {
		t.Errorf("non-443 redirect:\n%s", redirect)
	}
}

func TestRenderFallback(t *testing.T) {
	out := render(testConfig(t, ""), config.TLSACME, map[string]bool{"wiki.example.com": true})
	wiki := block(t, out, "wiki.example.com")
	if !strings.Contains(wiki, "tls internal") || strings.Contains(wiki, "Strict-Transport-Security") {
		t.Errorf("fallback domain:\n%s", wiki)
	}
	if strings.Contains(block(t, out, "spa.example.com"), "tls internal") {
		t.Error("only the fallback domain uses the local CA")
	}
}

func TestBracesBalanced(t *testing.T) {
	for _, mode := range []config.TLSMode{config.TLSACME, config.TLSLocalCA, config.TLSCustom} {
		out := render(testConfig(t, ""), mode, nil)
		if strings.Count(out, "{")-strings.Count(out, "{query}")-strings.Count(out, "{uri}") !=
			strings.Count(out, "}")-strings.Count(out, "{query}")-strings.Count(out, "{uri}") {
			t.Errorf("unbalanced braces in %s mode", mode)
		}
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"plain":      "plain",
		"has space":  `"has space"`,
		`a"b`:        `"a\"b"`,
		"":           `""`,
		`back\slash`: `"back\\slash"`,
	} {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestAdminLoad(t *testing.T) {
	var gotType, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if strings.Contains(gotBody, "broken") {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"adapting config: Caddyfile:3 - unknown directive"}`))
		}
	}))
	defer srv.Close()
	a := &Admin{URL: srv.URL, HTTP: srv.Client()}
	if err := a.Load(context.Background(), "x {}", false); err != nil {
		t.Fatal(err)
	}
	if gotType != "text/caddyfile" || gotBody != "x {}" {
		t.Errorf("load request: %s %q", gotType, gotBody)
	}
	err := a.Load(context.Background(), "broken", true)
	if err == nil || !strings.Contains(err.Error(), "unknown directive") {
		t.Errorf("expected caddy error, got %v", err)
	}
}
