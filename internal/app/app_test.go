package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n04b/guard/internal/caddy"
	"github.com/n04b/guard/internal/secrets"
	"github.com/n04b/guard/internal/state"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func setup(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	p := Paths{ConfigDir: filepath.Join(root, "config"), DataDir: filepath.Join(root, "data")}
	writeGuard(t, p, baseCfg, wikiApp)
	return p
}

const baseCfg = `
server: {hostname: auth.example.com}
admin: {bootstrap_email: admin@example.com}
applications:
`

const wikiApp = `
  - name: wiki
    domain: wiki.example.com
    upstream: {host: wiki, port: 3000}
`

const blogApp = `
  - name: blog
    domain: blog.example.com
    upstream: {host: blog, port: 2368}
`

const badApp = `
  - name: Broken!
`

// writeGuard writes guard.yml from a base and application items. Like an
// editor, it replaces the file instead of writing in place.
func writeGuard(t *testing.T, p Paths, base string, apps ...string) {
	t.Helper()
	os.MkdirAll(p.ConfigDir, 0o755)
	tmp := filepath.Join(p.ConfigDir, ".guard.yml.tmp")
	if err := os.WriteFile(tmp, []byte(base+strings.Join(apps, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(p.ConfigDir, "guard.yml")); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInitFirstBoot(t *testing.T) {
	p := setup(t)
	if err := Init(p, quietLog()); err != nil {
		t.Fatal(err)
	}
	sec := secrets.New(p.Secrets())
	for _, f := range []string{secrets.EncKey, secrets.RaftSecret, secrets.APISecret, secrets.APIKey, secrets.BootstrapAdmin} {
		if !sec.Exists(f) {
			t.Errorf("secret %s missing", f)
		}
		if st, _ := os.Stat(filepath.Join(p.Secrets(), f)); st.Mode().Perm() != 0o600 {
			t.Errorf("secret %s mode %v", f, st.Mode().Perm())
		}
	}
	if st, _ := os.Stat(p.Secrets()); st.Mode().Perm() != 0o700 {
		t.Errorf("secrets dir mode %v", st.Mode().Perm())
	}
	pw, _ := sec.Read(secrets.BootstrapAdmin)
	env := read(t, p.StartupEnv())
	if !strings.Contains(env, "BOOTSTRAP_ADMIN_PASSWORD_PLAIN='"+pw+"'") {
		t.Errorf("startup env: %s", env)
	}
	key, _ := sec.Read(secrets.APIKey)
	keys := read(t, filepath.Join(p.BootstrapDir(), "api_keys.json"))
	if !strings.Contains(keys, strings.SplitN(key, "$", 2)[1]) {
		t.Error("api_keys.json does not contain the API key secret")
	}
	toml := read(t, p.RauthyConfig())
	enc, _ := sec.Read(secrets.EncKey)
	if !strings.Contains(toml, enc) || !strings.Contains(toml, `data_dir = "`+p.RauthyData()+`"`) {
		t.Error("rauthy config incomplete")
	}
	if !strings.Contains(read(t, p.Caddyfile()), "wiki.example.com {") {
		t.Error("Caddyfile not written")
	}
	st, _ := state.NewStore(p.DataDir).Load()
	if st.RPID != "auth.example.com" {
		t.Errorf("rp_id not recorded: %q", st.RPID)
	}

	// Init again before Rauthy ever answered: the bootstrap material is
	// kept with the same values.
	if err := Init(p, quietLog()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, p.StartupEnv()), pw) {
		t.Error("an interrupted first start must reuse the same admin password")
	}

	// Second start after Rauthy was initialised: no bootstrap material,
	// same secrets.
	stStore := state.NewStore(p.DataDir)
	st0, _ := stStore.Load()
	st0.RauthyInitialized = true
	stStore.Save(st0)
	if err := Init(p, quietLog()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.BootstrapDir()); err == nil {
		t.Error("bootstrap dir should be removed after the first start")
	}
	if _, err := os.Stat(p.StartupEnv()); err == nil {
		t.Error("startup env should be removed after the first start")
	}
	if enc2, _ := sec.Read(secrets.EncKey); enc2 != enc {
		t.Error("encryption key must never change")
	}
}

func TestInitInvalidConfigFallsBack(t *testing.T) {
	p := setup(t)
	if err := Init(p, quietLog()); err != nil {
		t.Fatal(err)
	}
	before := read(t, p.Caddyfile())
	writeGuard(t, p, baseCfg, wikiApp, badApp)
	if err := Init(p, quietLog()); err != nil {
		t.Fatalf("invalid config with a previous working one must not fail: %v", err)
	}
	if read(t, p.Caddyfile()) != before {
		t.Error("previous Caddyfile must be kept")
	}

	// Without a previous configuration the start fails.
	p2 := setup(t)
	writeGuard(t, p2, baseCfg, badApp)
	if err := Init(p2, quietLog()); err == nil {
		t.Error("first start with invalid config must fail")
	}
}

func TestInitRefusesRPIDChange(t *testing.T) {
	p := setup(t)
	if err := Init(p, quietLog()); err != nil {
		t.Fatal(err)
	}
	os.Remove(p.Caddyfile()) // no fallback, so the error surfaces
	writeGuard(t, p, strings.Replace(baseCfg, "auth.example.com", "login.example.com", 1), wikiApp)
	err := Init(p, quietLog())
	if err == nil || !strings.Contains(err.Error(), "rp_id changed") {
		t.Fatalf("expected rp_id error, got %v", err)
	}
	t.Setenv(AllowRPIDChangeEnv, AllowRPIDChangeValue)
	if err := Init(p, quietLog()); err != nil {
		t.Fatalf("explicit override should work: %v", err)
	}
}

// fakeRauthy is a minimal HTTP Rauthy for the daemon test.
type fakeRauthy struct {
	mu      sync.Mutex
	key     string
	clients map[string]map[string]any
	login   bool
}

func (f *fakeRauthy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/auth/v1")
	if path == "/ping" || path == "/health" {
		return
	}
	if r.Header.Get("Authorization") != "API-Key "+f.key {
		w.WriteHeader(401)
		return
	}
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	switch {
	case path == "/clients" && r.Method == "GET":
		out := []map[string]any{}
		for _, c := range f.clients {
			out = append(out, c)
		}
		json.NewEncoder(w).Encode(out)
	case path == "/clients" && r.Method == "POST":
		f.clients[body["id"].(string)] = body
		json.NewEncoder(w).Encode(body)
	case strings.HasPrefix(path, "/clients/") && r.Method == "PUT":
		id := strings.TrimPrefix(path, "/clients/")
		body["id"] = id
		f.clients[id] = body
		json.NewEncoder(w).Encode(body)
	case path == "/roles" || path == "/groups":
		w.Write([]byte("[]"))
	case path == "/password_policy":
	case strings.HasPrefix(path, "/users/email/"):
		u := map[string]any{"id": "u1", "email": strings.TrimPrefix(path, "/users/email/"), "roles": []string{"rauthy_admin"}}
		if f.login {
			u["last_login"] = 1700000000
		}
		json.NewEncoder(w).Encode(u)
	default:
		w.WriteHeader(404)
	}
}

func TestDaemonSync(t *testing.T) {
	p := setup(t)
	if err := Init(p, quietLog()); err != nil {
		t.Fatal(err)
	}
	key, _ := secrets.New(p.Secrets()).Read(secrets.APIKey)
	fr := &fakeRauthy{key: key, clients: map[string]map[string]any{}}
	rsrv := httptest.NewServer(fr)
	defer rsrv.Close()

	var loads []string
	var lmu sync.Mutex
	csrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" {
			b, _ := io.ReadAll(r.Body)
			lmu.Lock()
			loads = append(loads, string(b))
			lmu.Unlock()
		}
	}))
	defer csrv.Close()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	healthAddr := ln.Addr().String()
	ln.Close()

	d := NewDaemon(p, quietLog(), "test")
	d.RauthyURL = rsrv.URL
	d.HealthAddr = healthAddr
	d.SetCaddyAdmin(&caddy.Admin{URL: csrv.URL, HTTP: csrv.Client()})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	defer func() { cancel(); <-done }()

	waitFor(t, "client created", func() bool {
		fr.mu.Lock()
		defer fr.mu.Unlock()
		c, ok := fr.clients["wiki"]
		return ok && c["flows_enabled"] != nil
	})
	waitFor(t, "first-start files removed", func() bool {
		_, err1 := os.Stat(p.BootstrapDir())
		_, err2 := os.Stat(p.StartupEnv())
		return os.IsNotExist(err1) && os.IsNotExist(err2)
	})
	if !secrets.New(p.Secrets()).Exists(secrets.BootstrapAdmin) {
		t.Error("admin password file must stay until the first login")
	}
	lmu.Lock()
	if len(loads) != 0 {
		t.Errorf("unchanged Caddyfile must not be reloaded, got %d loads", len(loads))
	}
	lmu.Unlock()

	// Adding an application reloads Caddy and creates a client.
	writeGuard(t, p, baseCfg, wikiApp, blogApp)
	waitFor(t, "caddy reloaded with blog", func() bool {
		lmu.Lock()
		defer lmu.Unlock()
		return len(loads) > 0 && strings.Contains(loads[len(loads)-1], "blog.example.com {")
	})
	waitFor(t, "blog client", func() bool {
		fr.mu.Lock()
		defer fr.mu.Unlock()
		_, ok := fr.clients["blog"]
		return ok
	})
	if !strings.Contains(read(t, p.Caddyfile()), "blog.example.com {") {
		t.Error("accepted Caddyfile must be saved as last-good")
	}

	// An invalid file keeps the running configuration and shows up in /health.
	writeGuard(t, p, baseCfg, wikiApp, blogApp, badApp)
	waitFor(t, "config error reported", func() bool {
		resp, err := http.Get("http://" + healthAddr + "/health/detail")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var r struct {
			Status      string `json:"status"`
			ConfigError string `json:"config_error"`
		}
		json.NewDecoder(resp.Body).Decode(&r)
		return r.Status == "degraded" && strings.Contains(r.ConfigError, "applications[2] (Broken!)")
	})
	resp, err := http.Get("http://" + healthAddr + "/health/public")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(b), "Broken") || !strings.Contains(string(b), `"status"`) {
		t.Errorf("public health must only expose the status: %s", b)
	}

	// After the admin's first login the one-time password file disappears.
	fr.mu.Lock()
	fr.login = true
	fr.mu.Unlock()
	writeGuard(t, p, baseCfg, wikiApp, blogApp)
	waitFor(t, "bootstrap password removed", func() bool {
		return !secrets.New(p.Secrets()).Exists(secrets.BootstrapAdmin)
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestNameFromEmail(t *testing.T) {
	for in, want := range map[string]string{
		"anna.k@example.com":   "anna.k",
		"john+tag@example.com": "johntag",
		"__@x":                 "User",
		"Миша@пример.рф":       "Миша",
	} {
		if got := nameFromEmail(in); got != want {
			t.Errorf("nameFromEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
