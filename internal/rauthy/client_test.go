package rauthy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/n04b/guard/internal/config"
)

func TestClientWireFormat(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotMethod = r.Header.Get("Authorization"), r.URL.Path, r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = nil
		json.Unmarshal(b, &gotBody)
		switch {
		case r.URL.Path == "/auth/v1/clients/missing":
			w.WriteHeader(404)
		case r.URL.Path == "/auth/v1/clients/bad":
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"BadRequest","message":"invalid redirect_uri"}`))
		default:
			w.Write([]byte(`{"id":"x","enabled":true,"confidential":false,"redirect_uris":[]}`))
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "guard-sync$abc")
	cfg := &config.Config{}
	cfg.Server.Server.Hostname = "auth.example.com"
	cfg.Server.Server.HTTPSPort = 443
	app := &config.Application{Name: "app", Domain: "app.example.com",
		Auth: config.AppAuth{Mode: config.ModeProxy, Scopes: []string{"openid"}, SigningAlg: "RS256", AccessTokenSeconds: 60}}
	req := DesiredClient(cfg, app)
	req.ID = "app"

	if _, err := c.CreateClient(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "API-Key guard-sync$abc" || gotMethod != "POST" || gotPath != "/auth/v1/clients" {
		t.Errorf("create: %s %s %s", gotMethod, gotPath, gotAuth)
	}
	for _, k := range []string{"id", "name", "confidential", "redirect_uris", "post_logout_redirect_uris"} {
		if _, ok := gotBody[k]; !ok {
			t.Errorf("create body misses %q", k)
		}
	}
	if _, ok := gotBody["flows_enabled"]; ok {
		t.Error("create body must only contain NewClientRequest fields")
	}

	if _, err := c.UpdateClient(context.Background(), "app", req); err != nil {
		t.Fatal(err)
	}
	if gotMethod != "PUT" || gotPath != "/auth/v1/clients/app" {
		t.Errorf("update: %s %s", gotMethod, gotPath)
	}
	if _, ok := gotBody["id"]; ok {
		t.Error("update body must not contain id")
	}
	// Rauthy requires these keys on update.
	for _, k := range []string{"confidential", "redirect_uris", "enabled", "flows_enabled", "access_token_alg",
		"id_token_alg", "auth_code_lifetime", "access_token_lifetime", "scopes", "default_scopes", "force_mfa", "claims_at_root"} {
		if _, ok := gotBody[k]; !ok {
			t.Errorf("update body misses %q", k)
		}
	}
	if gotBody["challenges"] != nil {
		t.Errorf("forward-auth client must send challenges: null, got %v", gotBody["challenges"])
	}

	_, err := c.UpdateClient(context.Background(), "missing", req)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("404 should map to ErrNotFound, got %v", err)
	}
	_, err = c.UpdateClient(context.Background(), "bad", req)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 400 || !strings.Contains(apiErr.Message, "invalid redirect_uri") {
		t.Errorf("error mapping: %v", err)
	}
}

func TestRenderConfig(t *testing.T) {
	cfg := loadCfg(t, nil)
	out, err := RenderConfig(RenderInput{
		Cfg: cfg, DataDir: "/data/rauthy", BootstrapDir: "/run/b", EncKey: "g1/AAAA",
		RaftSecret: `r"aft\`, APISecret: "api",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`pub_url = "auth.example.com"`,
		`rp_origin = "https://auth.example.com:443"`,
		`rp_id = "auth.example.com"`,
		`key_active = "g1"`,
		`secret_raft = "r\"aft\\"`,
		`listen_address = "127.0.0.1"`,
		`proxy_mode = true`,
		`argon2_m_cost = 32768`,
		`user = "x-guard-user"`,
		`[user_registration]` + "\n" + `enable = false`,
		`admin_force_mfa = true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config misses %s\n%s", want, out)
		}
	}
	if strings.Contains(out, "smtp_url") {
		t.Error("smtp must be absent when disabled")
	}
}

func TestRenderAPIKeysJSON(t *testing.T) {
	key, err := NewAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderAPIKeysJSON(key)
	if err != nil {
		t.Fatal(err)
	}
	var keys []struct {
		Name   string            `json:"name"`
		Secret map[string]string `json:"secret"`
		Access []struct {
			Group  string   `json:"group"`
			Rights []string `json:"access_rights"`
		} `json:"access"`
	}
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Name != "guard-sync" || len(keys[0].Secret["Plain"]) != 64 || len(keys[0].Access) != 5 {
		t.Errorf("unexpected api_keys.json: %s", b)
	}
	if _, err := RenderAPIKeysJSON("other$short"); err == nil {
		t.Error("malformed key must be rejected")
	}
}
