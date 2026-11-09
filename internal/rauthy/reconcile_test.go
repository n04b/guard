package rauthy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n04b/guard/internal/config"
	"github.com/n04b/guard/internal/secrets"
	"github.com/n04b/guard/internal/state"
)

// fakeAPI is an in-memory Rauthy.
type fakeAPI struct {
	clients map[string]*ClientResponse
	roles   []string
	groups  []string
	policy  *PasswordPolicyRequest
	calls   []string
}

func newFake() *fakeAPI { return &fakeAPI{clients: map[string]*ClientResponse{}} }

func (f *fakeAPI) ListClients(context.Context) ([]ClientResponse, error) {
	f.calls = append(f.calls, "list")
	var out []ClientResponse
	for _, c := range f.clients {
		out = append(out, *c)
	}
	return out, nil
}

func (f *fakeAPI) CreateClient(_ context.Context, r ClientRequest) (*ClientResponse, error) {
	f.calls = append(f.calls, "create "+r.ID)
	c := &ClientResponse{ID: r.ID, Name: r.Name, Confidential: r.Confidential, RedirectURIs: r.RedirectURIs,
		Enabled: true, FlowsEnabled: []string{"authorization_code"}, AccessTokenAlg: "EdDSA", IDTokenAlg: "EdDSA",
		AuthCodeLifetime: 60, AccessTokenLifetime: 1800, Scopes: []string{"openid"}, DefaultScopes: []string{"openid"}}
	if !r.Confidential {
		c.Challenges = []string{"S256"}
	}
	f.clients[r.ID] = c
	return c, nil
}

func (f *fakeAPI) UpdateClient(_ context.Context, id string, r ClientRequest) (*ClientResponse, error) {
	f.calls = append(f.calls, "update "+id)
	c := f.clients[id]
	*c = ClientResponse{ID: id, Name: r.Name, Enabled: r.Enabled, Confidential: r.Confidential,
		RedirectURIs: r.RedirectURIs, PostLogoutRedirectURIs: r.PostLogoutRedirectURIs, AllowedOrigins: r.AllowedOrigins,
		FlowsEnabled: r.FlowsEnabled, AccessTokenAlg: r.AccessTokenAlg, IDTokenAlg: r.IDTokenAlg,
		AuthCodeLifetime: r.AuthCodeLifetime, AccessTokenLifetime: r.AccessTokenLifetime,
		// Rauthy may return scopes in a different order.
		Scopes: reverse(r.Scopes), DefaultScopes: r.DefaultScopes, Challenges: r.Challenges, ForceMFA: r.ForceMFA,
		BackchannelLogoutURI: r.BackchannelLogoutURI, RestrictGroupPrefix: r.RestrictGroupPrefix}
	return c, nil
}

func (f *fakeAPI) DeleteClient(_ context.Context, id string) error {
	f.calls = append(f.calls, "delete "+id)
	delete(f.clients, id)
	return nil
}

func (f *fakeAPI) ClientSecret(_ context.Context, id string) (string, error) {
	f.calls = append(f.calls, "secret "+id)
	return "s3cr3t-" + id, nil
}

func (f *fakeAPI) ListRoles(context.Context) ([]string, error)  { return f.roles, nil }
func (f *fakeAPI) ListGroups(context.Context) ([]string, error) { return f.groups, nil }
func (f *fakeAPI) CreateRole(_ context.Context, n string) error {
	f.roles = append(f.roles, n)
	f.calls = append(f.calls, "role "+n)
	return nil
}
func (f *fakeAPI) CreateGroup(_ context.Context, n string) error {
	f.groups = append(f.groups, n)
	f.calls = append(f.calls, "group "+n)
	return nil
}
func (f *fakeAPI) PutPasswordPolicy(_ context.Context, p PasswordPolicyRequest) error {
	f.policy = &p
	return nil
}

func reverse(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

func (f *fakeAPI) mutations() []string {
	var out []string
	for _, c := range f.calls {
		if c != "list" {
			out = append(out, c)
		}
	}
	return out
}

// loadCfg builds guard.yml from a base plus application list items.
func loadCfg(t *testing.T, apps ...string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	content := `
server: {hostname: auth.example.com}
admin: {bootstrap_email: a@example.com}
security:
  roles: [editor]
  groups: [team]
  password_policy: {min_length: 14, require_digits: 1}
applications:
` + strings.Join(apps, "")
	if len(apps) == 0 {
		content += "  []\n"
	}
	if err := os.WriteFile(filepath.Join(dir, config.FileName), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

const proxyApp = `
  - name: wiki
    domain: wiki.example.com
    upstream: {host: wiki, port: 3000}
    auth: {mode: proxy, restrict_group_prefix: team}
`

const spaApp = `
  - name: spa
    domain: spa.example.com
    upstream: {host: spa, port: 80}
    on_remove: delete
    auth:
      mode: app
      client_type: confidential
      redirect_uris: [https://spa.example.com/callback]
`

func newReconciler(t *testing.T, api API) (*Reconciler, *secrets.Store) {
	store := secrets.New(t.TempDir())
	return &Reconciler{API: api, Secrets: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, store
}

func TestReconcileLifecycle(t *testing.T) {
	api := newFake()
	r, store := newReconciler(t, api)
	st := &state.State{ManagedClients: map[string]state.ManagedClient{}}

	cfg := loadCfg(t, proxyApp, spaApp)
	res := r.Reconcile(context.Background(), cfg, st)
	if err := res.Err(); err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 2 {
		t.Fatalf("created = %v", res.Created)
	}
	wiki := api.clients["wiki"]
	if !wiki.Confidential || wiki.Challenges != nil {
		t.Errorf("forward-auth client must be confidential without PKCE: %+v", wiki)
	}
	if wiki.RedirectURIs[0] != "https://wiki.example.com/.guard/callback" ||
		wiki.AllowedOrigins[0] != "https://wiki.example.com" {
		t.Errorf("forward-auth uris: %v %v", wiki.RedirectURIs, wiki.AllowedOrigins)
	}
	if wiki.RestrictGroupPrefix == nil || *wiki.RestrictGroupPrefix != "team" {
		t.Errorf("restrict_group_prefix not applied")
	}
	if wiki.AccessTokenAlg != "RS256" {
		t.Errorf("default alg = %s", wiki.AccessTokenAlg)
	}
	spa := api.clients["spa"]
	if len(spa.Challenges) != 1 || spa.Challenges[0] != "S256" {
		t.Errorf("app client must use PKCE: %v", spa.Challenges)
	}
	if v, _ := store.Read(secrets.ClientSecretName("spa")); v != "s3cr3t-spa" {
		t.Errorf("client secret file = %q", v)
	}
	if store.Exists(secrets.ClientSecretName("wiki")) {
		t.Error("proxy apps must not get a secret file")
	}
	if strings.Join(api.roles, ",") != "editor" || strings.Join(api.groups, ",") != "team" {
		t.Errorf("roles %v groups %v", api.roles, api.groups)
	}
	if api.policy == nil || api.policy.LengthMin != 14 || api.policy.IncludeDigits == nil || api.policy.IncludeUpperCase != nil {
		t.Errorf("policy = %+v", api.policy)
	}

	// Second run: nothing to do.
	api.calls = nil
	res = r.Reconcile(context.Background(), cfg, st)
	if res.Changed() || len(api.mutations()) != 0 {
		t.Fatalf("second run should be a no-op, got %v", api.mutations())
	}

	// Drift in Rauthy is corrected.
	api.clients["wiki"].ForceMFA = true
	res = r.Reconcile(context.Background(), cfg, st)
	if len(res.Updated) != 1 || api.clients["wiki"].ForceMFA {
		t.Fatalf("drift not corrected: %+v", res)
	}

	// Removing apps: wiki is disabled (default), spa deleted (on_remove: delete).
	cfg = loadCfg(t)
	res = r.Reconcile(context.Background(), cfg, st)
	if err := res.Err(); err != nil {
		t.Fatal(err)
	}
	if api.clients["wiki"].Enabled || !st.ManagedClients["wiki"].Disabled {
		t.Error("wiki should be disabled")
	}
	if _, ok := api.clients["spa"]; ok {
		t.Error("spa should be deleted")
	}
	if _, ok := st.ManagedClients["spa"]; ok {
		t.Error("spa should be forgotten")
	}
	if store.Exists(secrets.ClientSecretName("spa")) {
		t.Error("spa secret should be removed")
	}

	// Re-adding wiki enables it again.
	cfg = loadCfg(t, proxyApp)
	r.Reconcile(context.Background(), cfg, st)
	if !api.clients["wiki"].Enabled || st.ManagedClients["wiki"].Disabled {
		t.Error("wiki should be enabled again")
	}
}

func TestUnmanagedClientIsNotTouched(t *testing.T) {
	api := newFake()
	api.clients["wiki"] = &ClientResponse{ID: "wiki", Enabled: true}
	r, _ := newReconciler(t, api)
	st := &state.State{ManagedClients: map[string]state.ManagedClient{}}
	res := r.Reconcile(context.Background(), loadCfg(t, proxyApp), st)
	if res.Err() == nil || !strings.Contains(res.Err().Error(), "not created by Guard") {
		t.Fatalf("expected conflict error, got %v", res.Err())
	}
	for _, c := range api.mutations() {
		if strings.Contains(c, "wiki") {
			t.Errorf("unmanaged client touched: %s", c)
		}
	}
}
