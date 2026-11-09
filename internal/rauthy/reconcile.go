package rauthy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sort"

	"github.com/n04b/guard/internal/config"
	"github.com/n04b/guard/internal/secrets"
	"github.com/n04b/guard/internal/state"
)

// API is the part of the Rauthy API the reconciler uses. It is an
// interface so tests can use a fake.
type API interface {
	ListClients(ctx context.Context) ([]ClientResponse, error)
	CreateClient(ctx context.Context, req ClientRequest) (*ClientResponse, error)
	UpdateClient(ctx context.Context, id string, req ClientRequest) (*ClientResponse, error)
	DeleteClient(ctx context.Context, id string) error
	ClientSecret(ctx context.Context, id string) (string, error)
	ListRoles(ctx context.Context) ([]string, error)
	ListGroups(ctx context.Context) ([]string, error)
	CreateRole(ctx context.Context, name string) error
	CreateGroup(ctx context.Context, name string) error
	PutPasswordPolicy(ctx context.Context, p PasswordPolicyRequest) error
}

// Reconciler applies the YAML configuration to Rauthy.
type Reconciler struct {
	API     API
	Secrets *secrets.Store
	Log     *slog.Logger
}

// Result summarises one reconciliation.
type Result struct {
	Created, Updated, Disabled, Deleted []string
	Errors                              []error
}

func (r *Result) Changed() bool {
	return len(r.Created)+len(r.Updated)+len(r.Disabled)+len(r.Deleted) > 0
}

// Err joins all errors.
func (r *Result) Err() error { return errors.Join(r.Errors...) }

// Reconcile makes Rauthy match cfg. st is updated in place; the caller
// saves it. Errors for one client do not stop the others.
func (r *Reconciler) Reconcile(ctx context.Context, cfg *config.Config, st *state.State) *Result {
	res := &Result{}
	fail := func(err error) {
		r.Log.Error("rauthy sync", "err", err)
		res.Errors = append(res.Errors, err)
	}

	if err := r.ensureNames(ctx, "role", cfg.Security.Roles, r.API.ListRoles, r.API.CreateRole); err != nil {
		fail(err)
	}
	if err := r.ensureNames(ctx, "group", cfg.Security.Groups, r.API.ListGroups, r.API.CreateGroup); err != nil {
		fail(err)
	}
	if err := r.API.PutPasswordPolicy(ctx, PasswordPolicy(cfg.Security.PasswordPolicy)); err != nil {
		fail(fmt.Errorf("password policy: %w", err))
	}

	existing, err := r.API.ListClients(ctx)
	if err != nil {
		fail(fmt.Errorf("list clients: %w", err))
		return res
	}
	byID := make(map[string]*ClientResponse, len(existing))
	for i := range existing {
		byID[existing[i].ID] = &existing[i]
	}

	desiredIDs := map[string]bool{}
	for _, app := range cfg.ManagedApps() {
		id := app.Auth.ClientID
		desiredIDs[id] = true
		if err := r.applyClient(ctx, cfg, app, byID[id], st, res); err != nil {
			fail(fmt.Errorf("%s (client %s): %w", app.File, id, err))
		}
	}

	// Clients guard-sync created whose application is gone.
	ids := make([]string, 0, len(st.ManagedClients))
	for id := range st.ManagedClients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if desiredIDs[id] {
			continue
		}
		if err := r.removeClient(ctx, id, byID[id], st, res); err != nil {
			fail(fmt.Errorf("remove client %s: %w", id, err))
		}
	}
	return res
}

func (r *Reconciler) ensureNames(ctx context.Context, kind string, want []string,
	list func(context.Context) ([]string, error), create func(context.Context, string) error) error {
	if len(want) == 0 {
		return nil
	}
	have, err := list(ctx)
	if err != nil {
		return fmt.Errorf("list %ss: %w", kind, err)
	}
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	var errs []error
	for _, w := range want {
		if set[w] {
			continue
		}
		if err := create(ctx, w); err != nil {
			errs = append(errs, fmt.Errorf("create %s %s: %w", kind, w, err))
			continue
		}
		r.Log.Info("created "+kind, "name", w)
	}
	return errors.Join(errs...)
}

func (r *Reconciler) applyClient(ctx context.Context, cfg *config.Config, app *config.Application,
	cur *ClientResponse, st *state.State, res *Result) error {
	id := app.Auth.ClientID
	want := DesiredClient(cfg, app)
	managed, isManaged := st.ManagedClients[id]

	if cur == nil {
		create := want
		create.ID = id
		if _, err := r.API.CreateClient(ctx, create); err != nil {
			return fmt.Errorf("create: %w", err)
		}
		st.ManagedClients[id] = state.ManagedClient{App: app.Name, OnRemove: string(app.OnRemove)}
		if _, err := r.API.UpdateClient(ctx, id, want); err != nil {
			return fmt.Errorf("configure new client: %w", err)
		}
		r.Log.Info("created client", "client_id", id, "app", app.Name)
		res.Created = append(res.Created, id)
	} else {
		if !isManaged {
			return fmt.Errorf("a client with this id already exists in Rauthy but was not created by Guard; " +
				"delete it in the Admin UI or pick another client_id")
		}
		if !ClientEqual(want, cur.AsRequest()) {
			if _, err := r.API.UpdateClient(ctx, id, want); err != nil {
				return fmt.Errorf("update: %w", err)
			}
			r.Log.Info("updated client", "client_id", id, "app", app.Name)
			res.Updated = append(res.Updated, id)
		}
		managed.App = app.Name
		managed.OnRemove = string(app.OnRemove)
		managed.Disabled = false
		st.ManagedClients[id] = managed
	}

	return r.ensureSecretFile(ctx, app, want.Confidential)
}

// ensureSecretFile writes the client secret of confidential app-mode
// clients to /data/secrets/clients/<app>.secret.
func (r *Reconciler) ensureSecretFile(ctx context.Context, app *config.Application, confidential bool) error {
	name := secrets.ClientSecretName(app.Name)
	if app.Auth.Mode != config.ModeApp || !confidential {
		return r.Secrets.Remove(name)
	}
	if r.Secrets.Exists(name) {
		return nil
	}
	sec, err := r.API.ClientSecret(ctx, app.Auth.ClientID)
	if err != nil {
		return fmt.Errorf("read client secret: %w", err)
	}
	if err := r.Secrets.Write(name, sec); err != nil {
		return err
	}
	r.Log.Info("wrote client secret", "file", "secrets/"+name)
	return nil
}

func (r *Reconciler) removeClient(ctx context.Context, id string, cur *ClientResponse, st *state.State, res *Result) error {
	m := st.ManagedClients[id]
	if cur == nil {
		delete(st.ManagedClients, id)
		return r.Secrets.Remove(secrets.ClientSecretName(m.App))
	}
	if m.OnRemove == string(config.RemoveDelete) {
		if err := r.API.DeleteClient(ctx, id); err != nil {
			return err
		}
		delete(st.ManagedClients, id)
		r.Log.Info("deleted client", "client_id", id)
		res.Deleted = append(res.Deleted, id)
		return r.Secrets.Remove(secrets.ClientSecretName(m.App))
	}
	if cur.Enabled {
		req := cur.AsRequest()
		req.Enabled = false
		if _, err := r.API.UpdateClient(ctx, id, req); err != nil {
			return err
		}
		r.Log.Info("disabled client", "client_id", id)
		res.Disabled = append(res.Disabled, id)
	}
	m.Disabled = true
	st.ManagedClients[id] = m
	return nil
}

// DesiredClient builds the Rauthy client for an application.
func DesiredClient(cfg *config.Config, app *config.Application) ClientRequest {
	a := app.Auth
	name := app.Name
	if len(name) < 2 {
		name = "app " + name
	}
	confidential := a.Mode == config.ModeProxy || a.ClientType == config.ClientConfidential

	var challenges []string
	if a.Mode == config.ModeApp {
		// PKCE for every OIDC client, public or confidential.
		challenges = []string{"S256"}
	} // forward-auth clients must not have PKCE enabled

	alg := a.SigningAlg
	req := ClientRequest{
		Name:                   &name,
		Confidential:           confidential,
		RedirectURIs:           cfg.EffectiveRedirectURIs(app),
		PostLogoutRedirectURIs: a.PostLogoutRedirectURIs,
		AllowedOrigins:         cfg.EffectiveAllowedOrigins(app),
		Enabled:                true,
		FlowsEnabled:           []string{"authorization_code", "refresh_token"},
		AccessTokenAlg:         alg,
		IDTokenAlg:             alg,
		AuthCodeLifetime:       60,
		AccessTokenLifetime:    a.AccessTokenSeconds,
		Scopes:                 a.Scopes,
		DefaultScopes:          a.Scopes,
		Challenges:             challenges,
		ForceMFA:               a.RequirePasskey,
	}
	if a.BackchannelLogoutURI != "" {
		v := a.BackchannelLogoutURI
		req.BackchannelLogoutURI = &v
	}
	if a.RestrictGroupPrefix != "" {
		v := a.RestrictGroupPrefix
		req.RestrictGroupPrefix = &v
	}
	return req
}

// ClientEqual compares the fields guard-sync manages. Lists whose order
// has no meaning are compared as sets; redirect URIs keep their order
// because Rauthy uses the first one for forward-auth.
func ClientEqual(want, have ClientRequest) bool {
	return strPtrEq(want.Name, have.Name) &&
		want.Confidential == have.Confidential &&
		listEq(want.RedirectURIs, have.RedirectURIs) &&
		setEq(want.PostLogoutRedirectURIs, have.PostLogoutRedirectURIs) &&
		setEq(want.AllowedOrigins, have.AllowedOrigins) &&
		want.Enabled == have.Enabled &&
		setEq(want.FlowsEnabled, have.FlowsEnabled) &&
		want.AccessTokenAlg == have.AccessTokenAlg &&
		want.IDTokenAlg == have.IDTokenAlg &&
		want.AuthCodeLifetime == have.AuthCodeLifetime &&
		want.AccessTokenLifetime == have.AccessTokenLifetime &&
		setEq(want.Scopes, have.Scopes) &&
		setEq(want.DefaultScopes, have.DefaultScopes) &&
		setEq(want.Challenges, have.Challenges) &&
		want.ForceMFA == have.ForceMFA &&
		strPtrEq(want.BackchannelLogoutURI, have.BackchannelLogoutURI) &&
		strPtrEq(want.RestrictGroupPrefix, have.RestrictGroupPrefix) &&
		setEq(want.Contacts, have.Contacts) &&
		strPtrEq(want.ClientURI, have.ClientURI) &&
		jsonEmpty(have.Claims) && jsonEmpty(have.Scim) &&
		len(have.AllowedResources) == 0 && len(have.DefaultAud) == 0
}

func jsonEmpty(m json.RawMessage) bool { return len(m) == 0 || string(m) == "null" }

func strPtrEq(a, b *string) bool {
	av, bv := "", ""
	if a != nil {
		av = *a
	}
	if b != nil {
		bv = *b
	}
	return av == bv
}

func listEq(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func setEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	return listEq(as, bs)
}

// PasswordPolicy converts the YAML policy to Rauthy's request. Zero means
// "not required".
func PasswordPolicy(p config.PasswordPolicy) PasswordPolicyRequest {
	opt := func(v int) *int {
		if v <= 0 {
			return nil
		}
		return &v
	}
	return PasswordPolicyRequest{
		LengthMin:        p.MinLength,
		LengthMax:        p.MaxLength,
		IncludeLowerCase: opt(p.RequireLower),
		IncludeUpperCase: opt(p.RequireUpper),
		IncludeDigits:    opt(p.RequireDigits),
		IncludeSpecial:   opt(p.RequireSpecial),
		ValidDays:        opt(p.ValidDays),
		NotRecentlyUsed:  opt(p.NotRecentlyUsed),
	}
}
