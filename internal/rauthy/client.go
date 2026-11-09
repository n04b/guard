package rauthy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNotFound is returned for HTTP 404 responses.
var ErrNotFound = errors.New("not found")

// APIError is a non-2xx answer from Rauthy.
type APIError struct {
	Method, Path string
	Status       int
	Message      string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("rauthy %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Message)
}

// Client calls Rauthy's REST API with an API key.
type Client struct {
	BaseURL string // e.g. http://127.0.0.1:8080
	APIKey  string // "<name>$<secret>"
	HTTP    *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+"/auth/v1"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "API-Key "+c.APIKey)
	}
	// Rauthy runs in proxy mode and expects requests from a trusted proxy
	// with the client IP in X-Forwarded-For.
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s %s: %w", method, path, ErrNotFound)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Message: errorMessage(data)}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s %s: decode response: %w", method, path, err)
		}
	}
	return nil
}

func errorMessage(b []byte) string {
	var e struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(b, &e) == nil && (e.Message != "" || e.Error != "") {
		if e.Message == "" {
			return e.Error
		}
		return e.Message
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// Ping returns nil when Rauthy answers.
func (c *Client) Ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/ping", nil, nil)
}

// Health checks Rauthy's database and cache.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/health", nil, nil)
}

// ---------- clients ----------

// ClientRequest mirrors Rauthy's UpdateClientRequest (and the subset used
// by NewClientRequest).
type ClientRequest struct {
	ID                     string          `json:"id,omitempty"` // create only
	Name                   *string         `json:"name"`
	Confidential           bool            `json:"confidential"`
	RedirectURIs           []string        `json:"redirect_uris"`
	PostLogoutRedirectURIs []string        `json:"post_logout_redirect_uris"`
	AllowedOrigins         []string        `json:"allowed_origins"`
	Enabled                bool            `json:"enabled"`
	FlowsEnabled           []string        `json:"flows_enabled"`
	AccessTokenAlg         string          `json:"access_token_alg"`
	IDTokenAlg             string          `json:"id_token_alg"`
	AuthCodeLifetime       int             `json:"auth_code_lifetime"`
	AccessTokenLifetime    int             `json:"access_token_lifetime"`
	Scopes                 []string        `json:"scopes"`
	DefaultScopes          []string        `json:"default_scopes"`
	Challenges             []string        `json:"challenges"`
	ForceMFA               bool            `json:"force_mfa"`
	ClientURI              *string         `json:"client_uri"`
	Contacts               []string        `json:"contacts"`
	BackchannelLogoutURI   *string         `json:"backchannel_logout_uri"`
	RestrictGroupPrefix    *string         `json:"restrict_group_prefix"`
	Claims                 json.RawMessage `json:"claims,omitempty"`
	ClaimsAtRoot           bool            `json:"claims_at_root"`
	AllowedResources       []string        `json:"allowed_resources"`
	DefaultAud             []string        `json:"default_aud"`
	Scim                   json.RawMessage `json:"scim,omitempty"`
}

// ClientResponse mirrors Rauthy's ClientResponse.
type ClientResponse struct {
	ID                     string          `json:"id"`
	Name                   *string         `json:"name"`
	Enabled                bool            `json:"enabled"`
	Confidential           bool            `json:"confidential"`
	RedirectURIs           []string        `json:"redirect_uris"`
	PostLogoutRedirectURIs []string        `json:"post_logout_redirect_uris"`
	AllowedOrigins         []string        `json:"allowed_origins"`
	FlowsEnabled           []string        `json:"flows_enabled"`
	AccessTokenAlg         string          `json:"access_token_alg"`
	IDTokenAlg             string          `json:"id_token_alg"`
	AuthCodeLifetime       int             `json:"auth_code_lifetime"`
	AccessTokenLifetime    int             `json:"access_token_lifetime"`
	Scopes                 []string        `json:"scopes"`
	DefaultScopes          []string        `json:"default_scopes"`
	Challenges             []string        `json:"challenges"`
	ForceMFA               bool            `json:"force_mfa"`
	ClientURI              *string         `json:"client_uri"`
	Contacts               []string        `json:"contacts"`
	BackchannelLogoutURI   *string         `json:"backchannel_logout_uri"`
	RestrictGroupPrefix    *string         `json:"restrict_group_prefix"`
	Claims                 json.RawMessage `json:"claims"`
	ClaimsAtRoot           bool            `json:"claims_at_root"`
	AllowedResources       []string        `json:"allowed_resources"`
	DefaultAud             []string        `json:"default_aud"`
	Scim                   json.RawMessage `json:"scim"`
}

// AsRequest converts an existing client into an update request that would
// leave it unchanged.
func (r *ClientResponse) AsRequest() ClientRequest {
	return ClientRequest{
		Name:                   r.Name,
		Confidential:           r.Confidential,
		RedirectURIs:           r.RedirectURIs,
		PostLogoutRedirectURIs: r.PostLogoutRedirectURIs,
		AllowedOrigins:         r.AllowedOrigins,
		Enabled:                r.Enabled,
		FlowsEnabled:           r.FlowsEnabled,
		AccessTokenAlg:         r.AccessTokenAlg,
		IDTokenAlg:             r.IDTokenAlg,
		AuthCodeLifetime:       r.AuthCodeLifetime,
		AccessTokenLifetime:    r.AccessTokenLifetime,
		Scopes:                 r.Scopes,
		DefaultScopes:          r.DefaultScopes,
		Challenges:             r.Challenges,
		ForceMFA:               r.ForceMFA,
		ClientURI:              r.ClientURI,
		Contacts:               r.Contacts,
		BackchannelLogoutURI:   r.BackchannelLogoutURI,
		RestrictGroupPrefix:    r.RestrictGroupPrefix,
		Claims:                 nullToEmpty(r.Claims),
		ClaimsAtRoot:           r.ClaimsAtRoot,
		AllowedResources:       r.AllowedResources,
		DefaultAud:             r.DefaultAud,
		Scim:                   nullToEmpty(r.Scim),
	}
}

func nullToEmpty(m json.RawMessage) json.RawMessage {
	if len(m) == 0 || string(m) == "null" {
		return nil
	}
	return m
}

func (c *Client) ListClients(ctx context.Context) ([]ClientResponse, error) {
	var out []ClientResponse
	err := c.do(ctx, http.MethodGet, "/clients", nil, &out)
	return out, err
}

// CreateClient creates a client. Rauthy's create endpoint only accepts
// id, name, confidential and redirect URIs; call UpdateClient afterwards
// for everything else.
func (c *Client) CreateClient(ctx context.Context, req ClientRequest) (*ClientResponse, error) {
	in := map[string]any{
		"id":                        req.ID,
		"name":                      req.Name,
		"confidential":              req.Confidential,
		"redirect_uris":             req.RedirectURIs,
		"post_logout_redirect_uris": req.PostLogoutRedirectURIs,
	}
	var out ClientResponse
	err := c.do(ctx, http.MethodPost, "/clients", in, &out)
	return &out, err
}

func (c *Client) UpdateClient(ctx context.Context, id string, req ClientRequest) (*ClientResponse, error) {
	req.ID = ""
	var out ClientResponse
	err := c.do(ctx, http.MethodPut, "/clients/"+url.PathEscape(id), req, &out)
	return &out, err
}

func (c *Client) DeleteClient(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/clients/"+url.PathEscape(id), nil, nil)
}

// ClientSecret returns the cleartext secret of a confidential client.
func (c *Client) ClientSecret(ctx context.Context, id string) (string, error) {
	var out struct {
		Secret *string `json:"secret"`
	}
	if err := c.do(ctx, http.MethodPost, "/clients/"+url.PathEscape(id)+"/secret", nil, &out); err != nil {
		return "", err
	}
	if out.Secret == nil || *out.Secret == "" {
		return "", fmt.Errorf("client %s has no secret", id)
	}
	return *out.Secret, nil
}

// ---------- roles & groups ----------

type named struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *Client) ListRoles(ctx context.Context) ([]string, error) { return c.listNames(ctx, "/roles") }

func (c *Client) ListGroups(ctx context.Context) ([]string, error) {
	return c.listNames(ctx, "/groups")
}

func (c *Client) listNames(ctx context.Context, path string) ([]string, error) {
	var out []named
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	names := make([]string, len(out))
	for i, n := range out {
		names[i] = n.Name
	}
	return names, nil
}

func (c *Client) CreateRole(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/roles", map[string]any{"role": name}, nil)
}

func (c *Client) CreateGroup(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/groups", map[string]any{"group": name}, nil)
}

// ---------- password policy ----------

type PasswordPolicyRequest struct {
	LengthMin        int  `json:"length_min"`
	LengthMax        int  `json:"length_max"`
	IncludeLowerCase *int `json:"include_lower_case"`
	IncludeUpperCase *int `json:"include_upper_case"`
	IncludeDigits    *int `json:"include_digits"`
	IncludeSpecial   *int `json:"include_special"`
	ValidDays        *int `json:"valid_days"`
	NotRecentlyUsed  *int `json:"not_recently_used"`
}

func (c *Client) PutPasswordPolicy(ctx context.Context, p PasswordPolicyRequest) error {
	return c.do(ctx, http.MethodPut, "/password_policy", p, nil)
}

// ---------- users ----------

// User is the subset of Rauthy's UserResponse guard-sync needs. Raw keeps
// the full object so updates can preserve fields guard-sync does not know.
type User struct {
	ID            string   `json:"id"`
	Email         string   `json:"email"`
	GivenName     *string  `json:"given_name"`
	FamilyName    *string  `json:"family_name"`
	Language      string   `json:"language"`
	Roles         []string `json:"roles"`
	Groups        []string `json:"groups"`
	Enabled       bool     `json:"enabled"`
	EmailVerified bool     `json:"email_verified"`
	LastLogin     *int64   `json:"last_login"`
	UserExpires   *int64   `json:"user_expires"`

	Raw map[string]json.RawMessage `json:"-"`
}

func (c *Client) UserByEmail(ctx context.Context, email string) (*User, error) {
	var raw map[string]json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/users/email/"+url.PathEscape(email), nil, &raw); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(raw)
	u := &User{}
	if err := json.Unmarshal(b, u); err != nil {
		return nil, err
	}
	u.Raw = raw
	return u, nil
}

type NewUser struct {
	Email      string   `json:"email"`
	GivenName  *string  `json:"given_name,omitempty"`
	FamilyName *string  `json:"family_name,omitempty"`
	Language   string   `json:"language"`
	Roles      []string `json:"roles"`
	Groups     []string `json:"groups,omitempty"`
}

func (c *Client) CreateUser(ctx context.Context, u NewUser) (*User, error) {
	if u.Roles == nil {
		u.Roles = []string{}
	}
	var out User
	err := c.do(ctx, http.MethodPost, "/users", u, &out)
	return &out, err
}

// SetPassword sets a user's password and marks the e-mail as verified, keeping
// all other attributes as they are.
func (c *Client) SetPassword(ctx context.Context, u *User, password string) error {
	req := map[string]any{
		"email":          u.Email,
		"given_name":     u.GivenName,
		"family_name":    u.FamilyName,
		"password":       password,
		"roles":          nonNil(u.Roles),
		"groups":         u.Groups,
		"enabled":        u.Enabled,
		"email_verified": true,
		"user_expires":   u.UserExpires,
	}
	if u.Language != "" {
		req["language"] = u.Language
	}
	if v, ok := u.Raw["user_values"]; ok && string(v) != "null" {
		req["user_values"] = v
	}
	return c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(u.ID), req, nil)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
