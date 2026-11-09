// Package config loads and validates Guard's configuration file guard.yml.
//
// guard.yml is Guard's own interface. It is translated into a
// Rauthy config, Rauthy API calls and a Caddyfile by other packages.
package config

import "time"

// Config is the fully loaded and defaulted configuration.
type Config struct {
	Server       ServerFile
	TLS          TLSFile
	Security     SecurityFile
	Applications []Application

	// Dir is the directory the configuration was loaded from.
	Dir string
}

// ---------- top level of guard.yml: server, webauthn, admin, smtp, backup, logging ----------

type ServerFile struct {
	Server   Server   `yaml:"server"`
	WebAuthn WebAuthn `yaml:"webauthn"`
	Admin    Admin    `yaml:"admin"`
	SMTP     SMTP     `yaml:"smtp"`
	Backup   Backup   `yaml:"backup"`
	Logging  Logging  `yaml:"logging"`
}

type Server struct {
	Hostname string `yaml:"hostname"`
	// HTTPPort and HTTPSPort are the public ports browsers use. Inside the
	// container Caddy always listens on 80 and 443 (map them with docker -p).
	HTTPPort  int `yaml:"http_port"`
	HTTPSPort int `yaml:"https_port"`
	// TrustedProxies are CIDRs of reverse proxies / load balancers in front
	// of Guard (for example Cloudflare). Only these may set X-Forwarded-For.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

type WebAuthn struct {
	// RPID is the WebAuthn Relying Party ID. It must not change after the
	// first passkey has been registered.
	RPID   string `yaml:"rp_id"`
	RPName string `yaml:"rp_name"`
}

type Admin struct {
	BootstrapEmail string `yaml:"bootstrap_email"`
	// AllowFrom lists CIDRs that may open the Rauthy Admin UI and the
	// detailed /health output.
	AllowFrom []string `yaml:"allow_from"`
	// RequirePasskey forces admins to use a passkey (Rauthy ADMIN_FORCE_MFA).
	RequirePasskey *bool `yaml:"require_passkey"`
}

type SMTP struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	// PasswordEnv names the environment variable holding the SMTP password.
	// Secrets never live in YAML.
	PasswordEnv string `yaml:"password_env"`
	From        string `yaml:"from"`
	// TLSMode is one of: tls, starttls, plain.
	TLSMode string `yaml:"tls_mode"`
}

type Backup struct {
	// Cron in Rauthy / Hiqlite syntax: "sec min hour day_of_month month day_of_week year".
	Cron     string `yaml:"cron"`
	KeepDays int    `yaml:"keep_days"`
}

type Logging struct {
	// Level is one of: error, warn, info, debug.
	Level string `yaml:"level"`
}

// ---------- tls: ----------

type TLSFile struct {
	TLS TLS `yaml:"tls"`
}

type TLSMode string

const (
	TLSAuto    TLSMode = "auto"
	TLSCustom  TLSMode = "custom"
	TLSACME    TLSMode = "acme"
	TLSLocalCA TLSMode = "local-ca"
)

type TLS struct {
	Mode   TLSMode   `yaml:"mode"`
	Custom CustomTLS `yaml:"custom"`
	ACME   ACME      `yaml:"acme"`
}

type CustomTLS struct {
	Certificate string `yaml:"certificate"`
	PrivateKey  string `yaml:"private_key"`
}

type ACME struct {
	Email string `yaml:"email"`
	// CA is an optional ACME directory URL (for example the Let's Encrypt
	// staging directory). Empty means Caddy's defaults.
	CA string `yaml:"ca"`
	// AllowFallback permits switching a domain to the local CA when no ACME
	// certificate could be obtained within FallbackAfter.
	AllowFallback bool     `yaml:"allow_fallback"`
	FallbackAfter Duration `yaml:"fallback_after"`
}

// ---------- security: ----------

type SecurityFile struct {
	Registration   Registration   `yaml:"registration"`
	PasswordPolicy PasswordPolicy `yaml:"password_policy"`
	Session        Session        `yaml:"session"`
	Hashing        Hashing        `yaml:"hashing"`
	Roles          []string       `yaml:"roles"`
	Groups         []string       `yaml:"groups"`
}

type RegistrationMode string

const (
	RegistrationClosed RegistrationMode = "closed"
	RegistrationOpen   RegistrationMode = "open"
)

type Registration struct {
	Mode RegistrationMode `yaml:"mode"`
	// AllowedEmailDomain restricts open registration to one e-mail domain.
	AllowedEmailDomain string `yaml:"allowed_email_domain"`
}

type PasswordPolicy struct {
	MinLength       int `yaml:"min_length"`
	MaxLength       int `yaml:"max_length"`
	RequireLower    int `yaml:"require_lowercase"`
	RequireUpper    int `yaml:"require_uppercase"`
	RequireDigits   int `yaml:"require_digits"`
	RequireSpecial  int `yaml:"require_special"`
	NotRecentlyUsed int `yaml:"not_recently_used"`
	ValidDays       int `yaml:"valid_days"`
}

type Session struct {
	IdleMinutes int `yaml:"idle_minutes"`
	MaxHours    int `yaml:"max_hours"`
}

type Hashing struct {
	// MemoryMiB is the Argon2id memory cost per hash.
	MemoryMiB   int `yaml:"memory_mib"`
	Iterations  int `yaml:"iterations"`
	Parallelism int `yaml:"parallelism"`
	// MaxParallelHashes limits concurrent hash computations (peak memory is
	// roughly MemoryMiB * MaxParallelHashes).
	MaxParallelHashes int `yaml:"max_parallel_hashes"`
}

// ---------- applications: (list) ----------

type AuthMode string

const (
	ModeProxy AuthMode = "proxy"
	ModeApp   AuthMode = "app"
	ModeNone  AuthMode = "none"
)

type ClientType string

const (
	ClientPublic       ClientType = "public"
	ClientConfidential ClientType = "confidential"
)

type OnRemove string

const (
	RemoveDisable OnRemove = "disable"
	RemoveDelete  OnRemove = "delete"
)

type Application struct {
	Name     string   `yaml:"name"`
	Domain   string   `yaml:"domain"`
	Upstream Upstream `yaml:"upstream"`
	Auth     AppAuth  `yaml:"auth"`
	OnRemove OnRemove `yaml:"on_remove"`

	// File locates the entry for messages, e.g. "applications[2]".
	File string `yaml:"-"`
}

type Upstream struct {
	Host   string `yaml:"host"`
	Port   int    `yaml:"port"`
	Scheme string `yaml:"scheme"`
	// TLSInsecureSkipVerify allows self-signed upstream certificates
	// (only meaningful with scheme https).
	TLSInsecureSkipVerify bool `yaml:"tls_insecure_skip_verify"`
}

type AppAuth struct {
	Mode                   AuthMode   `yaml:"mode"`
	ClientID               string     `yaml:"client_id"`
	ClientType             ClientType `yaml:"client_type"`
	RedirectURIs           []string   `yaml:"redirect_uris"`
	PostLogoutRedirectURIs []string   `yaml:"post_logout_redirect_uris"`
	AllowedOrigins         []string   `yaml:"allowed_origins"`
	BackchannelLogoutURI   string     `yaml:"backchannel_logout_uri"`
	Scopes                 []string   `yaml:"scopes"`
	// RestrictGroupPrefix only lets users in with at least one group that
	// starts with this prefix (Rauthy restrict_group_prefix).
	RestrictGroupPrefix string `yaml:"restrict_group_prefix"`
	// RequirePasskey forces MFA (a passkey) for this application.
	RequirePasskey     bool `yaml:"require_passkey"`
	AccessTokenSeconds int  `yaml:"access_token_seconds"`
	// SigningAlg for ID and access tokens: RS256 (default, widest support),
	// RS384, RS512 or EdDSA.
	SigningAlg string `yaml:"signing_alg"`
}

// Duration is a time.Duration that unmarshals from strings like "10m".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		d.Duration = 0
		return nil
	}
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }
