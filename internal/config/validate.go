package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
)

var (
	reAppName      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	reClientID     = regexp.MustCompile(`^[a-zA-Z0-9._-]{2,256}$`)
	reRole         = regexp.MustCompile(`^[a-z0-9-_/,:*]{2,64}$`)
	reGroupPrefix  = regexp.MustCompile(`^[a-zA-Z0-9-_/,:*\s]{2,64}$`)
	reHostLabel    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reOrigin       = regexp.MustCompile(`^(http|https)://[a-z0-9.:-]+$`)
	reUpstreamHost = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253})?$`)
	reRPName       = regexp.MustCompile(`^[\p{L}\p{N}\p{Zs}._-]{1,64}$`)
	reCronField    = regexp.MustCompile(`^[0-9*/,\-A-Za-z?]+$`)
)

// KnownScopes are the scopes Rauthy creates by default.
var KnownScopes = map[string]bool{
	"openid": true, "profile": true, "email": true, "groups": true, "address": true, "phone": true,
}

// ValidationError collects all problems so the user can fix them in one go.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid configuration:\n  - " + strings.Join(e.Problems, "\n  - ")
}

type collector struct{ problems []string }

func (c *collector) addf(format string, args ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, args...))
}

// Validate checks the whole configuration. It is called by Load.
func (c *Config) Validate() error {
	v := &collector{}
	c.validateServer(v)
	c.validateTLS(v)
	c.validateSecurity(v)
	c.validateApps(v)
	if len(v.problems) > 0 {
		return &ValidationError{Problems: v.problems}
	}
	return nil
}

func (c *Config) validateServer(v *collector) {
	s := c.Server
	if s.Server.Hostname == "" {
		v.addf("server.hostname is required")
	} else if !IsHostname(s.Server.Hostname) {
		v.addf("server.hostname %q is not a valid host name", s.Server.Hostname)
	}
	checkPort(v, "server.http_port", s.Server.HTTPPort)
	checkPort(v, "server.https_port", s.Server.HTTPSPort)
	if s.Server.HTTPPort == s.Server.HTTPSPort {
		v.addf("server.http_port and server.https_port must differ")
	}
	for _, p := range s.Server.TrustedProxies {
		if _, _, err := net.ParseCIDR(p); err != nil {
			v.addf("server.trusted_proxies: %q is not a CIDR", p)
		}
	}

	rp := s.WebAuthn.RPID
	host := s.Server.Hostname
	if rp != host && !strings.HasSuffix(host, "."+rp) {
		v.addf("webauthn.rp_id %q must equal server.hostname or be a parent domain of it", rp)
	}
	if !reRPName.MatchString(s.WebAuthn.RPName) {
		v.addf("webauthn.rp_name %q contains unsupported characters", s.WebAuthn.RPName)
	}

	if s.Admin.BootstrapEmail == "" {
		v.addf("admin.bootstrap_email is required")
	} else if !isEmail(s.Admin.BootstrapEmail) {
		v.addf("admin.bootstrap_email %q is not an e-mail address", s.Admin.BootstrapEmail)
	}
	for _, p := range s.Admin.AllowFrom {
		if _, _, err := net.ParseCIDR(p); err != nil {
			v.addf("admin.allow_from: %q is not a CIDR (use 1.2.3.4/32 for a single address)", p)
		}
	}

	if s.SMTP.Enabled {
		if s.SMTP.Host == "" {
			v.addf("smtp.host is required when smtp.enabled is true")
		}
		checkPort(v, "smtp.port", s.SMTP.Port)
		if s.SMTP.From == "" {
			v.addf("smtp.from is required when smtp.enabled is true")
		}
		switch s.SMTP.TLSMode {
		case "tls", "starttls", "plain":
		default:
			v.addf("smtp.tls_mode must be tls, starttls or plain")
		}
	}

	fields := strings.Fields(s.Backup.Cron)
	if len(fields) != 7 {
		v.addf("backup.cron must have 7 fields (sec min hour day month weekday year), got %q", s.Backup.Cron)
	} else {
		for _, f := range fields {
			if !reCronField.MatchString(f) {
				v.addf("backup.cron field %q is invalid", f)
				break
			}
		}
	}
	if s.Backup.KeepDays < 1 || s.Backup.KeepDays > 3650 {
		v.addf("backup.keep_days must be between 1 and 3650")
	}
	switch s.Logging.Level {
	case "error", "warn", "info", "debug":
	default:
		v.addf("logging.level must be error, warn, info or debug")
	}
}

func (c *Config) validateTLS(v *collector) {
	t := c.TLS.TLS
	switch t.Mode {
	case TLSAuto, TLSCustom, TLSLocalCA:
	case TLSACME:
		if t.ACME.Email == "" {
			v.addf("tls.acme.email is required for mode acme")
		}
		for _, h := range c.AllHostnames() {
			if !IsPublicHostname(h) {
				v.addf("tls.mode acme needs public domains, %q is not one (use local-ca)", h)
			}
		}
	default:
		v.addf("tls.mode must be auto, custom, acme or local-ca, got %q", t.Mode)
	}
	if t.ACME.Email != "" && !isEmail(t.ACME.Email) {
		v.addf("tls.acme.email %q is not an e-mail address", t.ACME.Email)
	}
	if t.ACME.CA != "" {
		if u, err := url.Parse(t.ACME.CA); err != nil || u.Scheme != "https" || u.Host == "" {
			v.addf("tls.acme.ca must be an https URL")
		}
	}
	if t.ACME.FallbackAfter.Duration < 0 {
		v.addf("tls.acme.fallback_after must be positive")
	}
}

func (c *Config) validateSecurity(v *collector) {
	s := c.Security
	switch s.Registration.Mode {
	case RegistrationClosed:
	case RegistrationOpen:
		if !c.Server.SMTP.Enabled {
			v.addf("security.registration.mode open needs SMTP (new users set their password via an e-mail link); enable smtp or use closed")
		}
	default:
		v.addf("security.registration.mode must be closed or open, got %q", s.Registration.Mode)
	}
	if d := s.Registration.AllowedEmailDomain; d != "" && !IsHostname(strings.ToLower(d)) {
		v.addf("security.registration.allowed_email_domain %q is not a domain", d)
	}

	p := s.PasswordPolicy
	if p.MinLength < 8 || p.MinLength > 128 {
		v.addf("security.password_policy.min_length must be between 8 and 128")
	}
	if p.MaxLength < 8 || p.MaxLength > 128 || p.MaxLength < p.MinLength {
		v.addf("security.password_policy.max_length must be between min_length and 128")
	}
	for name, n := range map[string]int{
		"require_lowercase": p.RequireLower, "require_uppercase": p.RequireUpper,
		"require_digits": p.RequireDigits, "require_special": p.RequireSpecial,
	} {
		if n < 0 || n > 32 {
			v.addf("security.password_policy.%s must be between 0 and 32", name)
		}
	}
	if p.NotRecentlyUsed < 0 || p.NotRecentlyUsed > 10 {
		v.addf("security.password_policy.not_recently_used must be between 0 and 10")
	}
	if p.ValidDays < 0 || p.ValidDays > 3650 {
		v.addf("security.password_policy.valid_days must be between 0 and 3650")
	}

	if s.Session.IdleMinutes < 1 {
		v.addf("security.session.idle_minutes must be positive")
	}
	if s.Session.MaxHours < 1 {
		v.addf("security.session.max_hours must be positive")
	}
	if s.Session.IdleMinutes > s.Session.MaxHours*60 {
		v.addf("security.session.idle_minutes must not exceed session.max_hours")
	}

	h := s.Hashing
	if h.MemoryMiB < 8 || h.MemoryMiB > 1024 {
		v.addf("security.hashing.memory_mib must be between 8 and 1024")
	}
	if h.Iterations < 1 || h.Iterations > 16 {
		v.addf("security.hashing.iterations must be between 1 and 16")
	}
	if h.Parallelism < 1 || h.Parallelism > 16 {
		v.addf("security.hashing.parallelism must be between 1 and 16")
	}
	if h.MaxParallelHashes < 1 || h.MaxParallelHashes > 16 {
		v.addf("security.hashing.max_parallel_hashes must be between 1 and 16")
	}

	seen := map[string]bool{}
	for _, r := range s.Roles {
		if !reRole.MatchString(r) {
			v.addf("security.roles: %q must match %s", r, reRole)
		}
		if r == "rauthy_admin" {
			v.addf("security.roles: rauthy_admin is reserved")
		}
		if seen[r] {
			v.addf("security.roles: %q is listed twice", r)
		}
		seen[r] = true
	}
	seen = map[string]bool{}
	for _, g := range s.Groups {
		if !reRole.MatchString(g) {
			v.addf("security.groups: %q must match %s", g, reRole)
		}
		if seen[g] {
			v.addf("security.groups: %q is listed twice", g)
		}
		seen[g] = true
	}
}

func (c *Config) validateApps(v *collector) {
	names := map[string]string{}
	domains := map[string]string{c.Server.Server.Hostname: "server.hostname"}
	clients := map[string]string{}

	for i := range c.Applications {
		a := &c.Applications[i]
		where := a.File
		if where == "" {
			where = "applications"
		}
		if a.Name != "" {
			where += " (" + a.Name + ")"
		}

		if !reAppName.MatchString(a.Name) {
			v.addf("%s: name %q must be lowercase letters, digits and dashes", where, a.Name)
		} else if prev, ok := names[a.Name]; ok {
			v.addf("%s: name %q is already used in %s", where, a.Name, prev)
		} else {
			names[a.Name] = where
		}

		if a.Domain == "" {
			v.addf("%s: domain is required", where)
		} else if !IsHostname(a.Domain) {
			v.addf("%s: domain %q is not a valid host name", where, a.Domain)
		} else if prev, ok := domains[a.Domain]; ok {
			v.addf("%s: domain %q is already used in %s", where, a.Domain, prev)
		} else {
			domains[a.Domain] = where
		}

		if !reUpstreamHost.MatchString(a.Upstream.Host) {
			v.addf("%s: upstream.host %q is invalid", where, a.Upstream.Host)
		}
		checkPort(v, where+": upstream.port", a.Upstream.Port)
		if a.Upstream.Scheme != "http" && a.Upstream.Scheme != "https" {
			v.addf("%s: upstream.scheme must be http or https", where)
		}
		if a.Upstream.TLSInsecureSkipVerify && a.Upstream.Scheme != "https" {
			v.addf("%s: upstream.tls_insecure_skip_verify needs scheme https", where)
		}

		switch a.OnRemove {
		case RemoveDisable, RemoveDelete:
		default:
			v.addf("%s: on_remove must be disable or delete", where)
		}

		c.validateAppAuth(v, a, where, clients)
	}
}

func (c *Config) validateAppAuth(v *collector, a *Application, where string, clients map[string]string) {
	au := a.Auth
	switch au.Mode {
	case ModeNone:
		return
	case ModeProxy, ModeApp:
	default:
		v.addf("%s: auth.mode must be proxy, app or none, got %q", where, au.Mode)
		return
	}

	if !reClientID.MatchString(au.ClientID) {
		v.addf("%s: auth.client_id %q must match %s", where, au.ClientID, reClientID)
	} else if au.ClientID == "rauthy" {
		v.addf("%s: client_id rauthy is reserved", where)
	} else if prev, ok := clients[au.ClientID]; ok {
		v.addf("%s: client_id %q is already used in %s", where, au.ClientID, prev)
	} else {
		clients[au.ClientID] = where
	}

	if au.ClientType != ClientPublic && au.ClientType != ClientConfidential {
		v.addf("%s: auth.client_type must be public or confidential", where)
	}

	if au.Mode == ModeProxy {
		if len(au.RedirectURIs) > 0 {
			v.addf("%s: redirect_uris are generated automatically in mode proxy, remove them", where)
		}
		if au.ClientType == ClientPublic {
			v.addf("%s: client_type public is not supported in mode proxy", where)
		}
		if len(au.AllowedOrigins) > 0 {
			v.addf("%s: allowed_origins are generated automatically in mode proxy, remove them", where)
		}
	} else {
		if len(au.RedirectURIs) == 0 {
			v.addf("%s: auth.redirect_uris is required in mode app", where)
		}
		for _, u := range au.RedirectURIs {
			if err := checkRedirectURI(u); err != nil {
				v.addf("%s: redirect_uri %q: %v", where, u, err)
			}
		}
		for _, o := range au.AllowedOrigins {
			if !reOrigin.MatchString(o) {
				v.addf("%s: allowed_origin %q must look like https://app.example.com", where, o)
			}
		}
	}
	for _, u := range au.PostLogoutRedirectURIs {
		if err := checkRedirectURI(u); err != nil {
			v.addf("%s: post_logout_redirect_uri %q: %v", where, u, err)
		}
	}
	if au.BackchannelLogoutURI != "" {
		if err := checkRedirectURI(au.BackchannelLogoutURI); err != nil {
			v.addf("%s: backchannel_logout_uri: %v", where, err)
		}
	}

	hasOpenID := false
	for _, s := range au.Scopes {
		if !KnownScopes[s] {
			v.addf("%s: unknown scope %q (known: openid, profile, email, groups, address, phone)", where, s)
		}
		if s == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		v.addf("%s: scopes must include openid", where)
	}
	if au.RestrictGroupPrefix != "" && !reGroupPrefix.MatchString(au.RestrictGroupPrefix) {
		v.addf("%s: restrict_group_prefix %q is invalid", where, au.RestrictGroupPrefix)
	}
	if au.AccessTokenSeconds < 10 || au.AccessTokenSeconds > 86400 {
		v.addf("%s: access_token_seconds must be between 10 and 86400", where)
	}
	switch au.SigningAlg {
	case "RS256", "RS384", "RS512", "EdDSA":
	default:
		v.addf("%s: signing_alg must be RS256, RS384, RS512 or EdDSA", where)
	}
}

func checkRedirectURI(raw string) error {
	if strings.ContainsAny(raw, "#,") {
		return errors.New("must not contain # or ,")
	}
	if strings.HasSuffix(raw, "*") {
		return errors.New("wildcards are not allowed")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("must be an absolute URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		h := u.Hostname()
		if h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return errors.New("plain http is only allowed for localhost")
		}
	default:
		return fmt.Errorf("scheme %q is not allowed", u.Scheme)
	}
	return nil
}

func checkPort(v *collector, name string, p int) {
	if p < 1 || p > 65535 {
		v.addf("%s must be between 1 and 65535", name)
	}
}

func isEmail(s string) bool {
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s
}

// IsHostname reports whether s is a syntactically valid DNS host name.
func IsHostname(s string) bool {
	if s == "" || len(s) > 253 || strings.HasSuffix(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !reHostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

var privateSuffixes = []string{".localhost", ".local", ".lan", ".internal", ".home.arpa", ".test", ".example", ".invalid", ".home", ".corp"}

// IsPublicHostname reports whether a certificate for host can be obtained
// from a public ACME CA.
func IsPublicHostname(h string) bool {
	if h == "localhost" || net.ParseIP(h) != nil || !strings.Contains(h, ".") {
		return false
	}
	for _, s := range privateSuffixes {
		if strings.HasSuffix(h, s) {
			return false
		}
	}
	return true
}

// AllHostnames returns the auth host and every application domain.
func (c *Config) AllHostnames() []string {
	out := []string{c.Server.Server.Hostname}
	for _, a := range c.Applications {
		if a.Domain != "" {
			out = append(out, a.Domain)
		}
	}
	return out
}
