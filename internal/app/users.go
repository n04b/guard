package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/n04b/guard/internal/config"
	"github.com/n04b/guard/internal/rauthy"
	"github.com/n04b/guard/internal/secrets"
)

// UserOptions are the attributes of a new user.
type UserOptions struct {
	GivenName, FamilyName string
	Language              string
	Roles, Groups         []string
	Admin                 bool
}

func (p Paths) apiClient() (*rauthy.Client, *config.Config, error) {
	cfg, err := config.Load(p.ConfigDir)
	if err != nil {
		return nil, nil, err
	}
	key, err := secrets.New(p.Secrets()).Read(secrets.APIKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read the API key %s: %w", filepath.Join(p.Secrets(), secrets.APIKey), err)
	}
	return rauthy.NewClient(rauthy.InternalURL(), key), cfg, nil
}

// UserAdd creates a user with a random one-time password and returns it.
// Without SMTP this is how people get their first login; they then add a
// passkey on their account page.
func UserAdd(ctx context.Context, p Paths, email string, o UserOptions) (string, error) {
	c, cfg, err := p.apiClient()
	if err != nil {
		return "", err
	}
	if _, err := c.UserByEmail(ctx, email); err == nil {
		return "", fmt.Errorf("user %s already exists (use set-password to issue a new password)", email)
	} else if !errors.Is(err, rauthy.ErrNotFound) {
		return "", err
	}
	roles := append([]string{}, o.Roles...)
	if o.Admin {
		roles = append(roles, "rauthy_admin")
	}
	lang := o.Language
	if lang == "" {
		lang = "en"
	}
	// Rauthy requires a given name by default (user_values.given_name).
	given := o.GivenName
	if given == "" {
		given = nameFromEmail(email)
	}
	nu := rauthy.NewUser{Email: email, Language: lang, Roles: roles, Groups: o.Groups, GivenName: &given}
	if o.FamilyName != "" {
		nu.FamilyName = &o.FamilyName
	}
	if _, err := c.CreateUser(ctx, nu); err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	u, err := c.UserByEmail(ctx, email)
	if err != nil {
		return "", err
	}
	return setPassword(ctx, c, cfg, u)
}

// UserSetPassword gives an existing user a new random password.
func UserSetPassword(ctx context.Context, p Paths, email string) (string, error) {
	c, cfg, err := p.apiClient()
	if err != nil {
		return "", err
	}
	u, err := c.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, rauthy.ErrNotFound) {
			return "", fmt.Errorf("no user with e-mail %s", email)
		}
		return "", err
	}
	return setPassword(ctx, c, cfg, u)
}

func setPassword(ctx context.Context, c *rauthy.Client, cfg *config.Config, u *rauthy.User) (string, error) {
	if u.GivenName == nil || *u.GivenName == "" {
		// The update is validated against Rauthy's user_values rules.
		g := nameFromEmail(u.Email)
		u.GivenName = &g
	}
	pp := cfg.Security.PasswordPolicy
	n := 24
	if pp.MinLength > n {
		n = pp.MinLength
	}
	if pp.MaxLength < n {
		n = pp.MaxLength
	}
	// Make sure every required character class is present often enough.
	for i := 0; i < 50; i++ {
		pw, err := secrets.Password(n)
		if err != nil {
			return "", err
		}
		if satisfies(pw, pp) {
			if err := c.SetPassword(ctx, u, pw); err != nil {
				return "", fmt.Errorf("set password: %w", err)
			}
			return pw, nil
		}
	}
	return "", errors.New("could not generate a password for this password policy; relax require_* or raise max_length")
}

// nameFromEmail derives a given name Rauthy accepts
// ([\p{L}\p{M}\p{N}\p{Zs}'.-]{1,32}) from the local part of an address.
func nameFromEmail(email string) string {
	local, _, _ := strings.Cut(email, "@")
	var b strings.Builder
	for _, r := range local {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' {
			b.WriteRune(r)
		}
		if b.Len() >= 32 {
			break
		}
	}
	if b.Len() == 0 {
		return "User"
	}
	return b.String()
}

func satisfies(pw string, pp config.PasswordPolicy) bool {
	count := func(set string) int {
		n := 0
		for _, r := range pw {
			if strings.ContainsRune(set, r) {
				n++
			}
		}
		return n
	}
	return count("abcdefghijklmnopqrstuvwxyz") >= pp.RequireLower &&
		count("ABCDEFGHIJKLMNOPQRSTUVWXYZ") >= pp.RequireUpper &&
		count("0123456789") >= pp.RequireDigits &&
		count("-_.!+=@%") >= pp.RequireSpecial
}
