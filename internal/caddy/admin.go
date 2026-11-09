package caddy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Admin talks to Caddy's admin API.
type Admin struct {
	URL  string // http://localhost:2019
	HTTP *http.Client
}

func NewAdmin() *Admin {
	return &Admin{URL: "http://" + AdminAddr, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Load replaces Caddy's running config with the given Caddyfile. Caddy
// validates it first and keeps the old config if it is invalid. force
// reloads even an identical config, e.g. to pick up replaced certificate
// files.
func (a *Admin) Load(ctx context.Context, caddyfile string, force bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL+"/load", strings.NewReader(caddyfile))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/caddyfile")
	if force {
		req.Header.Set("Cache-Control", "must-revalidate")
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(body))
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return fmt.Errorf("caddy rejected config (HTTP %d): %s", resp.StatusCode, msg)
	}
	return nil
}

// Ping checks that the admin API answers.
func (a *Admin) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL+"/config/", nil)
	if err != nil {
		return err
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("caddy admin: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Cert describes the certificate currently stored for a domain.
type Cert struct {
	Issuer   string    `json:"issuer"` // acme, local, custom
	NotAfter time.Time `json:"not_after"`
}

// FindCert looks for the newest certificate for domain in Caddy's
// storage (<caddyDir>/certificates/<issuer>/<domain>/<domain>.crt).
func FindCert(caddyDir, domain string) (*Cert, error) {
	matches, err := filepath.Glob(filepath.Join(caddyDir, "certificates", "*", domain, domain+".crt"))
	if err != nil {
		return nil, err
	}
	var best *Cert
	for _, m := range matches {
		na, err := CertNotAfter(m)
		if err != nil {
			continue
		}
		issuer := filepath.Base(filepath.Dir(filepath.Dir(m)))
		kind := "acme"
		if issuer == "local" {
			kind = "local"
		}
		if best == nil || na.After(best.NotAfter) {
			best = &Cert{Issuer: kind, NotAfter: na}
		}
	}
	if best == nil {
		return nil, os.ErrNotExist
	}
	return best, nil
}

// HasACMECert reports whether a publicly trusted certificate exists.
func HasACMECert(caddyDir, domain string) bool {
	matches, _ := filepath.Glob(filepath.Join(caddyDir, "certificates", "*", domain, domain+".crt"))
	for _, m := range matches {
		if filepath.Base(filepath.Dir(filepath.Dir(m))) != "local" {
			return true
		}
	}
	return false
}

// CertNotAfter returns the expiry of the first certificate in a PEM file.
func CertNotAfter(path string) (time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return time.Time{}, errors.New("no certificate in " + path)
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return time.Time{}, err
		}
		return c.NotAfter, nil
	}
}

// Equal compares two Caddyfiles ignoring trailing whitespace.
func Equal(a, b string) bool {
	return bytes.Equal(bytes.TrimSpace([]byte(a)), bytes.TrimSpace([]byte(b)))
}
