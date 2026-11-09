// Package secrets keeps generated credentials in /data/secrets.
//
// Every file is written atomically with mode 0600 inside a 0700
// directory. Values are never logged.
package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Well-known secret file names.
const (
	EncKey         = "rauthy-enc-key"      // "<id>/<base64 32 bytes>"
	RaftSecret     = "hiqlite-raft"        // Hiqlite Raft secret
	APISecret      = "hiqlite-api"         // Hiqlite API secret
	APIKey         = "rauthy-api-key"      // "<name>$<secret>" for the Rauthy Admin API
	BootstrapAdmin = "bootstrap-admin.txt" // one-time admin password
	ClientsDir     = "clients"
)

// APIKeyName is the name of the API key guard-sync uses.
const APIKeyName = "guard-sync"

const (
	alnum   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	special = "-_.!+=@%"
)

// Store is a directory of secret files.
type Store struct{ Dir string }

func New(dir string) *Store { return &Store{Dir: dir} }

func (s *Store) path(name string) string { return filepath.Join(s.Dir, name) }

// Exists reports whether the secret file exists.
func (s *Store) Exists(name string) bool {
	_, err := os.Stat(s.path(name))
	return err == nil
}

// Read returns the trimmed content of a secret file.
func (s *Store) Read(name string) (string, error) {
	b, err := os.ReadFile(s.path(name))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Write stores a secret atomically with mode 0600.
func (s *Store) Write(name, value string) error {
	p := s.path(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return err
	}
	return WriteFileAtomic(p, []byte(value+"\n"), 0o600)
}

// Remove deletes a secret. A missing file is not an error.
func (s *Store) Remove(name string) error {
	err := os.Remove(s.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Ensure returns the existing secret or generates and stores a new one.
// created reports whether a new value was generated.
func (s *Store) Ensure(name string, gen func() (string, error)) (value string, created bool, err error) {
	v, err := s.Read(name)
	if err == nil && v != "" {
		return v, false, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	v, err = gen()
	if err != nil {
		return "", false, err
	}
	if err := s.Write(name, v); err != nil {
		return "", false, err
	}
	return v, true, nil
}

// ClientSecretName returns the secret file name for an application.
func ClientSecretName(app string) string {
	return filepath.Join(ClientsDir, app+".secret")
}

// RandomString returns n characters from the alphabet using crypto/rand.
func RandomString(n int, alphabet string) (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		x, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[x.Int64()])
	}
	return b.String(), nil
}

// Alnum returns a random alphanumeric string.
func Alnum(n int) (string, error) { return RandomString(n, alnum) }

// Password returns a random password of n (at least 8) characters with at
// least one character of each class, so it satisfies typical policies.
func Password(n int) (string, error) {
	if n < 8 {
		n = 8
	}
	for {
		p, err := RandomString(n, alnum+special)
		if err != nil {
			return "", err
		}
		if strings.ContainsAny(p, "abcdefghijklmnopqrstuvwxyz") &&
			strings.ContainsAny(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
			strings.ContainsAny(p, "0123456789") &&
			strings.ContainsAny(p, special) {
			return p, nil
		}
	}
}

// NewEncKey returns a Rauthy encryption key in the form "<id>/<base64>".
func NewEncKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	id := "g" + time.Now().UTC().Format("20060102")
	return id + "/" + base64.StdEncoding.EncodeToString(key), nil
}

// EncKeyID returns the id part of an encryption key.
func EncKeyID(key string) (string, error) {
	id, _, ok := strings.Cut(key, "/")
	if !ok || id == "" {
		return "", fmt.Errorf("malformed encryption key (expected <id>/<base64>)")
	}
	return id, nil
}

// WriteFileAtomic writes data to a temp file and renames it into place.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
