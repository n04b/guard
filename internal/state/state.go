// Package state persists what guard-sync has applied, in /data/guard.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/n04b/guard/internal/secrets"
)

// ManagedClient is an OIDC client created by guard-sync.
type ManagedClient struct {
	App      string `json:"app"`
	OnRemove string `json:"on_remove,omitempty"` // disable | delete
	Disabled bool   `json:"disabled,omitempty"`
}

// State is stored as JSON in <data>/guard/state.json.
type State struct {
	// RPID is the WebAuthn RP ID applied on first start. Changing it breaks
	// every registered passkey, so guard-sync refuses unless told otherwise.
	RPID string `json:"rp_id,omitempty"`

	// RauthyInitialized is set once Rauthy has answered after its first
	// start, i.e. its database and the bootstrap data exist.
	RauthyInitialized bool `json:"rauthy_initialized,omitempty"`

	// ManagedClients maps client_id -> owner application. Only these
	// clients are ever updated, disabled or deleted.
	ManagedClients map[string]ManagedClient `json:"managed_clients,omitempty"`

	// ACMEPendingSince records when a domain first needed an ACME
	// certificate. Used for the optional local-CA fallback.
	ACMEPendingSince map[string]time.Time `json:"acme_pending_since,omitempty"`

	// FallbackDomains are domains switched to the local CA after ACME failed.
	FallbackDomains map[string]bool `json:"fallback_domains,omitempty"`
}

// Store loads and saves the state file.
type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(dataDir string) *Store {
	return &Store{path: filepath.Join(dataDir, "guard", "state.json")}
}

func (s *Store) Path() string { return s.path }

// Load returns the saved state or an empty one.
func (s *Store) Load() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &State{}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		st.init()
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, err
	}
	st.init()
	return st, nil
}

// Save writes the state atomically.
func (s *Store) Save(st *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return secrets.WriteFileAtomic(s.path, append(b, '\n'), 0o600)
}

func (st *State) init() {
	if st.ManagedClients == nil {
		st.ManagedClients = map[string]ManagedClient{}
	}
	if st.ACMEPendingSince == nil {
		st.ACMEPendingSince = map[string]time.Time{}
	}
	if st.FallbackDomains == nil {
		st.FallbackDomains = map[string]bool{}
	}
}
