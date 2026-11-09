// Package health serves Guard's status on a loopback listener. Caddy
// exposes /health publicly (status only) and in detail to admin.allow_from.
package health

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

type Level string

const (
	OK       Level = "ok"
	Degraded Level = "degraded"
	Down     Level = "down"
)

// Component is the state of one part of the system.
type Component struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Cert is the certificate state of one domain.
type Cert struct {
	Issuer   string    `json:"issuer,omitempty"`
	NotAfter time.Time `json:"not_after,omitempty"`
	DaysLeft int       `json:"days_left,omitempty"`
	Problem  string    `json:"problem,omitempty"`
}

// Report is the detailed health document.
type Report struct {
	Status      Level                `json:"status"`
	Problems    []string             `json:"problems,omitempty"`
	Version     string               `json:"version"`
	Components  map[string]Component `json:"components"`
	TLSMode     string               `json:"tls_mode"`
	Certs       map[string]Cert      `json:"certificates,omitempty"`
	LastSync    *time.Time           `json:"last_sync,omitempty"`
	LastBackup  *time.Time           `json:"last_backup,omitempty"`
	ConfigError string               `json:"config_error,omitempty"`
	SyncError   string               `json:"sync_error,omitempty"`
	CheckedAt   time.Time            `json:"checked_at"`
}

// Collector builds a fresh report. It is called on every request with a
// short timeout, so it must be cheap.
type Collector func(ctx context.Context) *Report

// Evaluate sets Status and Problems from the other fields.
func (r *Report) Evaluate() {
	r.Status = OK
	r.Problems = nil
	down := func(p string) { r.Status = Down; r.Problems = append(r.Problems, p) }
	degraded := func(p string) {
		if r.Status == OK {
			r.Status = Degraded
		}
		r.Problems = append(r.Problems, p)
	}
	names := make([]string, 0, len(r.Components))
	for n := range r.Components {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if c := r.Components[n]; !c.OK {
			down(n + ": " + c.Detail)
		}
	}
	if r.ConfigError != "" {
		degraded("configuration: " + r.ConfigError)
	}
	if r.SyncError != "" {
		degraded("sync: " + r.SyncError)
	}
	domains := make([]string, 0, len(r.Certs))
	for d := range r.Certs {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	for _, d := range domains {
		if c := r.Certs[d]; c.Problem != "" {
			degraded(d + ": " + c.Problem)
		}
	}
	if r.LastBackup != nil && time.Since(*r.LastBackup) > 48*time.Hour {
		degraded("last database backup is older than 48h")
	}
}

// Server serves the health endpoints.
type Server struct {
	Collect Collector

	mu     sync.Mutex
	cached *Report
	at     time.Time
}

func (s *Server) report(ctx context.Context) *Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Cache briefly so a burst of requests does not hammer Rauthy.
	if s.cached != nil && time.Since(s.at) < 3*time.Second {
		return s.cached
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r := s.Collect(ctx)
	r.Evaluate()
	s.cached, s.at = r, time.Now()
	return r
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/public", func(w http.ResponseWriter, req *http.Request) {
		r := s.report(req.Context())
		writeJSON(w, code(r.Status), map[string]Level{"status": r.Status})
	})
	mux.HandleFunc("GET /health/detail", func(w http.ResponseWriter, req *http.Request) {
		r := s.report(req.Context())
		writeJSON(w, code(r.Status), r)
	})
	return mux
}

// ListenAndServe runs until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func code(l Level) int {
	if l == Down {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
