package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/n04b/guard/internal/caddy"
	"github.com/n04b/guard/internal/config"
	"github.com/n04b/guard/internal/health"
	"github.com/n04b/guard/internal/rauthy"
	"github.com/n04b/guard/internal/secrets"
	"github.com/n04b/guard/internal/state"
)

// Intervals of the sync loop.
const (
	pollInterval    = 2 * time.Second
	resyncInterval  = 5 * time.Minute
	waitingInterval = 3 * time.Second
	fallbackTick    = time.Minute
)

// Daemon keeps Rauthy and Caddy in line with /config.
type Daemon struct {
	P       Paths
	Log     *slog.Logger
	Version string

	// Endpoints; NewDaemon sets the container defaults.
	RauthyURL  string
	HealthAddr string

	stStore *state.Store
	sec     *secrets.Store
	caddy   *caddy.Admin

	mu              sync.Mutex
	cfg             *config.Config // last valid configuration
	configErr       string
	syncErr         string
	lastSync        time.Time
	rauthyReady     bool
	loadedCaddyfile string
	lastErrLogged   string
}

func NewDaemon(p Paths, log *slog.Logger, version string) *Daemon {
	return &Daemon{
		P: p, Log: log, Version: version,
		RauthyURL: rauthy.InternalURL(), HealthAddr: HealthAddr,
		stStore: state.NewStore(p.DataDir),
		sec:     secrets.New(p.Secrets()),
		caddy:   caddy.NewAdmin(),
	}
}

// Run blocks until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	// Caddy was started with this file by the service manager.
	if b, err := os.ReadFile(d.P.Caddyfile()); err == nil {
		d.loadedCaddyfile = string(b)
	}

	hs := &health.Server{Collect: d.collect}
	go func() {
		if err := hs.ListenAndServe(ctx, d.HealthAddr); err != nil {
			d.Log.Error("health server", "err", err)
		}
	}()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	fp, certFP := d.fingerprints()
	d.sync(ctx, false)

	poll := time.NewTicker(pollInterval)
	defer poll.Stop()
	resync := time.NewTicker(resyncInterval)
	defer resync.Stop()
	retry := time.NewTicker(waitingInterval)
	defer retry.Stop()
	fallback := time.NewTicker(fallbackTick)
	defer fallback.Stop()

	for {
		select {
		case <-ctx.Done():
			d.Log.Info("stopping")
			return nil
		case <-hup:
			d.Log.Info("SIGHUP: reloading configuration")
			fp, certFP = d.fingerprints()
			d.sync(ctx, true)
		case <-poll.C:
			nfp, ncert := d.fingerprints()
			if nfp != fp || ncert != certFP {
				d.Log.Info("configuration files changed, applying")
				force := ncert != certFP
				fp, certFP = nfp, ncert
				d.sync(ctx, force)
			}
		case <-retry.C:
			if !d.isReady() {
				d.sync(ctx, false)
			}
		case <-fallback.C:
			if d.fallbackActive() {
				d.sync(ctx, false)
			}
		case <-resync.C:
			d.sync(ctx, false)
		}
	}
}

// sync loads the configuration and applies it. forceCaddy reloads Caddy
// even if the Caddyfile did not change (new certificate files).
func (d *Daemon) sync(ctx context.Context, forceCaddy bool) {
	st, err := d.stStore.Load()
	if err != nil {
		d.setSyncErr(fmt.Errorf("read state: %w", err))
		return
	}

	cfg, err := LoadChecked(d.P, st)
	d.mu.Lock()
	if err != nil {
		d.configErr = err.Error()
		if d.lastErrLogged != d.configErr {
			d.Log.Error("configuration is invalid, keeping the running configuration", "err", err)
			d.lastErrLogged = d.configErr
		}
		cfg = d.cfg
	} else {
		if d.configErr != "" {
			d.Log.Info("configuration is valid again")
		}
		d.configErr, d.lastErrLogged = "", ""
		d.cfg = cfg
	}
	d.mu.Unlock()
	if cfg == nil {
		return
	}

	var errs []error
	if err := d.applyCaddy(ctx, cfg, st, forceCaddy); err != nil {
		errs = append(errs, err)
	}
	ready, err := d.applyRauthy(ctx, cfg, st)
	if err != nil {
		errs = append(errs, err)
	}
	if err := d.stStore.Save(st); err != nil {
		errs = append(errs, fmt.Errorf("save state: %w", err))
	}

	d.mu.Lock()
	d.rauthyReady = ready
	if len(errs) == 0 && ready {
		d.lastSync = time.Now()
	}
	d.mu.Unlock()
	d.setSyncErr(errors.Join(errs...))
}

func (d *Daemon) applyCaddy(ctx context.Context, cfg *config.Config, st *state.State, force bool) error {
	mode := cfg.ResolveTLSMode()
	d.updateFallbacks(cfg, mode, st)
	cf := caddy.Render(caddy.Input{
		Cfg: cfg, Mode: mode, FallbackDomains: activeFallbacks(cfg, st),
		CADir: d.P.CADir(), HealthAddr: HealthAddr,
	})
	if !force && caddy.Equal(cf, d.loadedCaddyfile) {
		return nil
	}
	lctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := d.caddy.Load(lctx, cf, force); err != nil {
		return fmt.Errorf("caddy: %w", err)
	}
	if err := secrets.WriteFileAtomic(d.P.Caddyfile(), []byte(cf), 0o600); err != nil {
		return err
	}
	d.loadedCaddyfile = cf
	d.Log.Info("caddy configuration applied", "tls", mode, "sites", len(cfg.Applications)+1)
	return nil
}

// updateFallbacks tracks ACME progress and switches a domain to the local
// CA once it has waited longer than tls.acme.fallback_after (only with
// tls.acme.allow_fallback).
func (d *Daemon) updateFallbacks(cfg *config.Config, mode config.TLSMode, st *state.State) {
	if mode != config.TLSACME {
		clear(st.ACMEPendingSince)
		clear(st.FallbackDomains)
		return
	}
	hosts := map[string]bool{}
	for _, h := range cfg.AllHostnames() {
		hosts[h] = true
		if caddy.HasACMECert(d.P.CaddyData(), h) {
			delete(st.ACMEPendingSince, h)
			if st.FallbackDomains[h] {
				d.Log.Info("ACME certificate obtained, leaving local CA fallback", "domain", h)
				delete(st.FallbackDomains, h)
			}
			continue
		}
		since, ok := st.ACMEPendingSince[h]
		if !ok {
			st.ACMEPendingSince[h] = time.Now()
			continue
		}
		if cfg.TLS.TLS.ACME.AllowFallback && !st.FallbackDomains[h] &&
			time.Since(since) > cfg.TLS.TLS.ACME.FallbackAfter.Duration {
			d.Log.Warn("no ACME certificate yet, switching to the local CA as allowed by tls.acme.allow_fallback", "domain", h)
			st.FallbackDomains[h] = true
		}
	}
	for h := range st.ACMEPendingSince {
		if !hosts[h] {
			delete(st.ACMEPendingSince, h)
		}
	}
	for h := range st.FallbackDomains {
		if !hosts[h] {
			delete(st.FallbackDomains, h)
		}
	}
}

func (d *Daemon) applyRauthy(ctx context.Context, cfg *config.Config, st *state.State) (ready bool, err error) {
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	probe := rauthy.NewClient(d.RauthyURL, "")
	if err := probe.Ping(pctx); err != nil {
		if d.isReady() {
			d.Log.Warn("rauthy is not reachable", "err", err)
		}
		return false, nil
	}
	// Rauthy migrates and bootstraps its database before it answers.
	st.RauthyInitialized = true

	apiKey, err := d.sec.Read(secrets.APIKey)
	if err != nil {
		return true, fmt.Errorf("no Rauthy API key in %s", filepath.Join(d.P.Secrets(), secrets.APIKey))
	}
	client := rauthy.NewClient(d.RauthyURL, apiKey)
	rec := &rauthy.Reconciler{API: client, Secrets: d.sec, Log: d.Log}
	rctx, cancel2 := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel2()
	res := rec.Reconcile(rctx, cfg, st)
	// Rauthy initialises its database before it starts answering, so
	// first-start leftovers can go even if one client failed to sync.
	d.afterRauthyReady(rctx, cfg, client)
	return true, res.Err()
}

// afterRauthyReady removes first-start and restore leftovers once Rauthy
// works with its data.
func (d *Daemon) afterRauthyReady(ctx context.Context, cfg *config.Config, client *rauthy.Client) {
	if _, err := os.Stat(d.P.BootstrapDir()); err == nil {
		if err := os.RemoveAll(d.P.BootstrapDir()); err == nil {
			d.Log.Info("first start finished, removed bootstrap files")
		}
	}
	if fileExists(d.P.RestorePending()) {
		os.Remove(d.P.RestorePending())
		os.RemoveAll(d.P.RestoreDir())
		d.Log.Info("database restore finished")
	}
	if fileExists(d.P.StartupEnv()) {
		os.Remove(d.P.StartupEnv())
	}
	if d.sec.Exists(secrets.BootstrapAdmin) {
		u, err := client.UserByEmail(ctx, cfg.Server.Admin.BootstrapEmail)
		if err == nil && u.LastLogin != nil {
			if err := d.sec.Remove(secrets.BootstrapAdmin); err == nil {
				d.Log.Info("the admin has logged in, removed the one-time password file")
			}
		}
	}
}

func (d *Daemon) setSyncErr(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil {
		d.syncErr = ""
		return
	}
	if d.syncErr != err.Error() {
		d.Log.Error("sync failed", "err", err)
	}
	d.syncErr = err.Error()
}

// SetCaddyAdmin replaces the Caddy admin client (tests).
func (d *Daemon) SetCaddyAdmin(a *caddy.Admin) { d.caddy = a }

func (d *Daemon) isReady() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rauthyReady
}

func (d *Daemon) fallbackActive() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg != nil && d.cfg.TLS.TLS.ACME.AllowFallback && d.cfg.ResolveTLSMode() == config.TLSACME
}

// fingerprints hashes the configuration files and, separately, custom
// certificate files.
func (d *Daemon) fingerprints() (cfgFP, certFP string) {
	h := sha256.New()
	filepath.WalkDir(d.P.ConfigDir, func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		hashFile(h, path)
		return nil
	})
	cfgFP = hex.EncodeToString(h.Sum(nil))

	d.mu.Lock()
	cfg := d.cfg
	d.mu.Unlock()
	if cfg == nil {
		return cfgFP, ""
	}
	h2 := sha256.New()
	hashFile(h2, cfg.TLS.TLS.Custom.Certificate)
	hashFile(h2, cfg.TLS.TLS.Custom.PrivateKey)
	return cfgFP, hex.EncodeToString(h2.Sum(nil))
}

func hashFile(h io.Writer, path string) {
	io.WriteString(h, path+"\x00")
	if f, err := os.Open(path); err == nil {
		io.Copy(h, f)
		f.Close()
	}
	io.WriteString(h, "\x00")
}

// collect builds the health report.
func (d *Daemon) collect(ctx context.Context) *health.Report {
	d.mu.Lock()
	cfg := d.cfg
	r := &health.Report{
		Version:     d.Version,
		Components:  map[string]health.Component{},
		ConfigError: d.configErr,
		SyncError:   d.syncErr,
		CheckedAt:   time.Now().UTC(),
	}
	if !d.lastSync.IsZero() {
		t := d.lastSync.UTC()
		r.LastSync = &t
	}
	d.mu.Unlock()

	if err := rauthy.NewClient(d.RauthyURL, "").Health(ctx); err != nil {
		r.Components["rauthy"] = health.Component{OK: false, Detail: err.Error()}
	} else {
		r.Components["rauthy"] = health.Component{OK: true}
	}
	if err := d.caddy.Ping(ctx); err != nil {
		r.Components["caddy"] = health.Component{OK: false, Detail: err.Error()}
	} else {
		r.Components["caddy"] = health.Component{OK: true}
	}
	if t, ok := newestFile(d.P.RauthyBackups()); ok {
		t = t.UTC()
		r.LastBackup = &t
	}
	if cfg == nil {
		return r
	}

	mode := cfg.ResolveTLSMode()
	r.TLSMode = string(mode)
	r.Certs = map[string]health.Cert{}
	for _, h := range cfg.AllHostnames() {
		var c *caddy.Cert
		if mode == config.TLSCustom {
			if na, err := caddy.CertNotAfter(cfg.TLS.TLS.Custom.Certificate); err == nil {
				c = &caddy.Cert{Issuer: "custom", NotAfter: na}
			}
		} else if found, err := caddy.FindCert(d.P.CaddyData(), h); err == nil {
			c = found
		}
		hc := health.Cert{}
		if c == nil {
			hc.Problem = "no certificate yet"
		} else {
			hc.Issuer, hc.NotAfter = c.Issuer, c.NotAfter.UTC()
			hc.DaysLeft = int(time.Until(c.NotAfter).Hours() / 24)
			switch {
			case hc.DaysLeft < 0:
				hc.Problem = "certificate expired"
			case hc.DaysLeft < 14:
				hc.Problem = fmt.Sprintf("certificate expires in %d days", hc.DaysLeft)
			case mode == config.TLSACME && c.Issuer == "local":
				hc.Problem = "using the local CA fallback, ACME has not succeeded"
			}
		}
		r.Certs[h] = hc
	}
	return r
}

func newestFile(dir string) (time.Time, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return time.Time{}, false
	}
	var newest time.Time
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest, !newest.IsZero()
}

// NewestFiles lists regular files in dir, newest first.
func NewestFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type f struct {
		name string
		t    time.Time
	}
	var fs []f
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			fs = append(fs, f{e.Name(), info.ModTime()})
		}
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].t.After(fs[j].t) })
	out := make([]string, len(fs))
	for i, x := range fs {
		out[i] = x.name
	}
	return out
}
