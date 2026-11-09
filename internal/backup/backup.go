// Package backup creates and restores Guard archives.
//
// An archive contains the newest consistent database backup written by
// Rauthy (Hiqlite), the secrets, Caddy's certificates and CA, guard-sync's
// state and a copy of the YAML configuration. It never copies the live
// database file.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Layout of the archive.
const (
	dirDB       = "rauthy-db"
	dirSecrets  = "secrets"
	dirCaddy    = "caddy"
	dirConfig   = "config"
	fileState   = "guard/state.json"
	manifestRel = "MANIFEST.json"
)

// Sources are the directories an archive is made from.
type Sources struct {
	RauthyBackups string // Hiqlite backup dir
	Secrets       string
	CaddyData     string
	StateFile     string
	ConfigDir     string
}

// Targets are where Restore puts things.
type Targets struct {
	RauthyData     string // must be empty unless force
	Secrets        string
	CaddyData      string
	StateFile      string
	RestoreDir     string // receives the database file
	RestorePending string // file whose content becomes HQL_BACKUP_RESTORE
	ConfigOut      string // the archived YAML is extracted here for reference
}

type Manifest struct {
	CreatedAt    time.Time `json:"created_at"`
	GuardVersion string    `json:"guard_version"`
	Database     string    `json:"database"`
	DatabaseTime time.Time `json:"database_time"`
}

// Create writes a gzip'ed tar archive to out (mode 0600: it holds secrets).
func Create(src Sources, out, version string) (*Manifest, error) {
	db, dbTime, err := newestRegular(src.RauthyBackups)
	if err != nil {
		return nil, fmt.Errorf("no database backup found in %s yet: Rauthy writes one on the backup.cron schedule (%w)", src.RauthyBackups, err)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return nil, err
	}
	tmp := out + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	m := &Manifest{CreatedAt: time.Now().UTC(), GuardVersion: version, Database: filepath.Base(db), DatabaseTime: dbTime.UTC()}

	steps := []func() error{
		func() error { return addFile(tw, db, dirDB+"/"+filepath.Base(db)) },
		func() error { return addTree(tw, src.Secrets, dirSecrets, nil) },
		func() error {
			// Lock files and the OCSP cache are not needed.
			skip := func(rel string) bool {
				return strings.HasPrefix(rel, "locks") || strings.HasPrefix(rel, "ocsp")
			}
			return addTree(tw, src.CaddyData, dirCaddy, skip)
		},
		func() error {
			if _, err := os.Stat(src.StateFile); errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return addFile(tw, src.StateFile, fileState)
		},
		func() error { return addTree(tw, src.ConfigDir, dirConfig, nil) },
		func() error {
			b, _ := json.MarshalIndent(m, "", "  ")
			return addBytes(tw, manifestRel, b, 0o600)
		},
	}
	for _, s := range steps {
		if err := s(); err != nil {
			f.Close()
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return m, os.Rename(tmp, out)
}

// Prune keeps the newest keep archives matching guard-*.tar.gz in dir.
func Prune(dir string, keep int) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "guard-*.tar.gz"))
	if err != nil {
		return nil, err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(matches))) // names carry a UTC timestamp
	var removed []string
	for i, m := range matches {
		if i < keep {
			continue
		}
		if err := os.Remove(m); err != nil {
			return removed, err
		}
		removed = append(removed, m)
	}
	return removed, nil
}

// ArchiveName returns a timestamped file name.
func ArchiveName(t time.Time) string {
	return "guard-" + t.UTC().Format("20060102-150405") + ".tar.gz"
}

// Restore unpacks an archive into an empty data volume. Rauthy restores
// the database on its next start (HQL_BACKUP_RESTORE).
func Restore(archive string, dst Targets, force bool) (*Manifest, error) {
	if entries, err := os.ReadDir(dst.RauthyData); err == nil && len(entries) > 0 && !force {
		return nil, fmt.Errorf("%s is not empty: restore into a fresh volume, or pass --force to replace the current database", dst.RauthyData)
	}
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("not a guard archive: %w", err)
	}
	tr := tar.NewReader(gz)

	var m *Manifest
	var dbFile string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		name := filepath.ToSlash(filepath.Clean(h.Name))
		if strings.HasPrefix(name, "../") || filepath.IsAbs(name) {
			return nil, fmt.Errorf("unsafe path in archive: %s", h.Name)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		var target string
		switch {
		case name == manifestRel:
			m = &Manifest{}
			if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(m); err != nil {
				return nil, fmt.Errorf("manifest: %w", err)
			}
			continue
		case strings.HasPrefix(name, dirDB+"/"):
			target = filepath.Join(dst.RestoreDir, strings.TrimPrefix(name, dirDB+"/"))
			dbFile = target
		case strings.HasPrefix(name, dirSecrets+"/"):
			target = filepath.Join(dst.Secrets, strings.TrimPrefix(name, dirSecrets+"/"))
		case strings.HasPrefix(name, dirCaddy+"/"):
			target = filepath.Join(dst.CaddyData, strings.TrimPrefix(name, dirCaddy+"/"))
		case name == fileState:
			target = dst.StateFile
		case strings.HasPrefix(name, dirConfig+"/"):
			target = filepath.Join(dst.ConfigOut, strings.TrimPrefix(name, dirConfig+"/"))
		default:
			continue
		}
		if err := extract(tr, target, fs.FileMode(h.Mode)&0o700); err != nil {
			return nil, err
		}
	}
	if m == nil || dbFile == "" {
		return nil, errors.New("archive has no manifest or no database: not a complete guard backup")
	}
	if force {
		if err := os.RemoveAll(dst.RauthyData); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dst.RauthyData, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(dst.RestorePending, []byte("file:"+dbFile+"\n"), 0o600); err != nil {
		return nil, err
	}
	return m, nil
}

func extract(r io.Reader, target string, mode fs.FileMode) error {
	if mode == 0 {
		mode = 0o600
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func addTree(tw *tar.Writer, root, prefix string, skip func(rel string) bool) error {
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if skip != nil && skip(rel) {
			if e.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !e.Type().IsRegular() {
			return nil
		}
		return addFile(tw, path, prefix+"/"+rel)
	})
}

func addFile(tw *tar.Writer, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	h := &tar.Header{Name: name, Mode: int64(st.Mode().Perm()), Size: st.Size(), ModTime: st.ModTime(), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	_, err = io.CopyN(tw, f, st.Size())
	return err
}

func addBytes(tw *tar.Writer, name string, b []byte, mode int64) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(b)), ModTime: time.Now(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func newestRegular(dir string) (string, time.Time, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", time.Time{}, err
	}
	var best string
	var bt time.Time
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if info.ModTime().After(bt) {
			best, bt = filepath.Join(dir, e.Name()), info.ModTime()
		}
	}
	if best == "" {
		return "", time.Time{}, os.ErrNotExist
	}
	return best, bt, nil
}
