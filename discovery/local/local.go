// Package local implements discovery of providers on the same computer
// through beacon files in well-known directories.
//
// A provider writes one JSON file named "<provider-id>.json" into a beacon
// directory while it is running and removes it on exit. The per-user
// directory is private to the user; the system directory is readable by all
// local users.
package local

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/noxer/magic"
	"github.com/noxer/magic/identity"
)

// UserDir returns the per-user beacon directory.
func UserDir() string {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "magic", "providers")
		}
	case "darwin":
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, "Library", "Application Support", "magic", "providers")
		}
	default:
		if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
			return filepath.Join(d, "magic", "providers")
		}
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "magic", "providers")
	}
	return filepath.Join(os.TempDir(), "magic-"+strings.ReplaceAll(os.Getenv("USER"), string(filepath.Separator), "_"), "providers")
}

// SystemDir returns the system-wide beacon directory.
func SystemDir() string {
	switch runtime.GOOS {
	case "windows":
		d := os.Getenv("ProgramData")
		if d == "" {
			d = `C:\ProgramData`
		}
		return filepath.Join(d, "magic", "providers")
	case "darwin":
		return "/Library/Application Support/magic/providers"
	default:
		return "/run/magic/providers"
	}
}

// Dirs returns the directories searched for beacons: MAGIC_BEACON_DIRS (a
// list separated by os.PathListSeparator) if set, else the user and system dirs.
func Dirs() []string {
	if v := os.Getenv("MAGIC_BEACON_DIRS"); v != "" {
		return filepath.SplitList(v)
	}
	return []string{UserDir(), SystemDir()}
}

// Publish writes a beacon into dir and returns a function removing it.
func Publish(dir string, b magic.Beacon) (remove func() error, err error) {
	if !identity.ValidID(b.ID) {
		return nil, errors.New("local: invalid provider id")
	}
	if b.Magic == "" {
		b.Magic = magic.Version
	}
	if b.PID == 0 {
		b.PID = os.Getpid()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, b.ID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return func() error { return os.Remove(path) }, nil
}

// Scan reads all live beacons from the given directories (Dirs() if none).
// Beacons whose process is gone are skipped.
func Scan(dirs ...string) []magic.Beacon {
	if len(dirs) == 0 {
		dirs = Dirs()
	}
	seen := map[string]bool{}
	var out []magic.Beacon
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			var b magic.Beacon
			if json.Unmarshal(data, &b) != nil || !identity.ValidID(b.ID) || b.URL == "" || seen[b.ID] {
				continue
			}
			if strings.TrimSuffix(filepath.Base(f), ".json") != b.ID {
				continue
			}
			if b.PID > 0 && !alive(b.PID) {
				continue
			}
			seen[b.ID] = true
			out = append(out, b)
		}
	}
	return out
}

// ReadToken reads a beacon's token file, if the caller is allowed to.
func ReadToken(b magic.Beacon) (string, error) {
	if b.TokenFile == "" {
		return "", os.ErrNotExist
	}
	data, err := os.ReadFile(b.TokenFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
