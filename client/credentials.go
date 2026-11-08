package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/noxer/magic"
	"github.com/noxer/magic/identity"
)

// Credential is what a client remembers about a paired provider.
type Credential struct {
	ProviderID  string               `json:"provider_id"`
	Name        string               `json:"name"`
	Fingerprint identity.Fingerprint `json:"fingerprint"`
	Token       string               `json:"token"`
	ClientID    string               `json:"client_id,omitempty"`
	Scopes      []magic.Capability   `json:"scopes,omitempty"`
	URLs        []string             `json:"urls,omitempty"`
	PairedAt    time.Time            `json:"paired_at"`
}

// Pin returns the TLS pin for the provider.
func (c *Credential) Pin() identity.Pin {
	return identity.Pin{Fingerprint: c.Fingerprint, ID: c.ProviderID}
}

// Credentials is a file-backed set of credentials, keyed by provider ID.
type Credentials struct {
	mu   sync.Mutex
	path string
	m    map[string]*Credential
}

// DefaultCredentialsPath is $XDG_CONFIG_HOME/magic/credentials.json or the
// platform equivalent (os.UserConfigDir).
func DefaultCredentialsPath() (string, error) {
	if p := os.Getenv("MAGIC_CREDENTIALS"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "magic", "credentials.json"), nil
}

// OpenCredentials loads the credential file at path (which may not exist yet).
func OpenCredentials(path string) (*Credentials, error) {
	c := &Credentials{path: path, m: map[string]*Credential{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	} else if err != nil {
		return nil, err
	}
	var list []*Credential
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	for _, cr := range list {
		c.m[cr.ProviderID] = cr
	}
	return c, nil
}

// Get returns the credential for a provider ID.
func (c *Credentials) Get(id string) *Credential {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[id]
}

// List returns all credentials sorted by name.
func (c *Credentials) List() []*Credential {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*Credential, 0, len(c.m))
	for _, cr := range c.m {
		out = append(out, cr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Put stores (or replaces) a credential and saves the file.
func (c *Credentials) Put(cr *Credential) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[cr.ProviderID] = cr
	return c.saveLocked()
}

// Delete removes a credential and saves the file.
func (c *Credentials) Delete(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, id)
	return c.saveLocked()
}

func (c *Credentials) saveLocked() error {
	list := make([]*Credential, 0, len(c.m))
	for _, cr := range c.m {
		list = append(list, cr)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ProviderID < list[j].ProviderID })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
