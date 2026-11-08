package provider

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/noxer/magic"
)

// Client kinds.
const (
	KindPaired = "paired" // obtained a token through pairing
	KindIssued = "issued" // token issued by the operator
	KindLocal  = "local"  // token file for local users
)

// Client is a client authorized to use the provider.
type Client struct {
	ID        string             `json:"id"`
	Kind      string             `json:"kind"`
	Info      magic.ClientInfo   `json:"info"`
	Scopes    []magic.Capability `json:"scopes"`
	Admin     bool               `json:"admin,omitempty"`
	TokenHash string             `json:"token_hash"`
	CreatedAt time.Time          `json:"created_at"`
}

// Allows reports whether the client may use capability c.
func (c *Client) Allows(cap magic.Capability) bool {
	if c.Admin {
		return true
	}
	for _, s := range c.Scopes {
		if s == cap {
			return true
		}
	}
	return false
}

// Store keeps authorized clients. Only hashes of tokens are stored.
type Store struct {
	mu      sync.RWMutex
	path    string
	clients map[string]*Client // by ID
	byHash  map[string]*Client
}

// OpenStore loads (or creates) the client store at path. An empty path gives
// an in-memory store.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, clients: map[string]*Client{}, byHash: map[string]*Client{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	} else if err != nil {
		return nil, err
	}
	var list []*Client
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	for _, c := range list {
		s.clients[c.ID] = c
		s.byHash[c.TokenHash] = c
	}
	return s, nil
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// NewToken returns a fresh random access token.
func NewToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return magic.TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func newID(prefix string) string {
	b := make([]byte, 9)
	rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// Issue creates a client with a new token and returns both.
func (s *Store) Issue(kind string, info magic.ClientInfo, scopes []magic.Capability, admin bool) (*Client, string, error) {
	tok := NewToken()
	c := &Client{
		ID:        newID("cl_"),
		Kind:      kind,
		Info:      info,
		Scopes:    scopes,
		Admin:     admin,
		TokenHash: hashToken(tok),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
	s.byHash[c.TokenHash] = c
	if err := s.saveLocked(); err != nil {
		delete(s.clients, c.ID)
		delete(s.byHash, c.TokenHash)
		return nil, "", err
	}
	return c, tok, nil
}

// Lookup returns the client owning tok, or nil.
func (s *Store) Lookup(tok string) *Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byHash[hashToken(tok)]
}

// Revoke deletes a client and invalidates its token.
func (s *Store) Revoke(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return false, nil
	}
	delete(s.clients, id)
	delete(s.byHash, c.TokenHash)
	return true, s.saveLocked()
}

// RevokeKind deletes all clients of a kind (e.g. stale local tokens).
func (s *Store) RevokeKind(kind string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.clients {
		if c.Kind == kind {
			delete(s.clients, id)
			delete(s.byHash, c.TokenHash)
		}
	}
	return s.saveLocked()
}

// List returns all clients sorted by creation time.
func (s *Store) List() []Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Client, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	list := make([]*Client, 0, len(s.clients))
	for _, c := range s.clients {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.path, b, 0o600)
}

// WriteFileAtomic writes data to path via a temporary file and rename.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
