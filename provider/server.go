// Package provider implements the provider side of the Magic protocol: the
// descriptor, pairing, token authentication, the control API and a gateway
// that exposes an OpenAI-compatible backend with capability-scoped access.
package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/noxer/magic"
	"github.com/noxer/magic/identity"
)

// ModelSource lists the models a provider currently offers.
type ModelSource func(ctx context.Context) ([]magic.Model, error)

// Config configures a Server.
type Config struct {
	Identity *identity.Identity
	Name     string
	Software *magic.SoftwareInfo
	Locality magic.Locality
	// Store holds authorized clients. Defaults to an in-memory store.
	Store *Store
	// Models lists the offered models; results are cached for ModelCacheTTL.
	Models        ModelSource
	ModelCacheTTL time.Duration
	// Backend serves the OpenAI-compatible API. It receives requests with the
	// API base stripped (e.g. "/chat/completions") and without the client's
	// Authorization header.
	Backend http.Handler
	// PublicModels includes model details in unauthenticated descriptors.
	PublicModels bool
	// OnPairing is called when a client requests pairing without a ticket.
	// The provider must show p.Code to its operator (and only to them).
	OnPairing func(p Pending)
	// OnPaired is called after a client completed pairing.
	OnPaired func(c Client)
	Logger   *slog.Logger
}

// Server is a Magic provider.
type Server struct {
	cfg      Config
	store    *Store
	pairings *pairings
	log      *slog.Logger

	mu       sync.Mutex
	models   []magic.Model
	modelsAt time.Time
}

// New creates a provider server.
func New(cfg Config) (*Server, error) {
	if cfg.Identity == nil {
		return nil, errors.New("provider: Identity is required")
	}
	if cfg.Name == "" {
		cfg.Name = "Magic provider"
	}
	if cfg.ModelCacheTTL == 0 {
		cfg.ModelCacheTTL = 30 * time.Second
	}
	if cfg.Locality == "" {
		cfg.Locality = magic.LocalityDevice
	}
	s := &Server{cfg: cfg, store: cfg.Store, pairings: newPairings(), log: cfg.Logger}
	if s.store == nil {
		s.store, _ = OpenStore("")
	}
	if s.log == nil {
		s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return s, nil
}

// Store returns the server's client store.
func (s *Server) Store() *Store { return s.store }

// ID returns the provider ID.
func (s *Server) ID() string { return s.cfg.Identity.ID() }

// Models returns the (cached) model list.
func (s *Server) Models(ctx context.Context) []magic.Model {
	if s.cfg.Models == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.models != nil && time.Since(s.modelsAt) < s.cfg.ModelCacheTTL {
		return s.models
	}
	m, err := s.cfg.Models(ctx)
	if err != nil {
		s.log.Warn("listing models failed", "err", err)
		if s.models != nil {
			return s.models
		}
		return []magic.Model{}
	}
	s.models, s.modelsAt = m, time.Now()
	return m
}

// Capabilities returns the capabilities currently offered.
func (s *Server) Capabilities(ctx context.Context) []magic.Capability {
	seen := map[magic.Capability]bool{}
	var out []magic.Capability
	for _, c := range magic.Registered {
		for _, m := range s.Models(ctx) {
			if m.Has(c) && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

func (s *Server) providerInfo() magic.ProviderInfo {
	return magic.ProviderInfo{
		ID:          s.cfg.Identity.ID(),
		Name:        s.cfg.Name,
		Fingerprint: s.cfg.Identity.Fingerprint.String(),
		Software:    s.cfg.Software,
		Locality:    s.cfg.Locality,
	}
}

// Descriptor builds the descriptor; details are included for authenticated
// clients or when PublicModels is set.
func (s *Server) Descriptor(ctx context.Context, detailed bool) magic.Descriptor {
	d := magic.Descriptor{
		Magic:    magic.Version,
		Provider: s.providerInfo(),
		Auth: magic.AuthInfo{
			Methods: []string{magic.AuthPairing, magic.AuthToken},
			Pairing: &magic.PairingInfo{Endpoint: magic.APIPrefix + "/pairings", Suites: []string{pakeSuite}, CodeDigits: CodeDigits},
		},
		API:          magic.APIInfo{OpenAI: "/v1"},
		Capabilities: map[magic.Capability]magic.CapabilityInfo{},
	}
	models := s.Models(ctx)
	for _, c := range s.Capabilities(ctx) {
		info := magic.CapabilityInfo{}
		if detailed {
			for _, m := range models {
				if m.Has(c) {
					info.Models = append(info.Models, m.ID)
				}
			}
		}
		d.Capabilities[c] = info
	}
	if detailed {
		d.Models = models
	}
	return d
}

// Options control one listener's handler.
type Options struct {
	// Loopback marks a plain-HTTP listener bound to a loopback address: the
	// Host header is checked to defeat DNS rebinding.
	Loopback bool
}

// Handler returns the HTTP handler for one listener.
func (s *Server) Handler(opts Options) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+magic.WellKnownPath, s.handleDescriptor)
	p := magic.APIPrefix
	mux.HandleFunc("POST "+p+"/pairings", s.handlePairingStart)
	mux.HandleFunc("POST "+p+"/pairings/{id}/exchange", s.handlePairingExchange)
	mux.HandleFunc("POST "+p+"/pairings/{id}/confirm", s.handlePairingConfirm)
	mux.HandleFunc("DELETE "+p+"/pairings/{id}", s.handlePairingCancel)
	mux.Handle("GET "+p+"/session", s.authed(s.handleSession))
	mux.Handle("DELETE "+p+"/session", s.authed(s.handleUnpair))
	mux.Handle("GET "+p+"/admin/pairings", s.admin(s.handleAdminPairings))
	mux.Handle("DELETE "+p+"/admin/pairings/{id}", s.admin(s.handleAdminPairingDeny))
	mux.Handle("POST "+p+"/admin/tickets", s.admin(s.handleAdminTicket))
	mux.Handle("GET "+p+"/admin/clients", s.admin(s.handleAdminClients))
	mux.Handle("DELETE "+p+"/admin/clients/{id}", s.admin(s.handleAdminRevoke))
	mux.Handle("POST "+p+"/admin/tokens", s.admin(s.handleAdminToken))
	mux.Handle("/v1/", s.authed(s.handleAPI))

	var h http.Handler = mux
	h = securityHeaders(h)
	if opts.Loopback {
		h = loopbackHost(h)
	}
	return h
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// loopbackHost rejects requests whose Host is not a loopback name, so that a
// web page cannot reach the provider through DNS rebinding.
func loopbackHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if !(strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()) {
			writeError(w, http.StatusMisdirectedRequest, magic.ErrCodeForbidden, "invalid Host for a loopback listener")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

// ClientFrom returns the authenticated client of a request.
func ClientFrom(ctx context.Context) *Client {
	c, _ := ctx.Value(ctxKey{}).(*Client)
	return c
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Server) authenticate(r *http.Request) *Client {
	tok := bearer(r)
	if tok == "" {
		return nil
	}
	return s.store.Lookup(tok)
}

func (s *Server) authed(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := s.authenticate(r)
		if c == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="magic"`)
			writeError(w, http.StatusUnauthorized, magic.ErrCodeUnauthorized, "missing or invalid access token")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
	})
}

func (s *Server) admin(h http.HandlerFunc) http.Handler {
	return s.authed(func(w http.ResponseWriter, r *http.Request) {
		if !ClientFrom(r.Context()).Admin {
			writeError(w, http.StatusForbidden, magic.ErrCodeForbidden, "admin access required")
			return
		}
		h(w, r)
	})
}

func (s *Server) handleDescriptor(w http.ResponseWriter, r *http.Request) {
	detailed := s.cfg.PublicModels || s.authenticate(r) != nil
	writeJSON(w, http.StatusOK, s.Descriptor(r.Context(), detailed))
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	c := ClientFrom(r.Context())
	writeJSON(w, http.StatusOK, magic.Session{ClientID: c.ID, Name: c.Info.Name, Scopes: c.Scopes, Admin: c.Admin, Provider: s.providerInfo()})
}

func (s *Server) handleUnpair(w http.ResponseWriter, r *http.Request) {
	c := ClientFrom(r.Context())
	if c.Kind == KindLocal {
		writeError(w, http.StatusBadRequest, magic.ErrCodeBadRequest, "local tokens cannot be revoked by clients")
		return
	}
	if _, err := s.store.Revoke(c.ID); err != nil {
		writeError(w, http.StatusInternalServerError, magic.ErrCodeInternal, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAPI enforces capability scopes and forwards to the backend.
func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Backend == nil {
		writeError(w, http.StatusNotFound, magic.ErrCodeNotFound, "no API backend configured")
		return
	}
	c := ClientFrom(r.Context())
	path := strings.TrimPrefix(r.URL.Path, "/v1")
	switch cap, ok := magic.CapabilityForPath(path); {
	case ok:
		if !c.Allows(cap) {
			writeError(w, http.StatusForbidden, magic.ErrCodeForbidden, "token lacks the "+string(cap)+" scope")
			return
		}
	case path == "/models" || strings.HasPrefix(path, "/models/"):
		// Model listing is available to every authorized client.
	case !c.Admin:
		writeError(w, http.StatusForbidden, magic.ErrCodeForbidden, "endpoint is not part of a capability")
		return
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = path
	r2.URL.RawPath = ""
	r2.Header.Del("Authorization")
	s.cfg.Backend.ServeHTTP(w, r2)
}

// Admin handlers.

func (s *Server) handleAdminPairings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"pairings": s.pairings.list()})
}

func (s *Server) handleAdminPairingDeny(w http.ResponseWriter, r *http.Request) {
	if !s.pairings.cancel(r.PathValue("id")) {
		writeError(w, http.StatusNotFound, magic.ErrCodeNotFound, "no such pairing session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type ticketRequest struct {
	Scopes     []magic.Capability `json:"scopes"`
	TTLSeconds int                `json:"ttl_seconds"`
}

func (s *Server) handleAdminTicket(w http.ResponseWriter, r *http.Request) {
	var req ticketRequest
	if !readJSON(w, r, &req) {
		return
	}
	scopes, err := s.validScopes(r.Context(), req.Scopes)
	if err != nil {
		writeError(w, http.StatusBadRequest, magic.ErrCodeBadRequest, err.Error())
		return
	}
	t := s.pairings.newTicket(scopes, time.Duration(req.TTLSeconds)*time.Second)
	writeJSON(w, http.StatusCreated, t)
}

// NewTicket creates a pairing ticket directly (for in-process operator UIs).
func (s *Server) NewTicket(scopes []magic.Capability, ttl time.Duration) Ticket {
	return *s.pairings.newTicket(scopes, ttl)
}

// PendingPairings lists pending pairing sessions with their codes.
func (s *Server) PendingPairings() []Pending { return s.pairings.list() }

func (s *Server) handleAdminClients(w http.ResponseWriter, r *http.Request) {
	clients := s.store.List()
	for i := range clients {
		clients[i].TokenHash = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

func (s *Server) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	ok, err := s.store.Revoke(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, magic.ErrCodeInternal, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, magic.ErrCodeNotFound, "no such client")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type tokenRequest struct {
	Name   string             `json:"name"`
	Scopes []magic.Capability `json:"scopes"`
}

func (s *Server) handleAdminToken(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if !readJSON(w, r, &req) {
		return
	}
	scopes, err := s.validScopes(r.Context(), req.Scopes)
	if err != nil || req.Name == "" {
		if err == nil {
			err = errors.New("name is required")
		}
		writeError(w, http.StatusBadRequest, magic.ErrCodeBadRequest, err.Error())
		return
	}
	c, tok, err := s.store.Issue(KindIssued, magic.ClientInfo{Name: req.Name}, scopes, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, magic.ErrCodeInternal, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, magic.Grant{Token: tok, TokenType: "Bearer", ClientID: c.ID, Scopes: c.Scopes, Provider: s.providerInfo()})
}

// validScopes checks requested scopes. An empty request means "everything
// currently offered".
func (s *Server) validScopes(ctx context.Context, req []magic.Capability) ([]magic.Capability, error) {
	if len(req) == 0 {
		return s.Capabilities(ctx), nil
	}
	seen := map[magic.Capability]bool{}
	var out []magic.Capability
	for _, c := range req {
		if !c.Valid() {
			return nil, errors.New("invalid scope " + string(c))
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// JSON helpers.

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	var e magic.Error
	e.Err.Code, e.Err.Message = code, msg
	writeJSON(w, status, e)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, magic.ErrCodeBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
