package provider

import (
	"errors"
	"net/http"
	"time"

	"github.com/noxer/magic"
	"github.com/noxer/magic/pake"
)

const pakeSuite = pake.Suite

func (s *Server) handlePairingStart(w http.ResponseWriter, r *http.Request) {
	var req magic.PairingRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Suite != pakeSuite {
		writeError(w, http.StatusBadRequest, magic.ErrCodeBadRequest, "unsupported suite; supported: "+pakeSuite)
		return
	}
	if req.Client.Name == "" || len(req.Client.Name) > 100 || len(req.Client.Software) > 100 || len(req.Client.Device) > 100 {
		writeError(w, http.StatusBadRequest, magic.ErrCodeBadRequest, "client.name is required (at most 100 bytes)")
		return
	}
	scopes, err := s.validScopes(r.Context(), req.Scopes)
	if err != nil {
		writeError(w, http.StatusBadRequest, magic.ErrCodeBadRequest, err.Error())
		return
	}
	p, err := s.pairings.start(req.Client, scopes, req.Ticket)
	switch {
	case errors.Is(err, errRateLimited):
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, magic.ErrCodeRateLimited, err.Error())
		return
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, magic.ErrCodeNotFound, "unknown or expired ticket")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, magic.ErrCodeInternal, err.Error())
		return
	}
	s.log.Info("pairing requested", "pairing", p.ID, "client", p.Client.Name, "device", p.Client.Device, "scopes", p.Scopes, "ticket", p.Ticket != "")
	if p.Ticket == "" && s.cfg.OnPairing != nil {
		s.cfg.OnPairing(*p)
	}
	writeJSON(w, http.StatusCreated, magic.PairingStarted{
		PairingID:  p.ID,
		ExpiresAt:  p.ExpiresAt.UTC().Format(time.RFC3339),
		CodeDigits: CodeDigits,
		Suite:      pakeSuite,
	})
}

func (s *Server) handlePairingExchange(w http.ResponseWriter, r *http.Request) {
	var req magic.PairingExchange
	if !readJSON(w, r, &req) {
		return
	}
	pA, err := unb64(req.PA)
	if err != nil {
		writeError(w, http.StatusBadRequest, magic.ErrCodeBadRequest, "pA is not base64url")
		return
	}
	fp := s.cfg.Identity.Fingerprint
	pB, confirm, err := s.pairings.exchange(r.PathValue("id"), fp[:], pA)
	if !s.pairingError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, magic.PairingExchanged{PB: b64(pB), Confirm: b64(confirm)})
}

func (s *Server) handlePairingConfirm(w http.ResponseWriter, r *http.Request) {
	var req magic.PairingConfirm
	if !readJSON(w, r, &req) {
		return
	}
	mac, err := unb64(req.Confirm)
	if err != nil {
		writeError(w, http.StatusBadRequest, magic.ErrCodeBadRequest, "confirm is not base64url")
		return
	}
	p, err := s.pairings.confirm(r.PathValue("id"), mac)
	if !s.pairingError(w, err) {
		s.log.Warn("pairing failed", "pairing", r.PathValue("id"), "err", err)
		return
	}
	c, tok, err := s.store.Issue(KindPaired, p.Client, p.Scopes, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, magic.ErrCodeInternal, err.Error())
		return
	}
	s.log.Info("client paired", "client", c.ID, "name", c.Info.Name, "scopes", c.Scopes)
	if s.cfg.OnPaired != nil {
		s.cfg.OnPaired(*c)
	}
	writeJSON(w, http.StatusOK, magic.Grant{Token: tok, TokenType: "Bearer", ClientID: c.ID, Scopes: c.Scopes, Provider: s.providerInfo()})
}

func (s *Server) handlePairingCancel(w http.ResponseWriter, r *http.Request) {
	s.pairings.cancel(r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// pairingError writes the response for err and reports whether err was nil.
func (s *Server) pairingError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, magic.ErrCodeNotFound, "unknown or expired pairing session")
	case errors.Is(err, errWrongStage):
		writeError(w, http.StatusConflict, magic.ErrCodeBadRequest, err.Error())
	case errors.Is(err, errPairingFailed), errors.Is(err, pake.ErrBadMessage):
		writeError(w, http.StatusForbidden, magic.ErrCodePairingFailed, errPairingFailed.Error())
	default:
		writeError(w, http.StatusInternalServerError, magic.ErrCodeInternal, err.Error())
	}
	return false
}
