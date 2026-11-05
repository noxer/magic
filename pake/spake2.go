// Package pake implements the password-authenticated key exchange used by
// Magic pairing: SPAKE2 over NIST P-256 with the M and N constants of
// RFC 9382, with the transcript and key schedule defined by the Magic
// pairing specification (spec/05-authentication.md).
//
// The construction lets two parties that share a short, low-entropy pairing
// code agree on keys and confirm each other's knowledge of the code. A
// network attacker gets exactly one guess per protocol run and cannot test
// guesses offline.
package pake

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"

	"filippo.io/nistec"
)

// Suite is the name of the ciphersuite implemented by this package.
const Suite = "SPAKE2-P256-SHA256"

const (
	label        = "magic-pair-v1"
	pointLen     = 65 // uncompressed SEC 1 encoding
	scalarLen    = 32
	confirmLen   = sha256.Size
	confirmLabel = "ConfirmationKeys"
)

// RFC 9382 section 6, P256 ciphersuite.
var (
	mBytes, _ = hex.DecodeString("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
	nBytes, _ = hex.DecodeString("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
	order, _  = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
)

func pointM() *nistec.P256Point { p, _ := nistec.NewP256Point().SetBytes(mBytes); return p }
func pointN() *nistec.P256Point { p, _ := nistec.NewP256Point().SetBytes(nBytes); return p }

// Role identifies the side of the exchange.
type Role int

const (
	// Client is party A (the device that wants access).
	Client Role = iota
	// Provider is party B (the device that grants access).
	Provider
)

var (
	// ErrBadMessage is returned for malformed or invalid peer messages.
	ErrBadMessage = errors.New("pake: invalid peer message")
	// ErrConfirmation is returned when key confirmation fails: the peer used a
	// different code or saw a different provider key.
	ErrConfirmation = errors.New("pake: key confirmation failed")
)

// Params are the inputs both parties must agree on.
type Params struct {
	// PairingID is the identifier of the pairing session, chosen by the provider.
	PairingID string
	// Code is the pairing code as entered or displayed, digits only.
	Code string
	// Binding is the channel binding value: the SHA-256 fingerprint of the
	// provider's TLS public key, as seen by the client or as owned by the provider.
	Binding []byte
}

// PasswordScalar derives w from the session parameters:
// w = SHA-512(lp("magic-pair-v1 w") || lp(pairing_id) || lp(code)) mod n.
func PasswordScalar(pairingID, code string) []byte {
	h := sha512.New()
	writeLP(h, []byte(label+" w"))
	writeLP(h, []byte(pairingID))
	writeLP(h, []byte(code))
	w := new(big.Int).SetBytes(h.Sum(nil))
	w.Mod(w, order)
	return w.FillBytes(make([]byte, scalarLen))
}

// State is one party's state during an exchange.
type State struct {
	role   Role
	params Params
	w      []byte // 32-byte big-endian scalar
	x      []byte // ephemeral secret scalar
	msg    []byte // our public share
	kcA    []byte
	kcB    []byte
	tt     []byte
	done   bool
}

// Start begins an exchange and returns the state and the message to send to
// the peer (pA for the client, pB for the provider).
func Start(role Role, p Params) (*State, []byte, error) {
	return start(role, p, rand.Reader)
}

func start(role Role, p Params, rnd io.Reader) (*State, []byte, error) {
	if p.PairingID == "" || p.Code == "" || len(p.Binding) == 0 {
		return nil, nil, errors.New("pake: incomplete parameters")
	}
	x, err := randomScalar(rnd)
	if err != nil {
		return nil, nil, err
	}
	s := &State{role: role, params: p, w: PasswordScalar(p.PairingID, p.Code), x: x}
	X, err := nistec.NewP256Point().ScalarBaseMult(x)
	if err != nil {
		return nil, nil, err
	}
	blind := pointM()
	if role == Provider {
		blind = pointN()
	}
	wB, err := nistec.NewP256Point().ScalarMult(blind, s.w)
	if err != nil {
		return nil, nil, err
	}
	s.msg = nistec.NewP256Point().Add(X, wB).Bytes()
	return s, append([]byte(nil), s.msg...), nil
}

// Finish processes the peer's share and returns this party's confirmation
// MAC (cA for the client, cB for the provider).
func (s *State) Finish(peer []byte) ([]byte, error) {
	if s.tt != nil {
		return nil, errors.New("pake: Finish called twice")
	}
	if len(peer) != pointLen || peer[0] != 4 {
		return nil, ErrBadMessage
	}
	P, err := nistec.NewP256Point().SetBytes(peer)
	if err != nil {
		return nil, ErrBadMessage
	}
	// Remove the peer's blinding: P - w*(peer constant).
	blind := pointN()
	if s.role == Provider {
		blind = pointM()
	}
	negW := new(big.Int).Sub(order, new(big.Int).SetBytes(s.w))
	negW.Mod(negW, order)
	unblind, err := nistec.NewP256Point().ScalarMult(blind, negW.FillBytes(make([]byte, scalarLen)))
	if err != nil {
		return nil, err
	}
	Y := nistec.NewP256Point().Add(P, unblind)
	K, err := nistec.NewP256Point().ScalarMult(Y, s.x)
	if err != nil {
		return nil, err
	}
	kb := K.Bytes()
	if len(kb) == 1 { // point at infinity
		return nil, ErrBadMessage
	}

	pA, pB := s.msg, peer
	if s.role == Provider {
		pA, pB = peer, s.msg
	}
	var tt []byte
	tt = appendLP(tt, []byte(label))
	tt = appendLP(tt, []byte(s.params.PairingID))
	tt = appendLP(tt, s.params.Binding)
	tt = appendLP(tt, pA)
	tt = appendLP(tt, pB)
	tt = appendLP(tt, kb)
	tt = appendLP(tt, s.w)
	s.tt = tt

	sum := sha256.Sum256(tt)
	ka := sum[16:] // Ke = sum[:16] is reserved for future use
	keys, err := hkdf.Key(sha256.New, ka, nil, confirmLabel, 2*sha256.Size)
	if err != nil {
		return nil, err
	}
	s.kcA, s.kcB = keys[:sha256.Size], keys[sha256.Size:]
	if s.role == Client {
		return mac(s.kcA, tt), nil
	}
	return mac(s.kcB, tt), nil
}

// Verify checks the peer's confirmation MAC.
func (s *State) Verify(peerConfirm []byte) error {
	if s.tt == nil {
		return errors.New("pake: Verify called before Finish")
	}
	key := s.kcB
	if s.role == Provider {
		key = s.kcA
	}
	if len(peerConfirm) != confirmLen || !hmac.Equal(mac(key, s.tt), peerConfirm) {
		return ErrConfirmation
	}
	s.done = true
	return nil
}

func mac(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func randomScalar(rnd io.Reader) ([]byte, error) {
	for {
		b := make([]byte, scalarLen+8)
		if _, err := io.ReadFull(rnd, b); err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(b)
		k.Mod(k, order)
		if k.Sign() != 0 {
			return k.FillBytes(make([]byte, scalarLen)), nil
		}
	}
}

func appendLP(dst, b []byte) []byte {
	dst = binary.LittleEndian.AppendUint64(dst, uint64(len(b)))
	return append(dst, b...)
}

func writeLP(w io.Writer, b []byte) {
	var l [8]byte
	binary.LittleEndian.PutUint64(l[:], uint64(len(b)))
	w.Write(l[:])
	w.Write(b)
}
