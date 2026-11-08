// Package identity implements Magic provider identities: the long-lived TLS
// key pair of a provider, the self-signed certificate wrapped around it, the
// provider ID derived from the public key, and certificate pinning for clients.
//
// A provider ID is self-certifying: it is the first 16 bytes of the SHA-256
// hash of the provider's SubjectPublicKeyInfo, encoded in lowercase base32
// without padding (26 characters). A client that knows a provider ID can
// verify any TLS connection against it without further configuration.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// IDLength is the length in characters of an encoded provider ID.
const IDLength = 26

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Fingerprint is the SHA-256 hash of a DER-encoded SubjectPublicKeyInfo.
type Fingerprint [sha256.Size]byte

// String returns the canonical text form "sha256:<base64url>".
func (f Fingerprint) String() string {
	return "sha256:" + base64.RawURLEncoding.EncodeToString(f[:])
}

// ID returns the provider ID derived from the fingerprint.
func (f Fingerprint) ID() string {
	return strings.ToLower(b32.EncodeToString(f[:16]))
}

// MatchesID reports whether the fingerprint belongs to the given provider ID.
func (f Fingerprint) MatchesID(id string) bool {
	return subtle.ConstantTimeCompare([]byte(f.ID()), []byte(strings.ToLower(id))) == 1
}

// IsZero reports whether f is the zero value.
func (f Fingerprint) IsZero() bool { return f == Fingerprint{} }

// MarshalText implements encoding.TextMarshaler.
func (f Fingerprint) MarshalText() ([]byte, error) { return []byte(f.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (f *Fingerprint) UnmarshalText(b []byte) error {
	p, err := ParseFingerprint(string(b))
	if err != nil {
		return err
	}
	*f = p
	return nil
}

// ParseFingerprint parses the "sha256:<base64url>" form.
func ParseFingerprint(s string) (Fingerprint, error) {
	var f Fingerprint
	rest, ok := strings.CutPrefix(s, "sha256:")
	if !ok {
		return f, errors.New("identity: fingerprint must start with \"sha256:\"")
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(b) != len(f) {
		return f, errors.New("identity: malformed fingerprint")
	}
	copy(f[:], b)
	return f, nil
}

// ValidID reports whether s is syntactically a provider ID.
func ValidID(s string) bool {
	if len(s) != IDLength {
		return false
	}
	_, err := b32.DecodeString(strings.ToUpper(s))
	return err == nil
}

// FingerprintOf computes the fingerprint of a certificate's public key.
func FingerprintOf(cert *x509.Certificate) Fingerprint {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

// FingerprintOfKey computes the fingerprint of a public key.
func FingerprintOfKey(pub crypto.PublicKey) (Fingerprint, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Fingerprint{}, err
	}
	return sha256.Sum256(der), nil
}

// Identity is a provider's key pair and certificate.
type Identity struct {
	Key         crypto.Signer
	Certificate tls.Certificate
	Fingerprint Fingerprint
}

// ID returns the provider ID.
func (id *Identity) ID() string { return id.Fingerprint.ID() }

// TLSConfig returns a server TLS configuration presenting the identity.
func (id *Identity) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id.Certificate},
	}
}

// LoadOrCreate loads the identity stored in dir (key.pem, cert.pem), creating
// a new one if none exists. The certificate is renewed (with the same key, and
// therefore the same provider ID) when it is about to expire.
func LoadOrCreate(dir string, hostnames []string) (*Identity, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")

	var key *ecdsa.PrivateKey
	if b, err := os.ReadFile(keyPath); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("identity: %s: no PEM data", keyPath)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("identity: %s: %w", keyPath, err)
		}
		var ok bool
		if key, ok = k.(*ecdsa.PrivateKey); !ok {
			return nil, fmt.Errorf("identity: %s: unsupported key type %T", keyPath, k)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
		_ = os.Remove(certPath) // a certificate for another key is useless
	} else {
		return nil, err
	}

	var certDER []byte
	if b, err := os.ReadFile(certPath); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil &&
				time.Until(c.NotAfter) > 30*24*time.Hour &&
				c.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
				certDER = blk.Bytes
			}
		}
	}
	if certDER == nil {
		var err error
		if certDER, err = SelfSign(key, hostnames, 2*365*24*time.Hour); err != nil {
			return nil, err
		}
		if err := writeFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
			return nil, err
		}
	}
	return New(key, certDER)
}

// New assembles an Identity from a key and a DER certificate.
func New(key crypto.Signer, certDER []byte) (*Identity, error) {
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Key:         key,
		Certificate: tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key, Leaf: leaf},
		Fingerprint: FingerprintOf(leaf),
	}, nil
}

// Generate creates an ephemeral in-memory identity (useful for tests).
func Generate() (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := SelfSign(key, []string{"localhost"}, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	return New(key, der)
}

// SelfSign creates a self-signed certificate for key.
func SelfSign(key crypto.Signer, hostnames []string, validity time.Duration) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	fp, err := FingerprintOfKey(key.Public())
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "magic provider " + fp.ID()},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // lets clients use the certificate as its own trust anchor
	}
	for _, h := range hostnames {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
}

// ErrPinMismatch is returned when a provider presents an unexpected key.
var ErrPinMismatch = errors.New("identity: provider key does not match pinned identity")

// Pin describes what a client expects of a provider's TLS key. Exactly one of
// Fingerprint or ID is normally set; if both are set, both must match.
type Pin struct {
	Fingerprint Fingerprint
	ID          string
}

// Verify checks a presented certificate against the pin.
func (p Pin) Verify(cert *x509.Certificate) error {
	fp := FingerprintOf(cert)
	if !p.Fingerprint.IsZero() && subtle.ConstantTimeCompare(fp[:], p.Fingerprint[:]) != 1 {
		return ErrPinMismatch
	}
	if p.ID != "" && !fp.MatchesID(p.ID) {
		return ErrPinMismatch
	}
	if p.Fingerprint.IsZero() && p.ID == "" {
		return errors.New("identity: empty pin")
	}
	return nil
}

// ClientTLSConfig returns a TLS configuration that accepts exactly the pinned
// provider key, independent of host names and certificate authorities.
func (p Pin) ClientTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("identity: no certificate presented")
			}
			return p.Verify(cs.PeerCertificates[0])
		},
	}
}

// Probe connects to addr (host:port), completes a TLS handshake without
// verification and returns the fingerprint of the presented key. This is the
// first step of pairing with an unknown provider; the result must be
// confirmed by the pairing protocol before it can be trusted.
func Probe(addr string, timeout time.Duration) (Fingerprint, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	if err != nil {
		return Fingerprint{}, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return Fingerprint{}, errors.New("identity: no certificate presented")
	}
	return FingerprintOf(certs[0]), nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
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

// Equal reports whether two fingerprints are equal in constant time.
func Equal(a, b Fingerprint) bool { return subtle.ConstantTimeCompare(a[:], b[:]) == 1 }
