package pake

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite spec/test-vectors/pairing-spake2.json")

func run(t *testing.T, client, provider Params) error {
	t.Helper()
	cs, pA, err := Start(Client, client)
	if err != nil {
		t.Fatal(err)
	}
	ps, pB, err := Start(Provider, provider)
	if err != nil {
		t.Fatal(err)
	}
	cB, err := ps.Finish(pA)
	if err != nil {
		return err
	}
	cA, err := cs.Finish(pB)
	if err != nil {
		return err
	}
	if err := cs.Verify(cB); err != nil {
		return err
	}
	return ps.Verify(cA)
}

func params(code string, binding byte) Params {
	return Params{PairingID: "pr_test", Code: code, Binding: bytes.Repeat([]byte{binding}, 32)}
}

func TestExchange(t *testing.T) {
	if err := run(t, params("12345678", 1), params("12345678", 1)); err != nil {
		t.Fatalf("matching parameters: %v", err)
	}
	if err := run(t, params("12345678", 1), params("12345679", 1)); err != ErrConfirmation {
		t.Fatalf("wrong code: got %v", err)
	}
	if err := run(t, params("12345678", 1), params("12345678", 2)); err != ErrConfirmation {
		t.Fatalf("binding mismatch (MITM): got %v", err)
	}
	other := params("12345678", 1)
	other.PairingID = "pr_other"
	if err := run(t, params("12345678", 1), other); err != ErrConfirmation {
		t.Fatalf("pairing id mismatch: got %v", err)
	}
}

func TestRejectsBadPoints(t *testing.T) {
	s, _, _ := Start(Provider, params("1", 1))
	for _, b := range [][]byte{nil, {0}, make([]byte, 65), append([]byte{4}, bytes.Repeat([]byte{0xff}, 64)...), mBytes} {
		if _, err := s.Finish(b); err != ErrBadMessage {
			t.Errorf("Finish(%x) = %v, want ErrBadMessage", b, err)
		}
	}
}

// detRand is a deterministic byte stream for test vectors.
type detRand struct {
	seed []byte
	ctr  byte
}

func (d *detRand) Read(p []byte) (int, error) {
	for i := 0; i < len(p); {
		h := sha256.Sum256(append(append([]byte{}, d.seed...), d.ctr))
		d.ctr++
		i += copy(p[i:], h[:])
	}
	return len(p), nil
}

type vector struct {
	Suite     string `json:"suite"`
	PairingID string `json:"pairing_id"`
	Code      string `json:"code"`
	Binding   string `json:"binding"`
	W         string `json:"w"`
	X         string `json:"x"`
	Y         string `json:"y"`
	PA        string `json:"pA"`
	PB        string `json:"pB"`
	TT        string `json:"TT"`
	CA        string `json:"cA"`
	CB        string `json:"cB"`
}

func TestVectors(t *testing.T) {
	binding := sha256.Sum256([]byte("example provider SPKI"))
	p := Params{PairingID: "pr_7f3k2m9q", Code: "48213907", Binding: binding[:]}
	cs, pA, err := start(Client, p, &detRand{seed: []byte("client")})
	if err != nil {
		t.Fatal(err)
	}
	ps, pB, err := start(Provider, p, &detRand{seed: []byte("provider")})
	if err != nil {
		t.Fatal(err)
	}
	cB, _ := ps.Finish(pA)
	cA, _ := cs.Finish(pB)
	if cs.Verify(cB) != nil || ps.Verify(cA) != nil {
		t.Fatal("confirmation failed")
	}
	if !bytes.Equal(cs.tt, ps.tt) {
		t.Fatal("transcripts differ")
	}
	v := vector{Suite, p.PairingID, p.Code, hex.EncodeToString(p.Binding), hex.EncodeToString(cs.w),
		hex.EncodeToString(cs.x), hex.EncodeToString(ps.x), hex.EncodeToString(pA), hex.EncodeToString(pB),
		hex.EncodeToString(cs.tt), hex.EncodeToString(cA), hex.EncodeToString(cB)}
	got, _ := json.MarshalIndent([]vector{v}, "", "  ")
	got = append(got, '\n')
	const path = "../spec/test-vectors/pairing-spake2.json"
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("test vectors changed; run with -update if intended")
	}
}
