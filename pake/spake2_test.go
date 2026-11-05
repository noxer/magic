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

// TestRFC9382 checks the core against the official test vectors (Appendix B).
func TestRFC9382(t *testing.T) {
	data, err := os.ReadFile("../spec/test-vectors/rfc9382-spake2-p256.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []map[string]string
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatal(err)
	}
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	for _, v := range vs {
		a, _, err := newState(Client, Params{}, h(v["w"]), h(v["x"]))
		if err != nil {
			t.Fatal(err)
		}
		b, _, _ := newState(Provider, Params{}, h(v["w"]), h(v["y"]))
		if hex.EncodeToString(a.msg) != v["pA"] || hex.EncodeToString(b.msg) != v["pB"] {
			t.Fatalf("A=%q B=%q: shares differ", v["A"], v["B"])
		}
		cA, err := a.finish(b.msg, []byte(v["A"]), []byte(v["B"]), nil)
		if err != nil {
			t.Fatal(err)
		}
		cB, _ := b.finish(a.msg, []byte(v["A"]), []byte(v["B"]), nil)
		for name, got := range map[string][]byte{"TT": a.tt, "Ke": a.ke, "KcA": a.kcA, "KcB": a.kcB, "A_conf": cA, "B_conf": cB} {
			if hex.EncodeToString(got) != v[name] {
				t.Errorf("A=%q B=%q: %s = %x, want %s", v["A"], v["B"], name, got, v[name])
			}
		}
	}
}

type vector struct {
	Suite     string `json:"suite"`
	PairingID string `json:"pairing_id"`
	Code      string `json:"code"`
	Binding   string `json:"binding"`
	IDA       string `json:"A"`
	IDB       string `json:"B"`
	AAD       string `json:"AAD"`
	W         string `json:"w"`
	X         string `json:"x"`
	Y         string `json:"y"`
	PA        string `json:"pA"`
	PB        string `json:"pB"`
	TT        string `json:"TT"`
	CA        string `json:"cA"`
	CB        string `json:"cB"`
}

// TestVectors checks (and with -update regenerates) the Magic pairing vectors.
func TestVectors(t *testing.T) {
	binding := sha256.Sum256([]byte("example provider SPKI"))
	p := Params{PairingID: "pr_7f3k2m9q", Code: "48213907", Binding: binding[:]}
	w := PasswordScalar(p.PairingID, p.Code)
	x, y := sha256.Sum256([]byte("client")), sha256.Sum256([]byte("provider")) // < n
	cs, pA, err := newState(Client, p, w, x[:])
	if err != nil {
		t.Fatal(err)
	}
	ps, pB, _ := newState(Provider, p, w, y[:])
	cB, _ := ps.Finish(pA)
	cA, _ := cs.Finish(pB)
	if cs.Verify(cB) != nil || ps.Verify(cA) != nil || !bytes.Equal(cs.tt, ps.tt) {
		t.Fatal("exchange failed")
	}
	idA, idB, aad := p.identities()
	v := vector{Suite, p.PairingID, p.Code, hex.EncodeToString(p.Binding), string(idA), string(idB), hex.EncodeToString(aad),
		hex.EncodeToString(w), hex.EncodeToString(x[:]), hex.EncodeToString(y[:]), hex.EncodeToString(pA), hex.EncodeToString(pB),
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
