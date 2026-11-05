package identity

import "testing"

func TestLoadOrCreateStable(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreate(dir, []string{"host.local", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != b.ID() || len(a.ID()) != IDLength || !ValidID(a.ID()) {
		t.Fatalf("unstable or malformed id: %s %s", a.ID(), b.ID())
	}
	fp, err := ParseFingerprint(a.Fingerprint.String())
	if err != nil || !Equal(fp, a.Fingerprint) || !fp.MatchesID(a.ID()) {
		t.Fatalf("fingerprint round trip failed: %v", err)
	}
	other, _ := Generate()
	leaf := a.Certificate.Leaf
	if (Pin{ID: a.ID()}).Verify(leaf) != nil || (Pin{Fingerprint: a.Fingerprint}).Verify(leaf) != nil {
		t.Fatal("pin rejects own certificate")
	}
	if (Pin{ID: other.ID()}).Verify(leaf) != ErrPinMismatch {
		t.Fatal("pin accepts foreign certificate")
	}
}
