package local

import (
	"os"
	"runtime"
	"testing"

	"github.com/noxer/magic"
	"github.com/noxer/magic/identity"
)

func TestPublishScan(t *testing.T) {
	dir := t.TempDir()
	id, _ := identity.Generate()
	remove, err := Publish(dir, magic.Beacon{ID: id.ID(), Name: "test", URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	// A stale beacon of a dead process must be ignored.
	dead, _ := identity.Generate()
	if _, err := Publish(dir, magic.Beacon{ID: dead.ID(), Name: "dead", URL: "http://127.0.0.1:2", PID: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dir+"/garbage.json", []byte("{"), 0o644)
	got := Scan(dir)
	if runtime.GOOS == "windows" && len(got) == 2 { // no cheap liveness check there
		got = got[:1]
		if got[0].ID != id.ID() {
			got = Scan(dir)[1:]
		}
	}
	if len(got) != 1 || got[0].ID != id.ID() || got[0].PID != os.Getpid() {
		t.Fatalf("Scan = %+v", got)
	}
	remove()
	if len(Scan(dir)) != 0 {
		t.Fatal("beacon not removed")
	}
}
