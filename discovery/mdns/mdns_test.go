package mdns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var testSvc = Service{
	Instance: "Basement GPU (2.0)",
	Type:     "_magic._tcp",
	Subtypes: []string{"chat", "_embeddings"},
	Host:     "Gpu-Box.example",
	Port:     8443,
	TXT:      []string{"txtvers=1", "id=abc", "caps=chat,embeddings"},
}

func query(name string, t dnsmessage.Type) *dnsmessage.Message {
	return &dnsmessage.Message{Questions: []dnsmessage.Question{{Name: mustName(name), Type: t, Class: dnsmessage.ClassINET}}}
}

func TestAnswerAndParse(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("fe80::1")}
	for _, name := range []string{"_magic._tcp.local.", "_chat._sub._magic._tcp.local.", "_embeddings._sub._magic._tcp.local."} {
		ans, add := testSvc.answer(query(name, dnsmessage.TypePTR), addrs)
		if len(ans) != 1 || len(add) != 4 {
			t.Fatalf("%s: %d answers, %d additionals", name, len(ans), len(add))
		}
		pkt, err := pack(0, true, nil, ans, add)
		if err != nil {
			t.Fatal(err)
		}
		var got []Entry
		b := &browser{svc: name, found: func(e Entry) { got = append(got, e) }, inst: map[string]*partial{}, hosts: map[string][]netip.Addr{}}
		var m dnsmessage.Message
		if err := m.Unpack(pkt); err != nil {
			t.Fatal(err)
		}
		b.process(&m)
		if len(got) != 1 {
			t.Fatalf("%s: resolved %d entries", name, len(got))
		}
		e := got[0]
		if e.Instance != testSvc.Instance || e.Port != 8443 || e.Host != "gpu-box.local." || len(e.Addrs) != 2 || e.TXT["id"] != "abc" {
			t.Fatalf("%s: bad entry %+v", name, e)
		}
		if e.Addr() != "192.168.1.20:8443" {
			t.Fatalf("Addr() = %s", e.Addr())
		}
	}
	if ans, _ := testSvc.answer(query("_printer._tcp.local.", dnsmessage.TypePTR), addrs); ans != nil {
		t.Fatal("answered foreign service")
	}
	if ans, _ := testSvc.answer(query("_services._dns-sd._udp.local.", dnsmessage.TypePTR), addrs); len(ans) != 1 {
		t.Fatal("service enumeration not answered")
	}
	if ans, _ := testSvc.answer(query("gpu-box.local.", dnsmessage.TypeA), addrs); len(ans) != 1 {
		t.Fatal("A query not answered")
	}
}

func TestKnownAnswerSuppression(t *testing.T) {
	q := query("_magic._tcp.local.", dnsmessage.TypePTR)
	q.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: mustName("_magic._tcp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 4000},
		Body:   &dnsmessage.PTRResource{PTR: mustName(testSvc.instanceName())},
	}}
	if ans, _ := testSvc.answer(q, nil); ans != nil {
		t.Fatal("known answer not suppressed")
	}
}

func TestEscaping(t *testing.T) {
	for _, s := range []string{"plain", "with.dot", `back\slash`, "Basement GPU (2.0)"} {
		if got := unescapeInstance(escapeInstance(s)); got != s {
			t.Errorf("round trip %q -> %q", s, got)
		}
	}
	if unescapeInstance(`a\032b`) != "a b" {
		t.Error("decimal escape")
	}
}

// TestLive advertises and browses over real sockets. It is skipped where
// multicast is unavailable (e.g. some containers).
func TestLive(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	svc := testSvc
	svc.Instance = "magic live test"
	svc.Host = "magic-live-test"
	r, err := Advertise(svc)
	if err != nil {
		t.Skipf("cannot advertise: %v", err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	found := make(chan Entry, 4)
	go Browse(ctx, "_chat._sub._magic._tcp", func(e Entry) {
		if e.Instance == svc.Instance {
			found <- e
		}
	})
	select {
	case e := <-found:
		if e.Port != svc.Port {
			t.Fatalf("bad port %d", e.Port)
		}
	case <-ctx.Done():
		t.Skip("no response over multicast (environment may block it)")
	}
}
