package mdns

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Entry is a resolved service instance.
type Entry struct {
	Instance string // unescaped instance name, e.g. "Basement GPU"
	Host     string // target host name, e.g. "gpu.local."
	Port     int
	Addrs    []netip.Addr
	TXT      map[string]string
}

// Addr returns a "host:port" address for the entry, preferring IPv4.
func (e Entry) Addr() string {
	for _, a := range e.Addrs {
		if a.Is4() {
			return net.JoinHostPort(a.String(), strconv.Itoa(e.Port))
		}
	}
	if len(e.Addrs) > 0 {
		return net.JoinHostPort(e.Addrs[0].String(), strconv.Itoa(e.Port))
	}
	return net.JoinHostPort(strings.TrimSuffix(e.Host, "."), strconv.Itoa(e.Port))
}

type partial struct {
	name     string
	host     string
	port     int
	txt      map[string]string
	hasSRV   bool
	hasTXT   bool
	reported bool
}

// Browse sends one-shot mDNS queries for service (e.g. "_magic._tcp", or
// "_chat._sub._magic._tcp" for a subtype) and calls found for each resolved
// instance until ctx is done. Queries are repeated with exponential backoff.
func Browse(ctx context.Context, service string, found func(Entry)) error {
	svcName := strings.TrimSuffix(service, ".") + ".local."
	b := &browser{svc: svcName, found: found, inst: map[string]*partial{}, hosts: map[string][]netip.Addr{}}
	ifaces := multicastInterfaces()

	c4, err4 := net.ListenPacket("udp4", "0.0.0.0:0")
	c6, err6 := net.ListenPacket("udp6", "[::]:0")
	if err4 != nil && err6 != nil {
		return err4
	}
	var p4 *ipv4.PacketConn
	var p6 *ipv6.PacketConn
	var wg sync.WaitGroup
	if err4 == nil {
		p4 = ipv4.NewPacketConn(c4)
		p4.SetMulticastTTL(255)
		p4.SetMulticastLoopback(true)
		wg.Add(1)
		go func() { defer wg.Done(); b.read(c4) }()
	}
	if err6 == nil {
		p6 = ipv6.NewPacketConn(c6)
		p6.SetMulticastHopLimit(255)
		p6.SetMulticastLoopback(true)
		wg.Add(1)
		go func() { defer wg.Done(); b.read(c6) }()
	}
	send := func(qs []dnsmessage.Question) {
		pkt, err := pack(0, false, qs, nil, nil)
		if err != nil {
			return
		}
		for i := range ifaces {
			ifi := &ifaces[i]
			if p4 != nil && p4.SetMulticastInterface(ifi) == nil {
				p4.WriteTo(pkt, nil, &net.UDPAddr{IP: groupV4.AsSlice(), Port: port})
			}
			if p6 != nil && p6.SetMulticastInterface(ifi) == nil {
				p6.WriteTo(pkt, nil, &net.UDPAddr{IP: groupV6.AsSlice(), Port: port, Zone: ifi.Name})
			}
		}
	}
	b.query = send

	delay := 250 * time.Millisecond
	timer := time.NewTimer(0)
	defer timer.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-timer.C:
			send([]dnsmessage.Question{{Name: mustName(svcName), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}})
			b.resolveMissing()
			timer.Reset(delay)
			if delay < 8*time.Second {
				delay *= 2
			}
		}
	}
	if c4 != nil {
		c4.Close()
	}
	if c6 != nil {
		c6.Close()
	}
	wg.Wait()
	return nil
}

type browser struct {
	svc   string
	found func(Entry)
	query func([]dnsmessage.Question)

	mu    sync.Mutex
	inst  map[string]*partial     // lower-case instance name ->
	hosts map[string][]netip.Addr // lower-case host name ->
}

func (b *browser) read(c net.PacketConn) {
	buf := make([]byte, 9000)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil || !m.Response {
			continue
		}
		b.process(&m)
	}
}

func (b *browser) process(m *dnsmessage.Message) {
	b.mu.Lock()
	var ready []Entry
	all := append(append([]dnsmessage.Resource{}, m.Answers...), m.Additionals...)
	all = append(all, m.Authorities...)
	for _, r := range all {
		name := strings.ToLower(r.Header.Name.String())
		switch body := r.Body.(type) {
		case *dnsmessage.PTRResource:
			if name == strings.ToLower(b.svc) && r.Header.TTL > 0 {
				b.instance(body.PTR.String())
			}
		case *dnsmessage.SRVResource:
			if p, ok := b.inst[name]; ok {
				p.host, p.port, p.hasSRV = body.Target.String(), int(body.Port), true
			}
		case *dnsmessage.TXTResource:
			if p, ok := b.inst[name]; ok {
				p.txt, p.hasTXT = parseTXT(body.TXT), true
			}
		case *dnsmessage.AResource:
			b.addHost(name, netip.AddrFrom4(body.A))
		case *dnsmessage.AAAAResource:
			b.addHost(name, netip.AddrFrom16(body.AAAA))
		}
	}
	for _, p := range b.inst {
		if p.reported || !p.hasSRV || !p.hasTXT || len(b.hosts[strings.ToLower(p.host)]) == 0 {
			continue
		}
		p.reported = true
		ready = append(ready, Entry{
			Instance: unescapeInstance(strings.TrimSuffix(p.name[:len(p.name)-len(b.svcSuffix(p.name))], ".")),
			Host:     p.host,
			Port:     p.port,
			Addrs:    slices.Clone(b.hosts[strings.ToLower(p.host)]),
			TXT:      p.txt,
		})
	}
	b.mu.Unlock()
	for _, e := range ready {
		b.found(e)
	}
}

// svcSuffix returns the service type suffix of an instance name. Subtype
// browsing yields instances under the parent type.
func (b *browser) svcSuffix(inst string) string {
	t := b.svc
	if i := strings.Index(strings.ToLower(t), "._sub."); i >= 0 {
		t = t[i+len("._sub."):]
	}
	if len(inst) >= len(t) && strings.EqualFold(inst[len(inst)-len(t):], t) {
		return t
	}
	return ""
}

func (b *browser) instance(name string) {
	k := strings.ToLower(name)
	if _, ok := b.inst[k]; !ok {
		b.inst[k] = &partial{name: name}
	}
}

func (b *browser) addHost(name string, a netip.Addr) {
	a = a.Unmap()
	if !slices.Contains(b.hosts[name], a) {
		b.hosts[name] = append(b.hosts[name], a)
	}
}

func (b *browser) resolveMissing() {
	b.mu.Lock()
	var qs []dnsmessage.Question
	for _, p := range b.inst {
		if p.reported {
			continue
		}
		if !p.hasSRV || !p.hasTXT {
			qs = append(qs,
				dnsmessage.Question{Name: mustName(p.name), Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET},
				dnsmessage.Question{Name: mustName(p.name), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET})
		} else if len(b.hosts[strings.ToLower(p.host)]) == 0 {
			qs = append(qs,
				dnsmessage.Question{Name: mustName(p.host), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
				dnsmessage.Question{Name: mustName(p.host), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET})
		}
	}
	b.mu.Unlock()
	if len(qs) > 0 && b.query != nil {
		b.query(qs)
	}
}

// parseTXT parses DNS-SD key/value strings (RFC 6763 6.3). Keys are
// case-insensitive; the first occurrence wins.
func parseTXT(txt []string) map[string]string {
	m := map[string]string{}
	for _, s := range txt {
		if s == "" {
			continue
		}
		k, v, _ := strings.Cut(s, "=")
		k = strings.ToLower(k)
		if _, dup := m[k]; !dup && k != "" {
			m[k] = v
		}
	}
	return m
}
