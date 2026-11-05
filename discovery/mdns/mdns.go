// Package mdns is a small multicast DNS (RFC 6762) / DNS-SD (RFC 6763)
// implementation sufficient to advertise and browse Magic providers without
// a system daemon.
//
// The responder answers PTR, SRV, TXT, A and AAAA questions for one service
// instance, including DNS-SD subtypes and service type enumeration, sends
// announcements on start and goodbye packets on close, and answers one-shot
// ("legacy unicast") queries directly. It does not implement probing and
// conflict resolution; instance names should therefore be unique (the Magic
// daemon appends a provider ID suffix on collision).
package mdns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	groupV4 = netip.MustParseAddr("224.0.0.251")
	groupV6 = netip.MustParseAddr("ff02::fb")
)

const (
	port         = 5353
	cacheFlush   = 1 << 15
	unicastQ     = 1 << 15
	hostTTL      = 120
	serviceTTL   = 4500
	enumerateSvc = "_services._dns-sd._udp.local."
)

// Service describes a DNS-SD service instance.
type Service struct {
	Instance string   // e.g. "Basement GPU"
	Type     string   // e.g. "_magic._tcp"
	Subtypes []string // e.g. ["_chat", "_embeddings"] (leading underscore optional)
	Host     string   // host name without ".local"; defaults to os.Hostname
	Port     int
	TXT      []string // "key=value" strings
}

func (s *Service) typeName() string     { return strings.TrimSuffix(s.Type, ".") + ".local." }
func (s *Service) hostName() string     { return sanitizeHost(s.Host) + ".local." }
func (s *Service) instanceName() string { return escapeInstance(s.Instance) + "." + s.typeName() }

func (s *Service) subtypeNames() []string {
	out := make([]string, 0, len(s.Subtypes))
	for _, st := range s.Subtypes {
		if !strings.HasPrefix(st, "_") {
			st = "_" + st
		}
		out = append(out, st+"._sub."+s.typeName())
	}
	return out
}

// escapeInstance escapes dots and backslashes in an instance label (RFC 6763 4.3).
func escapeInstance(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `.`, `\.`)
	if len(s) > 63 {
		s = s[:63]
	}
	return r.Replace(s)
}

// unescapeInstance reverses escapeInstance and decimal escapes (\DDD).
func unescapeInstance(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
				b.WriteByte(byte((int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0'))))
				i += 3
				continue
			}
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func sanitizeHost(h string) string {
	h = strings.TrimSuffix(strings.TrimSuffix(h, "."), ".local")
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(h) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "magic"
	}
	return b.String()
}

func mustName(s string) dnsmessage.Name {
	n, err := dnsmessage.NewName(s)
	if err != nil {
		panic(fmt.Sprintf("mdns: invalid name %q: %v", s, err))
	}
	return n
}

func sameName(a dnsmessage.Name, b string) bool { return strings.EqualFold(a.String(), b) }

// records builds the resource records for s with the given addresses. With
// goodbye set all TTLs are zero (RFC 6762 10.1).
func (s *Service) records(addrs []netip.Addr, goodbye bool) (ptrs, svc, host []dnsmessage.Resource) {
	long, short := uint32(serviceTTL), uint32(hostTTL)
	if goodbye {
		long, short = 0, 0
	}
	inst := mustName(s.instanceName())
	hostN := mustName(s.hostName())
	shared := func(name string) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: mustName(name), Class: dnsmessage.ClassINET, TTL: long}
	}
	unique := func(n dnsmessage.Name, ttl uint32) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET | cacheFlush, TTL: ttl}
	}
	ptrs = append(ptrs, dnsmessage.Resource{Header: shared(s.typeName()), Body: &dnsmessage.PTRResource{PTR: inst}})
	for _, st := range s.subtypeNames() {
		ptrs = append(ptrs, dnsmessage.Resource{Header: shared(st), Body: &dnsmessage.PTRResource{PTR: inst}})
	}
	ptrs = append(ptrs, dnsmessage.Resource{Header: shared(enumerateSvc), Body: &dnsmessage.PTRResource{PTR: mustName(s.typeName())}})

	txt := s.TXT
	if len(txt) == 0 {
		txt = []string{""}
	}
	svc = append(svc,
		dnsmessage.Resource{Header: unique(inst, short), Body: &dnsmessage.SRVResource{Target: hostN, Port: uint16(s.Port)}},
		dnsmessage.Resource{Header: unique(inst, long), Body: &dnsmessage.TXTResource{TXT: txt}},
	)
	for _, a := range addrs {
		if a.Is4() {
			host = append(host, dnsmessage.Resource{Header: unique(hostN, short), Body: &dnsmessage.AResource{A: a.As4()}})
		} else {
			host = append(host, dnsmessage.Resource{Header: unique(hostN, short), Body: &dnsmessage.AAAAResource{AAAA: a.As16()}})
		}
	}
	setTypes(ptrs)
	setTypes(svc)
	setTypes(host)
	return ptrs, svc, host
}

func setTypes(rs []dnsmessage.Resource) {
	for i := range rs {
		switch rs[i].Body.(type) {
		case *dnsmessage.PTRResource:
			rs[i].Header.Type = dnsmessage.TypePTR
		case *dnsmessage.SRVResource:
			rs[i].Header.Type = dnsmessage.TypeSRV
		case *dnsmessage.TXTResource:
			rs[i].Header.Type = dnsmessage.TypeTXT
		case *dnsmessage.AResource:
			rs[i].Header.Type = dnsmessage.TypeA
		case *dnsmessage.AAAAResource:
			rs[i].Header.Type = dnsmessage.TypeAAAA
		}
	}
}

// answer computes the response to a query, or nil if we have nothing to say.
func (s *Service) answer(q *dnsmessage.Message, addrs []netip.Addr) (answers, additionals []dnsmessage.Resource) {
	ptrs, svc, host := s.records(addrs, false)
	have := map[string]bool{}
	add := func(dst *[]dnsmessage.Resource, rs ...dnsmessage.Resource) {
		for _, r := range rs {
			k := r.Header.Name.String() + r.Body.GoString()
			if !have[k] {
				have[k] = true
				*dst = append(*dst, r)
			}
		}
	}
	match := func(r dnsmessage.Resource, qq dnsmessage.Question) bool {
		return sameName(r.Header.Name, qq.Name.String()) && (qq.Type == dnsmessage.TypeALL || qq.Type == r.Header.Type)
	}
	for _, qq := range q.Questions {
		for _, r := range ptrs {
			if match(r, qq) {
				add(&answers, r)
				if !sameName(r.Header.Name, enumerateSvc) {
					add(&additionals, svc...)
					add(&additionals, host...)
				}
			}
		}
		for _, r := range svc {
			if match(r, qq) {
				add(&answers, r)
				add(&additionals, host...)
			}
		}
		for _, r := range host {
			if match(r, qq) {
				add(&answers, r)
			}
		}
	}
	if len(answers) == 0 {
		return nil, nil
	}
	// Known-answer suppression (RFC 6762 7.1) for PTR records.
	known := map[string]bool{}
	for _, r := range q.Answers {
		if p, ok := r.Body.(*dnsmessage.PTRResource); ok && r.Header.TTL > hostTTL {
			known[strings.ToLower(r.Header.Name.String()+"|"+p.PTR.String())] = true
		}
	}
	kept := answers[:0]
	for _, r := range answers {
		if p, ok := r.Body.(*dnsmessage.PTRResource); ok && known[strings.ToLower(r.Header.Name.String()+"|"+p.PTR.String())] {
			continue
		}
		kept = append(kept, r)
	}
	if len(kept) == 0 {
		return nil, nil
	}
	return kept, additionals
}

func pack(id uint16, response bool, questions []dnsmessage.Question, answers, additionals []dnsmessage.Resource) ([]byte, error) {
	msg := dnsmessage.Message{
		Header:      dnsmessage.Header{ID: id, Response: response, Authoritative: response},
		Questions:   questions,
		Answers:     answers,
		Additionals: additionals,
	}
	return msg.AppendPack(make([]byte, 0, 512))
}

// interfaceAddrs returns the usable addresses of an interface.
func interfaceAddrs(ifi *net.Interface) []netip.Addr {
	as, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range as {
		pfx, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := pfx.Addr().Unmap()
		if ip.IsLoopback() && ifi.Flags&net.FlagLoopback == 0 {
			continue
		}
		out = append(out, ip.WithZone(""))
	}
	return out
}

// multicastInterfaces lists up, multicast-capable interfaces. Loopback is
// included only if no other interface exists.
func multicastInterfaces() []net.Interface {
	all, _ := net.Interfaces()
	var out, lo []net.Interface
	for _, ifi := range all {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		if ifi.Flags&net.FlagLoopback != 0 {
			lo = append(lo, ifi)
			continue
		}
		out = append(out, ifi)
	}
	if len(out) == 0 {
		return lo
	}
	return out
}

func jitter(max time.Duration) time.Duration {
	return time.Duration(time.Now().UnixNano() % int64(max))
}
