// Package discovery finds Magic providers on the local computer (beacon
// files), on the local network (DNS-SD over multicast DNS) and through
// explicit configuration (the MAGIC_PROVIDER environment variable).
package discovery

import (
	"context"
	"errors"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noxer/magic"
	"github.com/noxer/magic/discovery/local"
	"github.com/noxer/magic/discovery/mdns"
	"github.com/noxer/magic/identity"
)

// Sources of a discovered provider.
const (
	SourceEnv   = "env"
	SourceLocal = "local"
	SourceMDNS  = "mdns"
)

// Provider is a discovered provider. Discovery results are hints: nothing in
// them is authenticated except that ID is checked against the provider's TLS
// key when connecting.
type Provider struct {
	ID           string
	Name         string
	URLs         []string
	Capabilities []magic.Capability
	// Fingerprint is known for local providers (from the beacon) and is
	// required to pin plain-HTTP loopback connections.
	Fingerprint identity.Fingerprint
	TokenFile   string
	Sources     []string
}

// Has reports whether the provider advertises capability c.
func (p Provider) Has(c magic.Capability) bool { return slices.Contains(p.Capabilities, c) }

// TXT returns the DNS-SD TXT strings advertised for a provider.
func TXT(id string, caps []magic.Capability, auth []string) []string {
	cs := make([]string, len(caps))
	for i, c := range caps {
		cs[i] = string(c)
	}
	return []string{
		"txtvers=1",
		"v=" + magic.Version,
		"id=" + id,
		"caps=" + strings.Join(cs, ","),
		"auth=" + strings.Join(auth, ","),
	}
}

// Advertisement configures Advertise.
type Advertisement struct {
	Name         string // instance name shown to users
	Port         int
	ID           string
	Capabilities []magic.Capability
	Auth         []string
}

// Advertise announces a provider on the local network until the returned
// responder is closed. Each registered capability is also published as a
// DNS-SD subtype, so clients can browse for e.g. "_embeddings._sub._magic._tcp".
func Advertise(a Advertisement) (*mdns.Responder, error) {
	if !identity.ValidID(a.ID) {
		return nil, errors.New("discovery: invalid provider id")
	}
	var subs []string
	for _, c := range a.Capabilities {
		if c.Valid() {
			subs = append(subs, "_"+string(c))
		}
	}
	return mdns.Advertise(mdns.Service{
		Instance: a.Name,
		Type:     magic.ServiceType,
		Subtypes: subs,
		Port:     a.Port,
		TXT:      TXT(a.ID, a.Capabilities, a.Auth),
	})
}

// FromEnv returns the provider configured by MAGIC_PROVIDER, if any. The
// value is a base URL; the provider ID may be given as the URL fragment
// ("https://gpu.lan:8765#<provider-id>").
func FromEnv() (*Provider, error) {
	v := os.Getenv("MAGIC_PROVIDER")
	if v == "" {
		return nil, nil
	}
	return ParseURL(v)
}

// ParseURL parses a provider URL with an optional "#<provider-id>" fragment.
func ParseURL(s string) (*Provider, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && u.Scheme != "http" || u.Host == "" {
		return nil, errors.New("discovery: provider URL must be http(s)://host[:port]")
	}
	p := &Provider{Sources: []string{SourceEnv}}
	if u.Fragment != "" {
		if !identity.ValidID(u.Fragment) {
			return nil, errors.New("discovery: URL fragment is not a provider id")
		}
		p.ID = strings.ToLower(u.Fragment)
	}
	u.Fragment, u.Path, u.RawQuery = "", "", ""
	p.URLs = []string{u.String()}
	return p, nil
}

// Options configure Discover and Browse.
type Options struct {
	// Capability restricts results to providers advertising it.
	Capability magic.Capability
	// NoMDNS disables network discovery; NoLocal disables beacon discovery.
	NoMDNS, NoLocal bool
}

// Browse reports providers as they are found until ctx is done. A provider
// found through several sources is reported again with merged information.
func Browse(ctx context.Context, opts Options, found func(Provider)) error {
	var mu sync.Mutex
	known := map[string]*Provider{}
	report := func(p Provider) {
		if opts.Capability != "" && !p.Has(opts.Capability) {
			return
		}
		mu.Lock()
		if old, ok := known[p.ID]; ok {
			merged := merge(*old, p)
			if equal(*old, merged) {
				mu.Unlock()
				return
			}
			p = merged
		}
		known[p.ID] = &p
		mu.Unlock()
		found(p)
	}
	if !opts.NoLocal {
		for _, b := range local.Scan() {
			p := Provider{ID: b.ID, Name: b.Name, URLs: []string{b.URL}, Capabilities: b.Capabilities, TokenFile: b.TokenFile, Sources: []string{SourceLocal}}
			if fp, err := identity.ParseFingerprint(b.Fingerprint); err == nil && fp.MatchesID(b.ID) {
				p.Fingerprint = fp
			}
			report(p)
		}
	}
	if opts.NoMDNS {
		return nil
	}
	svc := magic.ServiceType
	if opts.Capability != "" && opts.Capability.Valid() {
		svc = "_" + string(opts.Capability) + "._sub." + magic.ServiceType
	}
	return mdns.Browse(ctx, svc, func(e mdns.Entry) {
		id := strings.ToLower(e.TXT["id"])
		if !identity.ValidID(id) {
			return
		}
		p := Provider{ID: id, Name: e.Instance, Sources: []string{SourceMDNS}}
		for _, c := range strings.Split(e.TXT["caps"], ",") {
			if c != "" {
				p.Capabilities = append(p.Capabilities, magic.Capability(c))
			}
		}
		p.URLs = append(p.URLs, "https://"+e.Addr())
		if h := strings.TrimSuffix(e.Host, "."); h != "" {
			p.URLs = append(p.URLs, "https://"+h+":"+strconv.Itoa(e.Port))
		}
		report(p)
	})
}

// Discover collects providers for the given duration.
func Discover(ctx context.Context, wait time.Duration, opts Options) ([]Provider, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var mu sync.Mutex
	byID := map[string]Provider{}
	var order []string
	err := Browse(ctx, opts, func(p Provider) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := byID[p.ID]; !ok {
			order = append(order, p.ID)
		}
		byID[p.ID] = p
	})
	mu.Lock()
	defer mu.Unlock()
	out := make([]Provider, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, err
}

func merge(a, b Provider) Provider {
	out := a
	if out.Name == "" {
		out.Name = b.Name
	}
	for _, u := range b.URLs {
		if !slices.Contains(out.URLs, u) {
			out.URLs = append(out.URLs, u)
		}
	}
	for _, c := range b.Capabilities {
		if !slices.Contains(out.Capabilities, c) {
			out.Capabilities = append(out.Capabilities, c)
		}
	}
	for _, s := range b.Sources {
		if !slices.Contains(out.Sources, s) {
			out.Sources = append(out.Sources, s)
		}
	}
	if out.Fingerprint.IsZero() {
		out.Fingerprint = b.Fingerprint
	}
	if out.TokenFile == "" {
		out.TokenFile = b.TokenFile
	}
	return out
}

func equal(a, b Provider) bool {
	return a.Name == b.Name && slices.Equal(a.URLs, b.URLs) && slices.Equal(a.Capabilities, b.Capabilities) &&
		slices.Equal(a.Sources, b.Sources) && a.Fingerprint == b.Fingerprint && a.TokenFile == b.TokenFile
}
