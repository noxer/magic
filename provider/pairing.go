package provider

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/noxer/magic"
	"github.com/noxer/magic/pake"
)

// Pairing limits.
const (
	CodeDigits        = 8
	PairingTTL        = 5 * time.Minute
	maxPending        = 16
	maxTicketFailures = 3
	startsPerMinute   = 10
)

// Pending is a pairing session waiting for the client to prove the code.
type Pending struct {
	ID        string             `json:"id"`
	Client    magic.ClientInfo   `json:"client"`
	Scopes    []magic.Capability `json:"scopes"`
	Code      string             `json:"code,omitempty"`
	Ticket    string             `json:"ticket,omitempty"`
	ExpiresAt time.Time          `json:"expires_at"`

	state *pake.State
}

// Ticket is an operator-created pairing code that can be redeemed once.
type Ticket struct {
	ID        string             `json:"ticket"`
	Code      string             `json:"code"`
	Scopes    []magic.Capability `json:"scopes"`
	ExpiresAt time.Time          `json:"expires_at"`
	failures  int
}

var (
	errNotFound      = errors.New("no such pairing session")
	errRateLimited   = errors.New("too many pairing attempts, try again later")
	errWrongStage    = errors.New("pairing session is not in the expected state")
	errPairingFailed = errors.New("pairing failed: wrong code or provider key mismatch")
)

type pairings struct {
	mu      sync.Mutex
	pending map[string]*Pending
	tickets map[string]*Ticket
	starts  []time.Time
	now     func() time.Time
}

func newPairings() *pairings {
	return &pairings{pending: map[string]*Pending{}, tickets: map[string]*Ticket{}, now: time.Now}
}

func randomCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%0*d", CodeDigits, n)
}

func (p *pairings) gcLocked() {
	now := p.now()
	for id, s := range p.pending {
		if now.After(s.ExpiresAt) {
			delete(p.pending, id)
		}
	}
	for id, t := range p.tickets {
		if now.After(t.ExpiresAt) {
			delete(p.tickets, id)
		}
	}
	cut := 0
	for cut < len(p.starts) && now.Sub(p.starts[cut]) > time.Minute {
		cut++
	}
	p.starts = p.starts[cut:]
}

// start creates a pairing session. scopes must already be validated.
func (p *pairings) start(client magic.ClientInfo, scopes []magic.Capability, ticketID string) (*Pending, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	if len(p.pending) >= maxPending || len(p.starts) >= startsPerMinute {
		return nil, errRateLimited
	}
	s := &Pending{ID: newID("pr_"), Client: client, Scopes: scopes, ExpiresAt: p.now().Add(PairingTTL)}
	if ticketID != "" {
		t, ok := p.tickets[ticketID]
		if !ok {
			return nil, errNotFound
		}
		s.Code, s.Ticket = t.Code, t.ID
		s.Scopes = intersect(scopes, t.Scopes)
		if t.ExpiresAt.Before(s.ExpiresAt) {
			s.ExpiresAt = t.ExpiresAt
		}
	} else {
		s.Code = randomCode()
	}
	p.starts = append(p.starts, p.now())
	p.pending[s.ID] = s
	return s, nil
}

// exchange runs the provider side of SPAKE2 for a session.
func (p *pairings) exchange(id string, binding, pA []byte) (pB, confirm []byte, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	s, ok := p.pending[id]
	if !ok {
		return nil, nil, errNotFound
	}
	if s.state != nil {
		return nil, nil, errWrongStage
	}
	st, msg, err := pake.Start(pake.Provider, pake.Params{PairingID: s.ID, Code: s.Code, Binding: binding})
	if err != nil {
		return nil, nil, err
	}
	c, err := st.Finish(pA)
	if err != nil {
		p.failLocked(s)
		return nil, nil, err
	}
	s.state = st
	return msg, c, nil
}

// confirm verifies the client's MAC. On success the session is consumed and returned.
func (p *pairings) confirm(id string, mac []byte) (*Pending, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	s, ok := p.pending[id]
	if !ok {
		return nil, errNotFound
	}
	if s.state == nil {
		return nil, errWrongStage
	}
	if err := s.state.Verify(mac); err != nil {
		p.failLocked(s)
		return nil, errPairingFailed
	}
	delete(p.pending, id)
	if s.Ticket != "" {
		delete(p.tickets, s.Ticket)
	}
	return s, nil
}

// failLocked ends a session after a failed attempt: each session allows
// exactly one guess, tickets allow maxTicketFailures in total.
func (p *pairings) failLocked(s *Pending) {
	delete(p.pending, s.ID)
	if t, ok := p.tickets[s.Ticket]; ok {
		t.failures++
		if t.failures >= maxTicketFailures {
			delete(p.tickets, t.ID)
		}
	}
}

func (p *pairings) cancel(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.pending[id]
	delete(p.pending, id)
	return ok
}

func (p *pairings) list() []Pending {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	out := make([]Pending, 0, len(p.pending))
	for _, s := range p.pending {
		c := *s
		c.state = nil
		if c.Ticket != "" {
			c.Code = "" // the operator already knows ticket codes
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out
}

func (p *pairings) newTicket(scopes []magic.Capability, ttl time.Duration) *Ticket {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	if ttl <= 0 || ttl > time.Hour {
		ttl = 10 * time.Minute
	}
	t := &Ticket{ID: newID("tk_"), Code: randomCode(), Scopes: scopes, ExpiresAt: p.now().Add(ttl)}
	p.tickets[t.ID] = t
	return t
}

func intersect(a, b []magic.Capability) []magic.Capability {
	var out []magic.Capability
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
				break
			}
		}
	}
	return out
}
