package provider_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/noxer/magic"
	"github.com/noxer/magic/client"
	"github.com/noxer/magic/identity"
	"github.com/noxer/magic/provider"
)

type fixture struct {
	srv   *provider.Server
	ts    *httptest.Server
	mu    sync.Mutex
	codes map[string]string // pairing id -> code shown to the operator
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{codes: map[string]string{}}
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("client token leaked to backend")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/chat/completions":
			io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"hello from backend"}}]}`)
		case "/embeddings":
			io.WriteString(w, `{"data":[{"embedding":[0.1,0.2]}]}`)
		default:
			http.NotFound(w, r)
		}
	})
	f.srv, err = provider.New(provider.Config{
		Identity: id,
		Name:     "Test GPU",
		Models: func(context.Context) ([]magic.Model, error) {
			return []magic.Model{
				{ID: "llama", Capabilities: []magic.Capability{magic.Chat}},
				{ID: "embed", Capabilities: []magic.Capability{magic.Embeddings}},
			}, nil
		},
		Backend: backend,
		OnPairing: func(p provider.Pending) {
			f.mu.Lock()
			f.codes[p.ID] = p.Code
			f.mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.ts = httptest.NewUnstartedServer(f.srv.Handler(provider.Options{}))
	f.ts.TLS = id.TLSConfig()
	f.ts.StartTLS()
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fixture) pinned(t *testing.T) *http.Client {
	hc, err := client.HTTPClient(f.ts.URL, identity.Pin{ID: f.srv.ID()})
	if err != nil {
		t.Fatal(err)
	}
	return hc
}

func (f *fixture) operatorCode(ctx context.Context, s magic.PairingStarted) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.codes[s.PairingID], nil
}

func pairOpts(url string, code func(context.Context, magic.PairingStarted) (string, error), scopes ...magic.Capability) client.PairOptions {
	return client.PairOptions{URL: url, Client: magic.ClientInfo{Name: "test app"}, Scopes: scopes, Code: code}
}

func TestPairAndUse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Unauthenticated descriptor hides model details.
	anon := &client.Client{BaseURL: f.ts.URL, HTTP: f.pinned(t)}
	d, err := anon.Descriptor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.Provider.ID != f.srv.ID() || len(d.Models) != 0 || len(d.Capabilities) != 2 {
		t.Fatalf("unexpected public descriptor: %+v", d)
	}

	cred, err := client.Pair(ctx, pairOpts(f.ts.URL, f.operatorCode, magic.Chat))
	if err != nil {
		t.Fatal(err)
	}
	if cred.ProviderID != f.srv.ID() || !strings.HasPrefix(cred.Token, magic.TokenPrefix) {
		t.Fatalf("bad credential %+v", cred)
	}
	c, err := client.New(f.ts.URL, cred)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := c.Chat(ctx, "llama", []client.ChatMessage{{Role: "user", Content: "hi"}})
	if err != nil || reply != "hello from backend" {
		t.Fatalf("chat: %q, %v", reply, err)
	}
	// Scope enforcement: only chat was granted.
	var ae *client.APIError
	if _, err := c.Embed(ctx, "embed", []string{"x"}); !errors.As(err, &ae) || ae.Status != 403 {
		t.Fatalf("embeddings without scope: %v", err)
	}
	d, err = c.Descriptor(ctx)
	if err != nil || len(d.Models) != 2 {
		t.Fatalf("authenticated descriptor: %+v %v", d, err)
	}
	s, err := c.Session(ctx)
	if err != nil || s.Name != "test app" {
		t.Fatalf("session: %+v %v", s, err)
	}
	// Unpair revokes the token.
	if err := c.Unpair(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Session(ctx); !errors.As(err, &ae) || ae.Status != 401 {
		t.Fatalf("after unpair: %v", err)
	}
}

func TestWrongCodeSingleAttempt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	wrong := func(context.Context, magic.PairingStarted) (string, error) { return "0000-0000", nil }
	if _, err := client.Pair(ctx, pairOpts(f.ts.URL, wrong)); !errors.Is(err, client.ErrPairingFailed) {
		t.Fatalf("wrong code: %v", err)
	}
	if n := len(f.srv.PendingPairings()); n != 0 {
		t.Fatalf("failed session not discarded: %d pending", n)
	}
	if n := len(f.srv.Store().List()); n != 0 {
		t.Fatalf("token issued after failed pairing")
	}
}

func TestTicket(t *testing.T) {
	f := newFixture(t)
	tk := f.srv.NewTicket([]magic.Capability{magic.Embeddings}, 0)
	opts := pairOpts(f.ts.URL, func(context.Context, magic.PairingStarted) (string, error) { return tk.Code, nil }, magic.Chat, magic.Embeddings)
	opts.Ticket = tk.ID
	cred, err := client.Pair(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.Scopes) != 1 || cred.Scopes[0] != magic.Embeddings {
		t.Fatalf("ticket scopes not enforced: %v", cred.Scopes)
	}
	if _, err := client.Pair(context.Background(), opts); err == nil {
		t.Fatal("ticket redeemed twice")
	}
}

// TestMITM runs pairing through an interceptor that terminates TLS with its
// own key and relays everything. Even with the right code, pairing must fail.
func TestMITM(t *testing.T) {
	f := newFixture(t)
	evil, _ := identity.Generate()
	upstream := f.ts.Listener.Addr().String()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", evil.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				u, err := tls.Dial("tcp", upstream, &tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return
				}
				defer u.Close()
				go io.Copy(u, c)
				io.Copy(c, u)
			}()
		}
	}()
	mitmURL := "https://" + ln.Addr().String()
	_, err = client.Pair(context.Background(), pairOpts(mitmURL, f.operatorCode))
	if !errors.Is(err, client.ErrPairingFailed) {
		t.Fatalf("pairing through MITM: %v", err)
	}
	if n := len(f.srv.Store().List()); n != 0 {
		t.Fatal("provider issued a token to the interceptor")
	}
	// And a client that expects the real provider ID refuses the interceptor outright.
	opts := pairOpts(mitmURL, f.operatorCode)
	opts.ExpectID = f.srv.ID()
	if _, err := client.Pair(context.Background(), opts); !errors.Is(err, identity.ErrPinMismatch) {
		t.Fatalf("expected pin mismatch, got %v", err)
	}
}

func TestLoopbackHostCheck(t *testing.T) {
	f := newFixture(t)
	h := f.srv.Handler(provider.Options{Loopback: true})
	for host, want := range map[string]int{"127.0.0.1:1234": 200, "localhost": 200, "[::1]:9": 200, "evil.example:1234": 421} {
		r := httptest.NewRequest("GET", magic.WellKnownPath, nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("Host %s: got %d want %d", host, w.Code, want)
		}
	}
}

func TestAdminAPI(t *testing.T) {
	f := newFixture(t)
	_, tok, _ := f.srv.Store().Issue(provider.KindLocal, magic.ClientInfo{Name: "admin"}, nil, true)
	c := &client.Client{BaseURL: f.ts.URL, Token: tok, HTTP: f.pinned(t)}
	var g magic.Grant
	if err := c.Do(context.Background(), "POST", magic.APIPrefix+"/admin/tokens", map[string]any{"name": "script", "scopes": []string{"chat"}}, &g); err != nil {
		t.Fatal(err)
	}
	var list struct{ Clients []json.RawMessage }
	if err := c.Do(context.Background(), "GET", magic.APIPrefix+"/admin/clients", nil, &list); err != nil || len(list.Clients) != 2 {
		t.Fatalf("clients: %v %d", err, len(list.Clients))
	}
	user := &client.Client{BaseURL: f.ts.URL, Token: g.Token, HTTP: f.pinned(t)}
	var ae *client.APIError
	if err := user.Do(context.Background(), "GET", magic.APIPrefix+"/admin/clients", nil, nil); !errors.As(err, &ae) || ae.Status != 403 {
		t.Fatalf("non-admin access to admin API: %v", err)
	}
}
