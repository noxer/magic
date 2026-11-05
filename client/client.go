// Package client implements the client side of the Magic protocol: pairing
// with providers, remembering credentials and calling capabilities.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/noxer/magic"
	"github.com/noxer/magic/identity"
	"github.com/noxer/magic/pake"
)

// APIError is an error response from a provider.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("magic: HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("magic: %s: %s", e.Code, e.Message)
}

// HTTPClient returns an *http.Client that talks to a provider at baseURL.
// For https URLs the provider's key must match pin; plain http is only
// permitted for loopback addresses.
func HTTPClient(baseURL string, pin identity.Pin) (*http.Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:               nil, // never send local-network traffic through a proxy
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	switch u.Scheme {
	case "https":
		tr.TLSClientConfig = pin.ClientTLSConfig()
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, errors.New("magic: plain http is only allowed for loopback providers")
		}
	default:
		return nil, fmt.Errorf("magic: unsupported URL scheme %q", u.Scheme)
	}
	return &http.Client{Transport: tr}, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Client calls one provider.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	// ProviderID, if set, must match the ID in descriptors and sessions.
	ProviderID string
}

// New creates a client for a provider at baseURL authenticated with cred.
func New(baseURL string, cred *Credential) (*Client, error) {
	hc, err := HTTPClient(baseURL, cred.Pin())
	if err != nil {
		return nil, err
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: cred.Token, HTTP: hc, ProviderID: cred.ProviderID}, nil
}

// Do sends a JSON request and decodes a JSON response into out (if non-nil).
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return readAPIError(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

func readAPIError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	e := &APIError{Status: resp.StatusCode, Message: strings.TrimSpace(string(b))}
	var me magic.Error
	if json.Unmarshal(b, &me) == nil && me.Err.Message != "" {
		e.Code, e.Message = me.Err.Code, me.Err.Message
	} else {
		// OpenAI-style errors: {"error": {"message": ..., "type": ...}}
		var oe struct {
			Error struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			} `json:"error"`
		}
		if json.Unmarshal(b, &oe) == nil && oe.Error.Message != "" {
			e.Code, e.Message = oe.Error.Type, oe.Error.Message
		}
	}
	return e
}

// Descriptor fetches the provider descriptor.
func (c *Client) Descriptor(ctx context.Context) (*magic.Descriptor, error) {
	var d magic.Descriptor
	if err := c.Do(ctx, http.MethodGet, magic.WellKnownPath, nil, &d); err != nil {
		return nil, err
	}
	if c.ProviderID != "" && !strings.EqualFold(d.Provider.ID, c.ProviderID) {
		return nil, identity.ErrPinMismatch
	}
	return &d, nil
}

// Session returns information about the current token.
func (c *Client) Session(ctx context.Context) (*magic.Session, error) {
	var s magic.Session
	if err := c.Do(ctx, http.MethodGet, magic.APIPrefix+"/session", nil, &s); err != nil {
		return nil, err
	}
	if c.ProviderID != "" && !strings.EqualFold(s.Provider.ID, c.ProviderID) {
		return nil, identity.ErrPinMismatch
	}
	return &s, nil
}

// Unpair revokes the client's own token at the provider.
func (c *Client) Unpair(ctx context.Context) error {
	return c.Do(ctx, http.MethodDelete, magic.APIPrefix+"/session", nil, nil)
}

// ChatMessage is a message in the OpenAI chat format (text only).
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is a minimal chat completion request.
type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream,omitempty"`
}

// ChatResponse is a minimal chat completion response.
type ChatResponse struct {
	Choices []struct {
		Message ChatMessage `json:"message"`
	} `json:"choices"`
}

// Chat runs a non-streaming chat completion and returns the reply text.
func (c *Client) Chat(ctx context.Context, model string, msgs []ChatMessage) (string, error) {
	var resp ChatResponse
	if err := c.Do(ctx, http.MethodPost, "/v1/chat/completions", ChatRequest{Model: model, Messages: msgs}, &resp); err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", errors.New("magic: empty chat response")
	}
	return resp.Choices[0].Message.Content, nil
}

// Embed returns embeddings for the inputs.
func (c *Client) Embed(ctx context.Context, model string, inputs []string) ([][]float64, error) {
	var resp struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := c.Do(ctx, http.MethodPost, "/v1/embeddings", map[string]any{"model": model, "input": inputs}, &resp); err != nil {
		return nil, err
	}
	out := make([][]float64, len(resp.Data))
	for i, d := range resp.Data {
		out[i] = d.Embedding
	}
	return out, nil
}

// PairOptions configure Pair.
type PairOptions struct {
	// URL is the provider's base URL (https://host:port, or http://127.0.0.1:port).
	URL string
	// ExpectID, if set, is the provider ID learned from discovery or a pairing
	// URI; pairing fails if the provider's key does not match it.
	ExpectID string
	// Fingerprint is the provider's key fingerprint. It is learned from the TLS
	// handshake for https URLs, and must be supplied (from a local beacon) for
	// loopback http URLs.
	Fingerprint identity.Fingerprint
	Client      magic.ClientInfo
	Scopes      []magic.Capability
	// Ticket redeems an operator-created ticket instead of a per-request code.
	Ticket string
	// Code is called once the provider has displayed (or knows) the code and
	// must return the code the user entered.
	Code func(ctx context.Context, started magic.PairingStarted) (string, error)
}

// ErrPairingFailed means the code was wrong or someone is intercepting the connection.
var ErrPairingFailed = errors.New("magic: pairing failed: wrong code, or the connection is being intercepted")

// Pair runs the pairing protocol and returns the resulting credential.
func Pair(ctx context.Context, opts PairOptions) (*Credential, error) {
	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, err
	}
	fp := opts.Fingerprint
	if u.Scheme == "https" {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		seen, err := identity.Probe(net.JoinHostPort(u.Hostname(), port), 5*time.Second)
		if err != nil {
			return nil, err
		}
		if !fp.IsZero() && !identity.Equal(fp, seen) {
			return nil, identity.ErrPinMismatch
		}
		fp = seen
	}
	if fp.IsZero() {
		return nil, errors.New("magic: provider fingerprint unknown")
	}
	if opts.ExpectID != "" && !fp.MatchesID(opts.ExpectID) {
		return nil, identity.ErrPinMismatch
	}
	if opts.Code == nil {
		return nil, errors.New("magic: PairOptions.Code is required")
	}
	pin := identity.Pin{Fingerprint: fp}
	hc, err := HTTPClient(opts.URL, pin)
	if err != nil {
		return nil, err
	}
	c := &Client{BaseURL: strings.TrimRight(opts.URL, "/"), HTTP: hc}

	var started magic.PairingStarted
	err = c.Do(ctx, http.MethodPost, magic.APIPrefix+"/pairings", magic.PairingRequest{
		Client: opts.Client, Scopes: opts.Scopes, Ticket: opts.Ticket, Suite: pake.Suite,
	}, &started)
	if err != nil {
		return nil, err
	}
	cancel := func() {
		ctx, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		c.Do(ctx, http.MethodDelete, magic.APIPrefix+"/pairings/"+url.PathEscape(started.PairingID), nil, nil)
	}
	code, err := opts.Code(ctx, started)
	if err != nil {
		cancel()
		return nil, err
	}
	code = NormalizeCode(code)
	if code == "" {
		cancel()
		return nil, errors.New("magic: empty pairing code")
	}
	st, pA, err := pake.Start(pake.Client, pake.Params{PairingID: started.PairingID, Code: code, Binding: fp[:]})
	if err != nil {
		return nil, err
	}
	base := magic.APIPrefix + "/pairings/" + url.PathEscape(started.PairingID)
	var ex magic.PairingExchanged
	if err := c.Do(ctx, http.MethodPost, base+"/exchange", magic.PairingExchange{PA: b64(pA)}, &ex); err != nil {
		return nil, mapPairingErr(err)
	}
	pB, err1 := unb64(ex.PB)
	cB, err2 := unb64(ex.Confirm)
	if err1 != nil || err2 != nil {
		return nil, ErrPairingFailed
	}
	cA, err := st.Finish(pB)
	if err != nil {
		return nil, ErrPairingFailed
	}
	if err := st.Verify(cB); err != nil {
		// Wrong code or a man in the middle. Do not reveal our confirmation.
		cancel()
		return nil, ErrPairingFailed
	}
	var g magic.Grant
	if err := c.Do(ctx, http.MethodPost, base+"/confirm", magic.PairingConfirm{Confirm: b64(cA)}, &g); err != nil {
		return nil, mapPairingErr(err)
	}
	if g.Token == "" {
		return nil, errors.New("magic: provider returned no token")
	}
	name := g.Provider.Name
	return &Credential{
		ProviderID:  fp.ID(),
		Name:        name,
		Fingerprint: fp,
		Token:       g.Token,
		ClientID:    g.ClientID,
		Scopes:      g.Scopes,
		URLs:        []string{opts.URL},
		PairedAt:    time.Now().UTC().Truncate(time.Second),
	}, nil
}

func mapPairingErr(err error) error {
	var ae *APIError
	if errors.As(err, &ae) && ae.Code == magic.ErrCodePairingFailed {
		return ErrPairingFailed
	}
	return err
}

// NormalizeCode strips everything but digits from a user-entered code.
func NormalizeCode(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
