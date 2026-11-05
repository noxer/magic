// Package magic defines the wire types of the Magic protocol: a standard way
// for apps to discover, authenticate to and use AI capabilities ("intelligence")
// offered by providers on the local computer and the local network.
//
// See the specification in the spec/ directory. Sub-packages implement the
// individual building blocks:
//
//   - identity: provider keys, provider IDs and certificate pinning
//   - pake: the SPAKE2 exchange behind pairing codes
//   - pairing: the pairing protocol (client and provider side)
//   - discovery: DNS-SD/mDNS and local beacon discovery
//   - provider: an HTTP server framework for providers
//   - client: a client library that discovers, pairs and calls providers
package magic

// Version is the protocol version implemented by this module.
const Version = "0.1"

// Well-known names.
const (
	// ServiceType is the DNS-SD service type under which providers advertise.
	ServiceType = "_magic._tcp"
	// WellKnownPath is the path of the provider descriptor (RFC 8615).
	WellKnownPath = "/.well-known/magic"
	// APIPrefix is the path prefix of the Magic control API.
	APIPrefix = "/magic/v1"
	// TokenPrefix starts every access token issued by a conforming provider.
	TokenPrefix = "mgc_"
)

// Capability identifies a kind of intelligence a provider offers. Registered
// capabilities are short lowercase tokens; vendor capabilities use the form
// "x-<vendor>-<name>".
type Capability string

// Registered capabilities. See spec/06-capabilities.md.
const (
	Chat          Capability = "chat"          // conversational text generation
	Completions   Capability = "completions"   // raw text completion
	Embeddings    Capability = "embeddings"    // vector embeddings
	Rerank        Capability = "rerank"        // relevance ranking
	Transcription Capability = "transcription" // speech to text
	Speech        Capability = "speech"        // text to speech
	Images        Capability = "images"        // image generation
	Moderation    Capability = "moderation"    // content classification
)

// Registered lists the registered capabilities in canonical order.
var Registered = []Capability{Chat, Completions, Embeddings, Rerank, Transcription, Speech, Images, Moderation}

// Endpoint returns the path, relative to the OpenAI-compatible API base,
// through which the capability is used, or "" for unknown capabilities.
func (c Capability) Endpoint() string {
	switch c {
	case Chat:
		return "/chat/completions"
	case Completions:
		return "/completions"
	case Embeddings:
		return "/embeddings"
	case Rerank:
		return "/rerank"
	case Transcription:
		return "/audio/transcriptions"
	case Speech:
		return "/audio/speech"
	case Images:
		return "/images/generations"
	case Moderation:
		return "/moderations"
	}
	return ""
}

// CapabilityForPath maps an API path (relative to the API base, e.g.
// "/chat/completions") to the capability required to call it. The second
// result is false if the path is not tied to a single capability.
func CapabilityForPath(path string) (Capability, bool) {
	switch path {
	case "/chat/completions":
		return Chat, true
	case "/completions":
		return Completions, true
	case "/embeddings":
		return Embeddings, true
	case "/rerank":
		return Rerank, true
	case "/audio/transcriptions", "/audio/translations":
		return Transcription, true
	case "/audio/speech":
		return Speech, true
	case "/images/generations", "/images/edits", "/images/variations":
		return Images, true
	case "/moderations":
		return Moderation, true
	}
	return "", false
}

// Valid reports whether c is a registered or well-formed vendor capability.
func (c Capability) Valid() bool {
	for _, r := range Registered {
		if c == r {
			return true
		}
	}
	s := string(c)
	if len(s) < 5 || len(s) > 40 || s[:2] != "x-" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// Feature is an optional behaviour of a model within a capability.
type Feature string

// Registered features.
const (
	FeatureStreaming        Feature = "streaming"         // server-sent event streaming
	FeatureTools            Feature = "tools"             // function / tool calling
	FeatureStructuredOutput Feature = "structured_output" // JSON schema constrained output
	FeatureVision           Feature = "vision"            // image inputs
	FeatureAudioInput       Feature = "audio_input"       // audio inputs to chat
	FeatureReasoning        Feature = "reasoning"         // exposes reasoning / thinking
)

// Locality says where a model processes data. Clients use it to keep
// sensitive data on the device or in the local network.
type Locality string

const (
	// LocalityDevice: data is processed on the provider's machine.
	LocalityDevice Locality = "device"
	// LocalityNetwork: data stays within the local network, but the provider
	// forwards it to another machine on that network.
	LocalityNetwork Locality = "network"
	// LocalityCloud: data leaves the local network (e.g. a hosted API).
	LocalityCloud Locality = "cloud"
)

// Descriptor is the document served at WellKnownPath.
type Descriptor struct {
	Magic        string                        `json:"magic"`
	Provider     ProviderInfo                  `json:"provider"`
	Auth         AuthInfo                      `json:"auth"`
	API          APIInfo                       `json:"api"`
	Capabilities map[Capability]CapabilityInfo `json:"capabilities"`
	Models       []Model                       `json:"models,omitempty"`
}

// ProviderInfo identifies a provider.
type ProviderInfo struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Fingerprint string        `json:"fingerprint,omitempty"`
	Software    *SoftwareInfo `json:"software,omitempty"`
	Locality    Locality      `json:"locality,omitempty"`
}

// SoftwareInfo names the implementation.
type SoftwareInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	URL     string `json:"url,omitempty"`
}

// AuthInfo describes how clients obtain access.
type AuthInfo struct {
	Methods []string     `json:"methods"`
	Pairing *PairingInfo `json:"pairing,omitempty"`
}

// Authentication methods.
const (
	AuthPairing = "pairing" // SPAKE2 pairing with a short code
	AuthToken   = "token"   // operator-issued bearer tokens
	AuthLocal   = "local"   // token file readable by local users
	AuthNone    = "none"    // no authentication (loopback only)
)

// PairingInfo describes the pairing endpoint.
type PairingInfo struct {
	Endpoint   string   `json:"endpoint"`
	Suites     []string `json:"suites"`
	CodeDigits int      `json:"code_digits"`
}

// APIInfo locates the APIs a provider speaks.
type APIInfo struct {
	// OpenAI is the base path of the OpenAI-compatible API, e.g. "/v1".
	OpenAI string `json:"openai"`
}

// CapabilityInfo summarizes one capability.
type CapabilityInfo struct {
	Models []string `json:"models,omitempty"`
}

// Model describes one model offered by a provider.
type Model struct {
	ID            string       `json:"id"`
	Name          string       `json:"name,omitempty"`
	Capabilities  []Capability `json:"capabilities"`
	Features      []Feature    `json:"features,omitempty"`
	ContextLength int          `json:"context_length,omitempty"`
	Dimensions    int          `json:"dimensions,omitempty"`
	Locality      Locality     `json:"locality,omitempty"`
	Family        string       `json:"family,omitempty"`
	Parameters    string       `json:"parameters,omitempty"`
}

// Has reports whether the model offers capability c.
func (m Model) Has(c Capability) bool {
	for _, x := range m.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}

// Supports reports whether the model has feature f.
func (m Model) Supports(f Feature) bool {
	for _, x := range m.Features {
		if x == f {
			return true
		}
	}
	return false
}

// Beacon is the file a provider places in a local discovery directory.
type Beacon struct {
	Magic        string       `json:"magic"`
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	URL          string       `json:"url"`
	Fingerprint  string       `json:"fingerprint,omitempty"`
	TokenFile    string       `json:"token_file,omitempty"`
	PID          int          `json:"pid,omitempty"`
	Capabilities []Capability `json:"capabilities,omitempty"`
}

// Error is the body of every error response of the Magic control API.
type Error struct {
	Err struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Error codes.
const (
	ErrCodeUnauthorized  = "unauthorized"
	ErrCodeForbidden     = "insufficient_scope"
	ErrCodeNotFound      = "not_found"
	ErrCodeBadRequest    = "bad_request"
	ErrCodeExpired       = "expired"
	ErrCodePairingFailed = "pairing_failed"
	ErrCodeRateLimited   = "rate_limited"
	ErrCodeInternal      = "internal_error"
)

// PairingRequest starts a pairing (POST {APIPrefix}/pairings).
type PairingRequest struct {
	Client ClientInfo   `json:"client"`
	Scopes []Capability `json:"scopes"`
	Ticket string       `json:"ticket,omitempty"`
	Suite  string       `json:"suite"`
}

// ClientInfo describes a client to the provider's operator.
type ClientInfo struct {
	Name     string `json:"name"`
	Software string `json:"software,omitempty"`
	Device   string `json:"device,omitempty"`
}

// PairingStarted is the response to a PairingRequest.
type PairingStarted struct {
	PairingID  string `json:"pairing_id"`
	ExpiresAt  string `json:"expires_at"`
	CodeDigits int    `json:"code_digits"`
	Suite      string `json:"suite"`
}

// PairingExchange carries the client's SPAKE2 share.
type PairingExchange struct {
	PA string `json:"pA"`
}

// PairingExchanged carries the provider's share and confirmation.
type PairingExchanged struct {
	PB      string `json:"pB"`
	Confirm string `json:"confirm"`
}

// PairingConfirm carries the client's confirmation.
type PairingConfirm struct {
	Confirm string `json:"confirm"`
}

// Grant is issued when pairing completes, and describes a token.
type Grant struct {
	Token     string       `json:"token,omitempty"`
	TokenType string       `json:"token_type,omitempty"`
	ClientID  string       `json:"client_id"`
	Scopes    []Capability `json:"scopes"`
	Provider  ProviderInfo `json:"provider"`
}

// Session is returned by GET {APIPrefix}/session.
type Session struct {
	ClientID string       `json:"client_id"`
	Name     string       `json:"name"`
	Scopes   []Capability `json:"scopes"`
	Admin    bool         `json:"admin,omitempty"`
	Provider ProviderInfo `json:"provider"`
}
