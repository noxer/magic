// Package backend connects magicd to an existing OpenAI-compatible inference
// server (Ollama, llama.cpp, LM Studio, vLLM, LocalAI, ...) and describes the
// models it serves in terms of Magic capabilities.
package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/noxer/magic"
)

// Backend is an OpenAI-compatible server.
type Backend struct {
	// Base is the API base URL including the version path, e.g.
	// "http://127.0.0.1:11434/v1".
	Base   *url.URL
	APIKey string
	// Overrides replace or add model descriptions by model ID.
	Overrides map[string]magic.Model
	Locality  magic.Locality

	http   *http.Client
	ollama bool
}

// Candidates are probed by Detect, in order.
var Candidates = []struct{ Name, URL string }{
	{"Ollama", "http://127.0.0.1:11434/v1"},
	{"LM Studio", "http://127.0.0.1:1234/v1"},
	{"llama.cpp", "http://127.0.0.1:8080/v1"},
	{"vLLM", "http://127.0.0.1:8000/v1"},
	{"Jan", "http://127.0.0.1:1337/v1"},
}

// New creates a backend for base, which may omit the "/v1" suffix.
func New(base, apiKey string) (*Backend, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("backend: unsupported URL %q", base)
	}
	if u.Path == "" {
		u.Path = "/v1"
	}
	b := &Backend{Base: u, APIKey: apiKey, http: &http.Client{Timeout: 10 * time.Second}, Locality: magic.LocalityDevice}
	b.ollama = b.probeOllama(context.Background())
	return b, nil
}

// Detect returns the first reachable well-known local backend.
func Detect(ctx context.Context) (*Backend, string, error) {
	for _, c := range Candidates {
		b, err := New(c.URL, "")
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
		_, err = b.listIDs(ctx)
		cancel()
		if err == nil {
			return b, c.Name, nil
		}
	}
	return nil, "", errors.New("backend: no local inference server found (tried Ollama, LM Studio, llama.cpp, vLLM, Jan); use --backend")
}

func (b *Backend) root() string {
	u := *b.Base
	u.Path = strings.TrimSuffix(u.Path, "/v1")
	return strings.TrimRight(u.String(), "/")
}

func (b *Backend) probeOllama(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, b.root()+"/api/version", nil)
	resp, err := b.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var v struct{ Version string }
	return resp.StatusCode == 200 && json.NewDecoder(resp.Body).Decode(&v) == nil && v.Version != ""
}

func (b *Backend) do(ctx context.Context, method, u string, in, out any) error {
	var body *bytes.Reader
	if in != nil {
		data, _ := json.Marshal(in)
		body = bytes.NewReader(data)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+b.APIKey)
	}
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("backend: %s %s: HTTP %d", method, u, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (b *Backend) listIDs(ctx context.Context) ([]string, error) {
	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := b.do(ctx, http.MethodGet, b.Base.String()+"/models", nil, &resp); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(resp.Data))
	for _, d := range resp.Data {
		ids = append(ids, d.ID)
	}
	sort.Strings(ids)
	return ids, nil
}

// Models lists the backend's models with their capabilities.
func (b *Backend) Models(ctx context.Context) ([]magic.Model, error) {
	ids, err := b.listIDs(ctx)
	if err != nil {
		return nil, err
	}
	var out []magic.Model
	seen := map[string]bool{}
	for _, id := range ids {
		m, ok := b.Overrides[id]
		if !ok {
			m = magic.Model{ID: id}
			if b.ollama {
				b.describeOllama(ctx, &m)
			}
			if len(m.Capabilities) == 0 {
				guess(&m)
			}
		}
		m.ID = id
		if m.Locality == "" {
			m.Locality = b.Locality
		}
		seen[id] = true
		out = append(out, m)
	}
	for id, m := range b.Overrides {
		if !seen[id] {
			m.ID = id
			if m.Locality == "" {
				m.Locality = b.Locality
			}
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// describeOllama fills in capabilities from Ollama's /api/show.
func (b *Backend) describeOllama(ctx context.Context, m *magic.Model) {
	var show struct {
		Capabilities []string       `json:"capabilities"`
		ModelInfo    map[string]any `json:"model_info"`
		Details      struct {
			Family        string `json:"family"`
			ParameterSize string `json:"parameter_size"`
		} `json:"details"`
	}
	if err := b.do(ctx, http.MethodPost, b.root()+"/api/show", map[string]string{"model": m.ID}, &show); err != nil {
		return
	}
	m.Family, m.Parameters = show.Details.Family, show.Details.ParameterSize
	for k, v := range show.ModelInfo {
		if f, ok := v.(float64); ok {
			switch {
			case strings.HasSuffix(k, ".context_length"):
				m.ContextLength = int(f)
			case strings.HasSuffix(k, ".embedding_length"):
				m.Dimensions = int(f)
			}
		}
	}
	for _, c := range show.Capabilities {
		switch c {
		case "completion":
			m.Capabilities = append(m.Capabilities, magic.Chat, magic.Completions)
			m.Features = append(m.Features, magic.FeatureStreaming, magic.FeatureStructuredOutput)
		case "embedding":
			m.Capabilities = append(m.Capabilities, magic.Embeddings)
		case "vision":
			m.Features = append(m.Features, magic.FeatureVision)
		case "tools":
			m.Features = append(m.Features, magic.FeatureTools)
		case "thinking":
			m.Features = append(m.Features, magic.FeatureReasoning)
		}
	}
	if !m.Has(magic.Embeddings) {
		m.Dimensions = 0
	}
}

// guess infers capabilities from a model name when the backend cannot say.
func guess(m *magic.Model) {
	n := strings.ToLower(m.ID)
	switch {
	case strings.Contains(n, "rerank"):
		m.Capabilities = []magic.Capability{magic.Rerank}
	case strings.Contains(n, "embed") || strings.Contains(n, "bge-") || strings.Contains(n, "e5-") || strings.Contains(n, "minilm"):
		m.Capabilities = []magic.Capability{magic.Embeddings}
	case strings.Contains(n, "whisper") || strings.Contains(n, "transcribe"):
		m.Capabilities = []magic.Capability{magic.Transcription}
	case strings.Contains(n, "tts") || strings.Contains(n, "kokoro") || strings.Contains(n, "piper"):
		m.Capabilities = []magic.Capability{magic.Speech}
	case strings.Contains(n, "stable-diffusion") || strings.Contains(n, "sdxl") || strings.Contains(n, "flux"):
		m.Capabilities = []magic.Capability{magic.Images}
	default:
		m.Capabilities = []magic.Capability{magic.Chat}
		m.Features = []magic.Feature{magic.FeatureStreaming}
		if strings.Contains(n, "vl") || strings.Contains(n, "vision") || strings.Contains(n, "llava") || strings.Contains(n, "gemma3") {
			m.Features = append(m.Features, magic.FeatureVision)
		}
	}
}

// Handler returns a reverse proxy to the backend. Incoming paths are relative
// to the API base ("/chat/completions").
func (b *Backend) Handler() http.Handler {
	base := *b.Base
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = base.Scheme
			pr.Out.URL.Host = base.Host
			pr.Out.URL.Path = strings.TrimRight(base.Path, "/") + pr.In.URL.Path
			pr.Out.URL.RawPath = ""
			pr.Out.Host = base.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")
			if b.APIKey != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+b.APIKey)
			}
		},
		FlushInterval: -1, // stream server-sent events immediately
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "backend_unavailable", "message": err.Error()}})
		},
	}
}
