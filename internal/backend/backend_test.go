package backend

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noxer/magic"
)

func TestOllamaModels(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			io.WriteString(w, `{"version":"0.12.0"}`)
		case "/v1/models":
			io.WriteString(w, `{"data":[{"id":"qwen2.5vl:7b"},{"id":"nomic-embed-text:latest"}]}`)
		case "/api/show":
			b, _ := io.ReadAll(r.Body)
			if string(b) == `{"model":"qwen2.5vl:7b"}` {
				io.WriteString(w, `{"capabilities":["completion","vision","tools"],"model_info":{"qwen2.5vl.context_length":128000},"details":{"family":"qwen25vl","parameter_size":"8.3B"}}`)
			} else {
				io.WriteString(w, `{"capabilities":["embedding"],"model_info":{"nomic-bert.embedding_length":768}}`)
			}
		}
	}))
	defer ts.Close()
	b, err := New(ts.URL, "")
	if err != nil || !b.ollama {
		t.Fatalf("New: %v ollama=%v", err, b.ollama)
	}
	ms, err := b.Models(context.Background())
	if err != nil || len(ms) != 2 {
		t.Fatalf("Models: %v %v", ms, err)
	}
	embed, chat := ms[0], ms[1]
	if !embed.Has(magic.Embeddings) || embed.Dimensions != 768 {
		t.Errorf("embedding model: %+v", embed)
	}
	if !chat.Has(magic.Chat) || !chat.Supports(magic.FeatureVision) || !chat.Supports(magic.FeatureTools) || chat.ContextLength != 128000 {
		t.Errorf("chat model: %+v", chat)
	}
}

func TestGuess(t *testing.T) {
	for id, want := range map[string]magic.Capability{
		"bge-reranker-v2-m3": magic.Rerank, "text-embedding-3-small": magic.Embeddings,
		"whisper-1": magic.Transcription, "kokoro-82m": magic.Speech, "llama-3.1-8b": magic.Chat,
	} {
		m := magic.Model{ID: id}
		guess(&m)
		if !m.Has(want) {
			t.Errorf("%s: got %v, want %s", id, m.Capabilities, want)
		}
	}
}
