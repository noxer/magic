# Magic — intelligence on your local network

**Magic** is an open protocol, with a Go reference implementation, for
bringing AI capabilities ("intelligence") to the local computer and the local
network. Any app can **discover** the LLMs, embedding models, speech
recognizers and image generators around it, **pair** with them securely, and
**use** them through the OpenAI-compatible API it already speaks.

Think *AirPrint for AI*: the GPU box in the basement, the laptop running
Ollama and the NAS with an NPU announce themselves; your editor, notes app or
home automation finds them, asks for permission once, and gets to work.

```
$ magic discover
NAME          ID                          CAPABILITIES                   VIA         ACCESS  URL
Basement GPU  3yt7gi2mtkanxfe7rnclz736mq  chat,embeddings,transcription  local,mdns  -       https://192.168.1.20:8765

$ magic pair "Basement GPU"
Pairing with Basement GPU (id 3yt7gi2m…).
Enter the 8-digit code shown by the provider: 8091-1576
Paired with "Basement GPU" (id 3yt7gi2mtkanxfe7rnclz736mq). Granted: chat,embeddings,transcription

$ magic chat "Write a haiku about local inference"
```

## Why

Local inference servers (Ollama, llama.cpp, LM Studio, vLLM, LocalAI, …)
almost all speak an OpenAI-compatible API, but every app still has to be told
a URL, has to guess what each model can do, and usually goes without
authentication. Magic adds exactly what's missing, using existing standards:

| | Magic | Built on |
|---|---|---|
| **Discovery** | `_magic._tcp` DNS-SD service with capability subtypes; beacon files for apps on the same computer; `MAGIC_PROVIDER` for manual setup | mDNS / DNS-SD (RFC 6762/6763) |
| **Description** | `/.well-known/magic`: capabilities, models, features (tools, vision, …), and where data is processed (`device` / `network` / `cloud`) | RFC 8615 |
| **Identity** | Self-certifying provider IDs = hash of the TLS key; clients pin them, no CA needed | TLS 1.3 |
| **Authentication** | Pairing with an 8-digit code via a PAKE bound to the TLS key (MITM-resistant); operator-issued tokens; local token files | SPAKE2 (RFC 9382), Bearer (RFC 6750) |
| **Authorization** | Tokens scoped to capabilities (`chat`, `embeddings`, `transcription`, …) | |
| **Usage** | Each capability maps to its OpenAI-compatible endpoint | `/v1/chat/completions`, `/v1/embeddings`, … |

Read the **[specification](spec/README.md)**.

## Capabilities

`chat` · `completions` · `embeddings` · `rerank` · `transcription` · `speech` ·
`images` · `moderation`, plus vendor extensions (`x-acme-ocr`). Models add
**features** such as `streaming`, `tools`, `structured_output`, `vision`,
`audio_input` and `reasoning`. See [spec/06-capabilities.md](spec/06-capabilities.md).

## Reference implementation

```
go install github.com/noxer/magic/cmd/magicd@latest   # provider
go install github.com/noxer/magic/cmd/magic@latest    # client CLI
```

### Run a provider: `magicd`

`magicd` puts an existing inference server on the network. It auto-detects
Ollama, LM Studio, llama.cpp, vLLM and Jan on localhost, or takes `-backend`:

```
$ magicd -name "Basement GPU"                     # or: -backend http://127.0.0.1:8080
level=INFO msg="detected backend" kind=Ollama url=http://127.0.0.1:11434/v1
level=INFO msg="provider ready" id=3yt7gi2mtkanxfe7rnclz736mq capabilities="chat, embeddings"
level=INFO msg="serving LAN" addr=[::]:8765 tls=true
level=INFO msg="advertising via mDNS" service=_magic._tcp instance="Basement GPU"
level=INFO msg="serving local apps" url=http://127.0.0.1:41129
```

When a device asks to pair, `magicd` shows the request and its code:

```
  ┌ Pairing request from "magic CLI" on tims-laptop
  │ wants: chat, embeddings
  │ Code:  8091-1576   (valid until 11:21:16)
  └ Enter this code on the device to allow access. Ignore to deny.
```

What it does:

* Generates a persistent identity (`~/.config/magicd/identity`), serves TLS on
  `:8765` and advertises via mDNS, with one DNS-SD subtype per capability.
* Describes the models: capabilities and features come from Ollama's
  `/api/show` or from name heuristics, and can be overridden with
  `-models models.json`.
* Enforces capability scopes, strips client tokens before forwarding, and
  streams responses.
* Serves apps on the same computer over loopback HTTP (with DNS-rebinding
  protection), announced by a beacon file with a user-only token file.

Operator commands, run against the running daemon:

```
magicd pairings                       # pending requests and their codes
magicd deny <pairing-id>
magicd ticket -scopes chat            # one-time code + magic:// pairing URI (QR codes, headless setup)
magicd token -name homeassistant -scopes chat,transcription
magicd clients
magicd revoke <client-id>
```

Flags: `-listen`, `-local`, `-backend`, `-backend-key`, `-state`, `-no-mdns`,
`-public-models`, `-locality device|network|cloud`, `-models`.

### Use providers: `magic`

```
magic discover [-cap embeddings]     # this computer + local network
magic pair <name|id|url|magic://…>   # enter the code shown by the provider
magic list
magic models [provider]
magic chat -m llama3.2:3b "Hello"
magic embed "some text"
magic forget <provider>
```

**Existing tools** that only take an OpenAI base URL and key can use a paired
provider through a local bridge:

```
$ magic proxy -p "Basement GPU"
Serving Basement GPU as an OpenAI-compatible API. Point your tools at:

  OPENAI_BASE_URL=http://127.0.0.1:7777/v1
  OPENAI_API_KEY=mgc_…
```

### Go library

```go
// Find a provider that can embed, pair once, then use it.
ps, _ := discovery.Discover(ctx, 2*time.Second, discovery.Options{Capability: magic.Embeddings})

cred, err := client.Pair(ctx, client.PairOptions{
	URL:      ps[0].URLs[0],
	ExpectID: ps[0].ID,
	Client:   magic.ClientInfo{Name: "My App"},
	Scopes:   []magic.Capability{magic.Embeddings},
	Code: func(ctx context.Context, s magic.PairingStarted) (string, error) {
		return askUser("Enter the code shown on " + ps[0].Name)
	},
})
creds.Put(cred) // client.OpenCredentials(path)

c, _ := client.Connect(ctx, ps[0], creds)
vecs, _ := c.Embed(ctx, "nomic-embed-text", []string{"hello"})
// c.HTTP is a pinned *http.Client; use it with any OpenAI SDK as well.
```

| Package | Purpose |
|---|---|
| [`magic`](magic.go) | Wire types: descriptor, capabilities, features, beacons, pairing messages |
| [`identity`](identity) | Provider keys, IDs, fingerprints, certificate pinning |
| [`pake`](pake) | SPAKE2-P256-SHA256 as used by pairing |
| [`discovery`](discovery) | Combined discovery; [`mdns`](discovery/mdns) responder/browser; [`local`](discovery/local) beacons |
| [`provider`](provider) | Provider server: descriptor, pairing, tokens, scopes, admin API, gateway |
| [`client`](client) | Pairing, credential store, pinned connections, chat/embeddings helpers |

## Development

```
go test ./...
python3 spec/test-vectors/verify_spake2.py   # independent check of the pairing crypto
```

The tests include an end-to-end pairing through a TLS-intercepting
man-in-the-middle (which must fail even with the correct code), scope
enforcement, ticket redemption, DNS-rebinding checks, and a live mDNS
advertise/browse round trip.

## Status and limitations

Version 0.1 is a draft for discussion and experimentation.

* The names `Magic`, `_magic._tcp` and `magic://` are working names and not
  registered with IANA.
* The embedded mDNS responder has no probing or conflict resolution yet;
  choose unique provider names.
* No key rotation, per-client rate limits or model-level scopes yet.
* No browser profile yet (web apps can't pin certificates).

See [spec/01-overview.md § Open issues](spec/01-overview.md#17-open-issues).

## License

MIT, see [LICENSE](LICENSE).
