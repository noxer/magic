# 3. Provider descriptor

Every provider MUST serve its descriptor at **`GET /.well-known/magic`** on
each of its listeners, as `application/json`. The descriptor is available
without authentication. A provider MAY omit `models` and the `models` lists of
`capabilities` from unauthenticated responses; it MUST include them for
requests carrying a valid token.

## 3.1 Example

```json
{
  "magic": "0.1",
  "provider": {
    "id": "3yt7gi2mtkanxfe7rnclz736mq",
    "name": "Basement GPU",
    "fingerprint": "sha256:3ksDF2vL…",
    "software": { "name": "magicd", "version": "0.1.0", "url": "https://github.com/noxer/magic" },
    "locality": "device"
  },
  "auth": {
    "methods": ["pairing", "token"],
    "pairing": { "endpoint": "/magic/v1/pairings", "suites": ["SPAKE2-P256-SHA256"], "code_digits": 8 }
  },
  "api": { "openai": "/v1" },
  "capabilities": {
    "chat":       { "models": ["llama3.2:3b", "qwen2.5vl:7b"] },
    "embeddings": { "models": ["nomic-embed-text"] }
  },
  "models": [
    {
      "id": "qwen2.5vl:7b",
      "capabilities": ["chat", "completions"],
      "features": ["streaming", "structured_output", "vision", "tools"],
      "context_length": 128000,
      "family": "qwen25vl",
      "parameters": "8.3B",
      "locality": "device"
    },
    {
      "id": "nomic-embed-text",
      "capabilities": ["embeddings"],
      "dimensions": 768,
      "locality": "device"
    }
  ]
}
```

## 3.2 Members

### Top level

| Member | Type | Required | Meaning |
|---|---|---|---|
| `magic` | string | MUST | Protocol version |
| `provider` | object | MUST | Identity, below |
| `auth` | object | MUST | Authentication methods, below |
| `api` | object | MUST | API base paths, below |
| `capabilities` | object | MUST | Map from capability to summary |
| `models` | array | see above | Model descriptions |

### `provider`

| Member | Required | Meaning |
|---|---|---|
| `id` | MUST | Provider ID. A client MUST check it equals the ID derived from the TLS key of the connection and discard the descriptor otherwise. |
| `name` | MUST | Display name |
| `fingerprint` | SHOULD | `sha256:<base64url>` of the TLS key (part 4) |
| `software` | MAY | `name`, `version`, `url` of the implementation |
| `locality` | SHOULD | Default locality of the provider's models (§ 3.3) |

### `auth`

`methods` lists the supported methods: `pairing`, `token`, `local` (part 5).
If `pairing` is listed, `pairing` MUST describe the pairing endpoint, the
supported PAKE suites and the number of code digits.

### `api`

`openai`: base path of the OpenAI-compatible API (normally `/v1`). Capability
endpoints in part 6 are relative to it. Future versions may add other API
families.

### `capabilities`

Keys are capability identifiers (part 6). Each value MAY list the IDs of the
models offering the capability. A capability present here is offered *now*;
providers SHOULD remove capabilities whose models are unavailable.

### `models[]`

| Member | Required | Meaning |
|---|---|---|
| `id` | MUST | The model name used in API requests |
| `capabilities` | MUST | Capabilities this model offers |
| `name` | MAY | Display name |
| `features` | MAY | Optional behaviours (part 6.3) |
| `context_length` | MAY | Maximum context in tokens |
| `dimensions` | MAY | Embedding size, for `embeddings` models |
| `locality` | SHOULD | Where this model processes data (§ 3.3) |
| `family`, `parameters` | MAY | Informational |

## 3.3 Locality

Locality tells clients where prompts and other inputs go, so they can keep
sensitive data close:

| Value | Meaning |
|---|---|
| `device` | Processed on the machine the provider runs on |
| `network` | Forwarded to another machine within the local network |
| `cloud` | Leaves the local network (e.g. a hosted API) |

A provider MUST NOT declare a locality closer than the truth. A model without
`locality` inherits `provider.locality`; if both are absent, clients MUST
assume `cloud`.

## 3.4 Caching

Providers SHOULD send `Cache-Control: no-store` for authenticated descriptors.
Clients SHOULD re-fetch the descriptor when they reconnect.
