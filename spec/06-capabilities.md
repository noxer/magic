# 6. Capabilities

A **capability** is a kind of intelligence a client can ask for, tied to one
HTTP endpoint. Capabilities are also the unit of authorization: token scopes
are lists of capabilities.

## 6.1 Registry

Endpoints are relative to the descriptor's `api.openai` base (normally `/v1`)
and follow the request and response formats of the OpenAI-compatible API, as
implemented by Ollama, llama.cpp, vLLM, LM Studio and others. Providers MUST
implement at least the core fields listed, and SHOULD accept and ignore
fields they don't support rather than fail.

| Capability | Endpoint(s) | Core request fields | Typical models |
|---|---|---|---|
| `chat` | `POST /chat/completions` | `model`, `messages[]` (`role`, `content`), `stream`, `max_tokens`, `temperature` | Llama, Qwen, Gemma, Mistral |
| `completions` | `POST /completions` | `model`, `prompt`, `max_tokens`, `stream` | base models, code infill |
| `embeddings` | `POST /embeddings` | `model`, `input` (string or array) | nomic-embed, bge, e5 |
| `rerank` | `POST /rerank` | `model`, `query`, `documents[]`, `top_n` | bge-reranker, jina-reranker |
| `transcription` | `POST /audio/transcriptions`, `POST /audio/translations` | multipart: `file`, `model`, `language`, `response_format` | Whisper |
| `speech` | `POST /audio/speech` | `model`, `input`, `voice`, `response_format` | Kokoro, Piper |
| `images` | `POST /images/generations` (also `/images/edits`, `/images/variations`) | `model`, `prompt`, `size`, `n` | Stable Diffusion, FLUX |
| `moderation` | `POST /moderations` | `model`, `input` | Llama Guard |

`rerank` follows the de-facto format shared by llama.cpp, vLLM, Jina and
Cohere: the response holds `results[]` with `index` and `relevance_score`.

`GET /models` (OpenAI model list) is available to every valid token
regardless of scopes. Requests to other endpoints under the API base that
aren't mapped to a capability SHOULD be refused (`403`) unless the token has
the admin right.

A provider MUST check, before forwarding or processing a request, that the
token's scopes include the capability of the endpoint. Providers MAY
additionally refuse models that don't offer the capability.

## 6.2 Vendor capabilities

Capabilities not in the registry use the form `x-<vendor>-<name>`, lowercase
letters, digits and hyphens, at most 40 characters (e.g. `x-acme-ocr`). They
MAY be listed in the descriptor and in scopes; their endpoints are defined by
the vendor. They aren't published as DNS-SD subtypes.

New registered capabilities are added in minor versions. Candidates include
`realtime` (bidirectional audio sessions), `video`, `responses` (the OpenAI
Responses API), and `agents`.

## 6.3 Features

Features describe optional behaviour of a model within its capabilities.
Clients use them to pick a suitable model; providers MUST NOT list a feature
the model doesn't support.

| Feature | Applies to | Meaning |
|---|---|---|
| `streaming` | chat, completions | `stream: true` yields server-sent events |
| `tools` | chat | Function or tool calling (`tools`, `tool_calls`) |
| `structured_output` | chat, completions | `response_format` with JSON schema |
| `vision` | chat | Image parts in `messages[].content` |
| `audio_input` | chat | Audio parts in `messages[].content` |
| `reasoning` | chat | Model produces separate reasoning/thinking output |

Unknown features MUST be ignored. Vendor features use the `x-<vendor>-` prefix.

## 6.4 Choosing a model

A client looking for a capability:

1. browses the capability subtype (part 2.1) or filters discovered providers
   by `caps`;
2. reads the descriptor and selects models with the capability, the features
   it needs, and an acceptable `locality`;
3. passes the model ID in its requests.

Clients SHOULD let users restrict sensitive work to `device` or `network`
locality, and SHOULD tell users when a request will be processed in the
`cloud`.
