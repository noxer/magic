# 1. Overview

## 1.1 Problem

Local inference is everywhere: Ollama, llama.cpp, LM Studio, vLLM, LocalAI,
NPUs in laptops and phones, home servers with GPUs. Almost all of these speak
an OpenAI-compatible HTTP API, but every app that wants to use them must:

* be told a URL (`http://localhost:11434`? `:1234`? `:8080`? which machine?),
* guess which models can do what (is this model good for embeddings? does it
  take images?), and
* do without authentication, or copy API keys around by hand. Many servers
  ship with no authentication at all and are exposed to the whole network, or
  to any web page via DNS rebinding.

Magic standardizes the missing pieces and nothing else:

| Concern | Magic provides | Builds on |
|---|---|---|
| Finding providers | DNS-SD service type, TXT keys, capability subtypes, local beacon files | RFC 6762, RFC 6763 |
| Describing them | A JSON descriptor at a well-known URI | RFC 8615 |
| Trusting them | Self-certifying provider IDs, key pinning | TLS 1.3 |
| Getting access | Pairing with a short code, scoped bearer tokens | SPAKE2 (RFC 9382), RFC 6750 |
| Using them | Capability → endpoint registry | OpenAI-compatible HTTP API |

## 1.2 Goals

* **Zero configuration.** An app finds intelligence near it without asking the
  user for URLs.
* **Secure by default, also on hostile networks.** Coffee-shop Wi-Fi and
  shared offices included: no plain-text tokens on the network, no trust in
  discovery data, protection against man-in-the-middle during pairing.
* **Consent.** A provider's operator decides who may use which capability.
* **Truthful about privacy.** Each model declares whether data stays on the
  device, in the local network, or goes to the cloud.
* **Adoptable today.** Existing servers can be wrapped by a gateway (the
  reference `magicd`), and existing OpenAI client libraries work unchanged
  once they have a base URL and a token.

Non-goals: defining a new inference API; replacing MCP (which connects models
to tools; Magic connects apps to models); internet-scale federation.

## 1.3 Roles

* **Provider**: offers one or more capabilities. It may run the models itself,
  front another server, or forward to a hosted API.
* **Client**: an app, library or device that uses capabilities.
* **Operator**: the person who controls a provider and approves clients. On
  a laptop this is its user; on a home server, its administrator.
* **Bridge** (optional): a process that is a client of remote providers and
  re-exposes them locally, for example `magic proxy` in the reference
  implementation, which lets tools without Magic support use a paired provider.

```
   ┌──────────── local network ───────────────────────────┐
   │                                                      │
   │  ┌──────────────┐   mDNS: _magic._tcp   ┌──────────┐ │
   │  │  Provider    │◀────── browse ────────│  Client  │ │
   │  │  (GPU box)   │                       │  (laptop)│ │
   │  │              │◀── TLS (pinned) ──────│          │ │
   │  │ /.well-known/│     pairing, then     │          │ │
   │  │   magic      │     /v1/... + token   │          │ │
   │  └──────────────┘                       └──────────┘ │
   │                                                      │
   │  ┌──────────── one computer ─────────────────────┐   │
   │  │  Provider ── beacon file ──▶ Client           │   │
   │  │      ▲   http://127.0.0.1:port + token file   │   │
   │  │      └────────────────────────────────────────│   │
   │  └───────────────────────────────────────────────┘   │
   └──────────────────────────────────────────────────────┘
```

## 1.4 Flow

1. **Discover.** The client browses `_magic._tcp` (optionally a capability
   subtype such as `_embeddings._sub._magic._tcp`) and scans local beacon
   directories. Each result names a provider ID, addresses and capability hints.
2. **Describe.** The client fetches `/.well-known/magic` to learn the
   capabilities, models, features and authentication methods.
3. **Authorize.** If it has no token, the client pairs. The provider shows its
   operator an 8-digit code; the user enters it on the client; a
   password-authenticated key exchange bound to the provider's TLS key proves
   that both sides saw the same code and the same key. The client receives a
   token scoped to the requested capabilities.
4. **Use.** The client calls the OpenAI-compatible endpoints with
   `Authorization: Bearer <token>` over a pinned connection.

## 1.5 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY" and "OPTIONAL" are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in
all capitals.

* JSON documents are UTF-8 (RFC 8259). Receivers MUST ignore unknown members.
* `base64url` means unpadded base64url (RFC 4648 § 5).
* Times are RFC 3339 strings in UTC.
* `lp(x)` denotes the 8-byte little-endian length of `x` followed by `x`.

## 1.6 Versioning

The protocol version is `major.minor` and appears as `magic` in the descriptor
and `v` in TXT records. Minor versions only add optional features. Paths carry
the major version (`/magic/v1/...`).

## 1.7 Open issues

* **Naming and registration.** "Magic" and `_magic._tcp` are working names; the
  service name is not yet registered with IANA, nor is the `magic` well-known
  URI suffix or the `magic` URI scheme.
* **Key rotation.** A provider ID is bound to one key; a signed rotation
  statement that lets clients follow a new key without re-pairing is planned.
* **Client-shown codes.** Devices without input (speakers, sensors) could show
  a code and let the operator type it into the provider; the PAKE supports
  this, the message flow does not yet.
* **Streaming realtime APIs** (speech-to-speech over WebSocket) and an
  `agents`/`tools` capability family.
* **Model-level authorization** (scopes narrower than a capability) and quotas.
* **Browsers.** Web apps can't pin certificates or read beacon files; a
  browser-facing profile (for example via a local bridge with an origin
  allow-list) is to be defined.
