# Magic Protocol Specification — v0.1 (draft)

Magic is an open protocol that lets any app on any device **find, securely
connect to, and use the AI capabilities ("intelligence") available on the
local computer and the local network**: a GPU box in the basement, a NAS with
an NPU, a laptop running Ollama, or a gateway to a hosted model.

It does for intelligence what IPP Everywhere / AirPrint did for printers:
zero-configuration discovery, a self-describing capability model, and a
standard way to get authorized, on top of the inference API everyone already
speaks.

| Part | Document |
|---|---|
| 1 | [Overview, roles and conventions](01-overview.md) |
| 2 | [Discovery](02-discovery.md) — DNS-SD/mDNS, local beacons, manual configuration |
| 3 | [Provider descriptor](03-descriptor.md) — `/.well-known/magic` |
| 4 | [Transport and identity](04-transport-and-identity.md) — TLS, provider IDs, pinning |
| 5 | [Authentication and authorization](05-authentication.md) — pairing, tokens, scopes |
| 6 | [Capabilities](06-capabilities.md) — registry, features, wire APIs |
| 7 | [Security and privacy considerations](07-security-privacy.md) |

Machine-readable material:

* [`schema/descriptor.schema.json`](schema/descriptor.schema.json) and
  [`schema/beacon.schema.json`](schema/beacon.schema.json) (JSON Schema 2020-12)
* Test vectors: the official RFC 9382 vectors
  ([`rfc9382-spake2-p256.json`](test-vectors/rfc9382-spake2-p256.json)) and
  Magic pairing vectors ([`pairing-spake2.json`](test-vectors/pairing-spake2.json)),
  with an independent standard-library checker,
  [`verify_spake2.py`](test-vectors/verify_spake2.py)

## Status

This is a **working draft**. Wire formats may change before 1.0. Notable open
items are listed in [01-overview.md § Open issues](01-overview.md#17-open-issues).

## Conformance at a glance

A conforming **provider**:

1. serves the descriptor at `GET /.well-known/magic`;
2. on the network, listens with TLS 1.3 using a long-lived key whose hash is its
   provider ID, and advertises `_magic._tcp` via DNS-SD;
3. on the same computer, may also listen on loopback with plain HTTP and
   publishes a beacon file;
4. implements pairing (`SPAKE2-P256-SHA256`) and bearer tokens with capability
   scopes;
5. offers each capability through the OpenAI-compatible endpoint listed in
   part 6, and enforces scopes there.

A conforming **client**:

1. discovers providers through at least one of the mechanisms in part 2;
2. pins the provider's key to its provider ID and never sends a token to a
   connection that fails the pin;
3. pairs using the code shown by the provider, or uses an operator-issued token;
4. treats everything learned from discovery as an unauthenticated hint.
