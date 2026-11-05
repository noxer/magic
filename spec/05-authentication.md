# 5. Authentication and authorization

## 5.1 Model

Every request to a capability endpoint and to the control API (except the
descriptor and pairing endpoints) MUST carry a bearer token (RFC 6750):

```
Authorization: Bearer mgc_6hJk…
```

A token is an opaque string starting with `mgc_`, with at least 256 bits of
entropy. Providers SHOULD store only a hash of each token. Each token belongs
to a **client record** with:

* a client ID (opaque, e.g. `cl_…`),
* the client's self-description (`name`, `software`, `device`), which is for
  display only,
* **scopes**: the capabilities the client may use (part 6), and
* optionally the **admin** right, which grants all capabilities and the admin
  API (§ 5.6).

A provider MUST reject requests without a valid token with
`401 Unauthorized` and `WWW-Authenticate: Bearer realm="magic"`, and requests
for a capability outside the token's scopes with `403 Forbidden`.

Clients obtain tokens in one of three ways:

| Method | `auth.methods` | Use |
|---|---|---|
| Pairing | `pairing` | Interactive: user enters a code shown by the provider |
| Issued token | `token` | Headless clients, scripts, services |
| Local token file | `local` | Apps on the provider's own computer |

## 5.2 Pairing

Pairing gives a client a token after the user proves, by typing a short code,
that they have the operator's permission. In the same step it authenticates
the provider's TLS key to the client. It uses a password-authenticated key
exchange (PAKE), so a network attacker:

* cannot learn the code by watching or by relaying,
* gets exactly **one guess** per pairing session, which is visible to the
  operator, and
* cannot sit in the middle of the TLS connection, because both sides bind the
  fingerprint *they* see into the exchange.

### 5.2.1 Messages

All pairing requests go over the pinned connection: over TLS, the client
first completes a handshake, computes the fingerprint `F` and pins it for the
rest of the exchange; over loopback HTTP, `F` comes from the beacon.

**1. Start**: `POST /magic/v1/pairings`

```json
{
  "client": { "name": "Notes App", "software": "notes/2.1", "device": "tims-laptop" },
  "scopes": ["chat", "embeddings"],
  "suite": "SPAKE2-P256-SHA256",
  "ticket": "tk_…"
}
```

`scopes` empty or absent means "all capabilities currently offered".
`ticket` is optional (§ 5.2.4). Response `201 Created`:

```json
{ "pairing_id": "pr_VE6zhd1mn0KC", "expires_at": "2026-11-05T11:21:16Z", "code_digits": 8, "suite": "SPAKE2-P256-SHA256" }
```

Without a ticket, the provider generates a uniformly random code of
`code_digits` decimal digits (at least 6; 8 RECOMMENDED) and shows it **to its
operator only**: in a notification, its UI, its console, or its admin API,
together with the client's self-description and the requested scopes. Showing
the code to the user *is* the approval. Ignoring the request denies it.

**2. Exchange**: `POST /magic/v1/pairings/{pairing_id}/exchange`

The user types the code into the client. The client computes its SPAKE2
share `pA` (§ 5.2.2) and sends `{ "pA": "<base64url>" }`. The provider replies
`{ "pB": "<base64url>", "confirm": "<base64url cB>" }`.

**3. Confirm**: `POST /magic/v1/pairings/{pairing_id}/confirm`

The client verifies `cB`. **If verification fails, the code was wrong or the
connection is intercepted: the client MUST abort without sending `cA`**, and
SHOULD cancel the session (`DELETE /magic/v1/pairings/{pairing_id}`).
Otherwise it sends `{ "confirm": "<base64url cA>" }`. If `cA` verifies, the
provider creates the client record and replies `200 OK`:

```json
{
  "token": "mgc_…",
  "token_type": "Bearer",
  "client_id": "cl_bh9iH-z8n4b0",
  "scopes": ["chat"],
  "provider": { "id": "3yt7gi2mtkanxfe7rnclz736mq", "name": "Basement GPU", "fingerprint": "sha256:…" }
}
```

The granted scopes may be narrower than the request. The client stores the
token with the provider ID and fingerprint `F`, and pins `F` from then on.

A session allows **exactly one** exchange. Any failed `exchange` or `confirm`
MUST destroy the session. Sessions expire after at most 10 minutes (5
RECOMMENDED). Providers MUST rate-limit session creation (the reference
allows 10 per minute and 16 pending) and SHOULD show failed attempts to the
operator.

### 5.2.2 Cryptography: `SPAKE2-P256-SHA256`

SPAKE2 (RFC 9382) over NIST P-256 with SHA-256, HKDF-SHA256 and HMAC-SHA256.
The client is party A, the provider party B. The group constants are those of
RFC 9382 § 6 for P-256:

```
M = 02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f
N = 03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
```

The password scalar, transcript and key schedule are specific to Magic and
defined here in full. `n` is the group order, `G` the generator, `id` the
pairing ID as UTF-8, `code` the code as ASCII digits with separators removed,
and `F` the 32-byte fingerprint.

```
w   = OS2IP( SHA-512( lp("magic-pair-v1 w") || lp(id) || lp(code) ) ) mod n

A:  x  <-$ [1, n-1];   pA = x·G + w·M
B:  y  <-$ [1, n-1];   pB = y·G + w·N
A:  K  = x·(pB − w·N)
B:  K  = y·(pA − w·M)

TT  = lp("magic-pair-v1") || lp(id) || lp(F) || lp(pA) || lp(pB) || lp(K) || lp(w)
Ka  = SHA-256(TT)[16:32]          (SHA-256(TT)[0:16] is reserved)
KcA || KcB = HKDF-SHA256(IKM = Ka, salt = empty, info = "ConfirmationKeys", L = 64)
cA  = HMAC-SHA256(KcA, TT)
cB  = HMAC-SHA256(KcB, TT)
```

Points are encoded uncompressed (65 bytes, SEC 1 § 2.3.3); `w` as 32 bytes
big-endian. Receivers MUST reject shares that aren't valid points on the
curve or that are the point at infinity, and MUST abort if `K` is the
point at infinity. MACs MUST be compared in constant time.

Test vectors: [`test-vectors/pairing-spake2.json`](test-vectors/pairing-spake2.json).

### 5.2.3 Why this is safe

* **Wrong code**: confirmation fails and the session dies. With 8 digits and
  10 sessions per minute, an online attacker needs about 19 years on average,
  and every attempt is visible to the operator.
* **Man in the middle**: an interceptor terminating TLS with its own key gets
  a different `F` into the client's transcript than the provider uses, so
  `cB` fails at the client even when the attacker relays the code-holder's
  messages. To get further it must guess the code (one try per session).
* **Passive observer**: sees only TLS.
* **Rogue provider** that spoofs discovery: the code the user enters is shown
  by the real provider, which the impostor can't read, so its exchange with
  the client fails. Clients that know the provider ID from an earlier
  contact or a pairing URI reject the impostor before pairing even starts.

### 5.2.4 Tickets

An operator MAY create a **ticket** in advance: a one-time code with a fixed
scope set and a lifetime of at most one hour, for clients set up from the
provider's console or by scanning a QR code (pairing URI, part 2.4). A client
redeems it by passing `ticket` in the start request and the ticket's code in
the exchange. Granted scopes are the intersection of the request and the
ticket. A ticket is consumed on success and destroyed after 3 failures.

## 5.3 Issued tokens

Operators MAY issue tokens directly (`magicd token -name …` in the reference).
The operator gives the client the token **and the provider ID** (for example
as `MAGIC_PROVIDER=https://host:port#<id>` and `MAGIC_TOKEN=…`), so that the
client can pin the connection.

## 5.4 Local token files

A provider MAY write a token to a file and reference it as `token_file` in its
beacon. File permissions decide who may use it: the reference writes it with
mode `0600` into the user's runtime directory, so that every process of that
user, and no one else, has access. This matches the operating system's
security boundary: processes of one user can already read each other's data.
Sandboxed apps (Flatpak, macOS App Sandbox, mobile platforms) cannot read the
file and pair instead, which gives the user a consent step.

Providers SHOULD rotate local tokens on every start. Clients MUST NOT copy a
local token to other machines.

## 5.5 Session and unpairing

* `GET /magic/v1/session` returns the token's client record:
  `{ "client_id", "name", "scopes", "admin", "provider" }`. Clients use it to
  test credentials.
* `DELETE /magic/v1/session` revokes the caller's own token (`204`). Clients
  SHOULD call it when the user removes a provider.

## 5.6 Admin API (optional)

Providers MAY expose an admin API to tokens with the admin right, so that
operator tools can be independent of the provider implementation:

| Request | Effect |
|---|---|
| `GET /magic/v1/admin/pairings` | Pending sessions, with codes (except ticket sessions) |
| `DELETE /magic/v1/admin/pairings/{id}` | Deny a pending session |
| `POST /magic/v1/admin/tickets` `{scopes, ttl_seconds}` | Create a ticket: `{ticket, code, scopes, expires_at}` |
| `GET /magic/v1/admin/clients` | Client records (without token hashes) |
| `DELETE /magic/v1/admin/clients/{id}` | Revoke a client |
| `POST /magic/v1/admin/tokens` `{name, scopes}` | Issue a token (response as in pairing) |

Admin tokens MUST NOT be obtainable through pairing in this version.

## 5.7 Errors

Control API errors use this body, with the HTTP status codes above,
`400` for malformed requests, `404` for unknown sessions or tickets, `409` for
out-of-order pairing messages and `429` (with `Retry-After`) for rate limits:

```json
{ "error": { "code": "pairing_failed", "message": "pairing failed: wrong code or provider key mismatch" } }
```

| Code | Meaning |
|---|---|
| `unauthorized` | Missing or invalid token |
| `insufficient_scope` | Token lacks the capability |
| `bad_request` | Malformed request |
| `not_found` | Unknown resource |
| `pairing_failed` | Wrong code, or fingerprint mismatch |
| `rate_limited` | Too many attempts |
| `internal_error` | Provider failure |

Errors from capability endpoints follow the OpenAI-compatible format of the
underlying API.
