# 2. Discovery

Discovery tells a client *where* providers are and *roughly* what they offer.
Discovery data is unauthenticated: a client MUST NOT trust any of it beyond
using the provider ID as the pin for the connection it then makes (part 4).

Clients SHOULD support all three mechanisms below and merge results by
provider ID.

## 2.1 Local network: DNS-SD

Providers reachable over the network MUST advertise a DNS-SD service
(RFC 6763) of type **`_magic._tcp`**, over multicast DNS (RFC 6762) in the
`local.` domain. They MAY also be registered in a unicast DNS-SD domain
(RFC 6763 § 11) for managed networks; clients use the same records there.

### Instance name

A human-readable name chosen by the operator, e.g. `Basement GPU`. Clients
display it but MUST NOT use it as an identity. Providers SHOULD resolve name
conflicts per RFC 6762 § 9 or by appending a short form of their provider ID.

### SRV and addresses

The SRV record gives the host and port of the TLS listener (part 4). A/AAAA
records follow the usual mDNS rules.

### TXT record

| Key | Required | Value |
|---|---|---|
| `txtvers` | MUST | `1` |
| `v` | MUST | Protocol version, e.g. `0.1` |
| `id` | MUST | Provider ID (26 lowercase base32 characters, part 4) |
| `caps` | SHOULD | Comma-separated capabilities, e.g. `chat,embeddings` |
| `auth` | SHOULD | Comma-separated auth methods, e.g. `pairing,token` |
| `path` | MAY | Descriptor path if not `/.well-known/magic` |

Keys are case-insensitive. Clients MUST ignore unknown keys and SHOULD ignore
instances without a syntactically valid `id`. Since TXT records are limited in
practice to a few hundred bytes, the `caps` list is a hint; the descriptor is
authoritative.

### Capability subtypes

For each registered capability it offers, a provider SHOULD also register the
DNS-SD subtype `_<capability>._sub._magic._tcp`, so that a client looking for,
say, speech recognition can browse `_transcription._sub._magic._tcp.local.` and
only hear from providers that can do it.

### Example

```
_magic._tcp.local.                       PTR  Basement\032GPU._magic._tcp.local.
_chat._sub._magic._tcp.local.            PTR  Basement\032GPU._magic._tcp.local.
_embeddings._sub._magic._tcp.local.      PTR  Basement\032GPU._magic._tcp.local.
Basement\032GPU._magic._tcp.local.       SRV  0 0 8765 gpu-box.local.
Basement\032GPU._magic._tcp.local.       TXT  "txtvers=1" "v=0.1"
                                              "id=3yt7gi2mtkanxfe7rnclz736mq"
                                              "caps=chat,embeddings,transcription"
                                              "auth=pairing,token"
gpu-box.local.                           A    192.168.1.20
```

## 2.2 Same computer: beacon files

Providers that serve apps on the same computer SHOULD publish a **beacon**:
a JSON file named `<provider-id>.json` in a beacon directory, written when the
provider starts and removed when it stops.

| Platform | Per-user directory | System directory |
|---|---|---|
| Linux, BSD | `$XDG_RUNTIME_DIR/magic/providers/` | `/run/magic/providers/` |
| macOS | `~/Library/Application Support/magic/providers/` | `/Library/Application Support/magic/providers/` |
| Windows | `%LOCALAPPDATA%\magic\providers\` | `%ProgramData%\magic\providers\` |

If `$XDG_RUNTIME_DIR` is unset, the per-user directory is
`<user cache dir>/magic/providers/`. The environment variable
`MAGIC_BEACON_DIRS` (a list in the platform's path-list syntax) replaces both
directories, e.g. inside containers or sandboxes.

The per-user directory MUST be accessible only to its user. Files MUST be
replaced atomically (write to a temporary name, then rename).

### Beacon format

```json
{
  "magic": "0.1",
  "id": "3yt7gi2mtkanxfe7rnclz736mq",
  "name": "Basement GPU",
  "url": "http://127.0.0.1:41129",
  "fingerprint": "sha256:3ksDF…",
  "token_file": "/run/user/1000/magic/3yt7gi2mtkanxfe7rnclz736mq.token",
  "pid": 4242,
  "capabilities": ["chat", "embeddings"]
}
```

| Member | Required | Meaning |
|---|---|---|
| `magic` | MUST | Protocol version |
| `id` | MUST | Provider ID; MUST equal the file name |
| `name` | MUST | Display name |
| `url` | MUST | Base URL for local clients: `http://` with a loopback address, or `https://` |
| `fingerprint` | SHOULD | Key fingerprint (part 4); REQUIRED for pairing over `http://` |
| `token_file` | MAY | Path of a file containing a bearer token for local users (part 5.4) |
| `pid` | MAY | Process ID; clients MAY skip beacons whose process no longer exists |
| `capabilities` | SHOULD | Capability hints |

A client SHOULD confirm that a beacon is live by fetching the descriptor and
checking that its provider ID matches.

## 2.3 Manual configuration

Clients SHOULD accept a provider given explicitly as a URL, optionally with
the provider ID as fragment, and SHOULD read it from the environment
variable **`MAGIC_PROVIDER`**:

```
MAGIC_PROVIDER=https://gpu-box.lan:8765#3yt7gi2mtkanxfe7rnclz736mq
MAGIC_TOKEN=mgc_…            # optional, an operator-issued token (part 5.3)
```

If the fragment is present, the client MUST pin the provider to it.

## 2.4 Pairing URIs

A provider MAY display a pairing URI, e.g. as a QR code, that carries
everything needed to pair with an operator-created ticket (part 5.2.4):

```
magic://192.168.1.20:8765/pair?id=3yt7gi2mtkanxfe7rnclz736mq&ticket=tk_0Mwl…&code=05282985
```

The authority is the provider's TLS endpoint, `id` the provider ID to pin,
`ticket` and `code` the ticket. A pairing URI is a secret until it is redeemed
or expires.
