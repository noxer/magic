# 7. Security and privacy considerations

## 7.1 Threat model

The protocol is designed for networks that may contain attackers: shared
offices, dormitories, public Wi-Fi, compromised IoT devices. Such an attacker
can send arbitrary multicast traffic, spoof addresses and intercept or modify
traffic between any two hosts.

| Threat | Mitigation |
|---|---|
| Eavesdropping on prompts, outputs, tokens | TLS 1.3 on every network listener (part 4.2) |
| Fake provider via spoofed mDNS | Discovery data is a hint only; pins and pairing authenticate the key (4.3, 5.2) |
| Interception during pairing | PAKE bound to the TLS fingerprint (5.2.3) |
| Brute-forcing pairing codes | One guess per session, rate limits, operator visibility, expiry |
| Stolen token used elsewhere | Tokens are only sent over pinned connections; revocation per client; scopes limit damage |
| Web pages attacking local providers (CSRF, DNS rebinding) | `Host` checks on loopback listeners, bearer tokens (not cookies), no CORS by default |
| Other users on the same computer | Per-user beacon directories and `0600` token files |
| Misleading privacy claims | Mandatory honest locality declaration (3.3); clients assume `cloud` if absent |

Out of scope: a compromised provider host, malicious processes running as the
same user as a client, and a malicious operator.

## 7.2 Discovery leaks

mDNS announcements reveal that a provider exists, its name and its rough
capabilities to everyone on the link. Operators of sensitive providers SHOULD
use neutral instance names, MAY omit `caps` and subtypes, or MAY disable
mDNS and distribute `MAGIC_PROVIDER` URLs instead. Providers SHOULD NOT reveal
model details to unauthenticated clients unless configured to (part 3).

## 7.3 Browsers

Providers MUST NOT send permissive CORS headers by default. A provider that
wants to serve web applications MUST restrict CORS to origins the operator
approved and MUST still require tokens. A future version will define a
browser profile.

## 7.4 Logging and retention

Providers SHOULD NOT log prompt or output content by default. A provider that
retains content MUST say so in its user-facing documentation; a future
descriptor member will make retention machine-readable.

## 7.5 Gateways to hosted APIs

A provider that forwards to a hosted API holds the hosted API's credentials;
clients never see them. Such a provider MUST declare `cloud` locality for the
forwarded models and SHOULD make sure scopes and rate limits prevent local
clients from running up costs.

## 7.6 Resource exhaustion

Inference is expensive. Providers SHOULD apply per-client concurrency limits
and request size limits, and SHOULD let operators revoke misbehaving clients.
