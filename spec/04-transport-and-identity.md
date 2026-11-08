# 4. Transport and identity

## 4.1 Provider identity

A provider has a long-lived asymmetric key pair; the reference
implementation uses ECDSA P-256. From its DER-encoded SubjectPublicKeyInfo
(SPKI):

* **Fingerprint**: `SHA-256(SPKI)`, written `sha256:` + base64url.
* **Provider ID**: the first 16 bytes of the fingerprint, encoded in base32
  (RFC 4648 alphabet, lower case, no padding). That's 26 characters, for
  example `3yt7gi2mtkanxfe7rnclz736mq`.

The ID is *self-certifying*: anyone who knows it can check a TLS connection
against it with no other configuration and no certificate authority. Clients
MUST compare IDs case-insensitively. User interfaces MAY show a shortened
prefix but MUST NOT use a prefix for pinning.

## 4.2 Listeners

* **Network listeners** MUST use TLS 1.3 (RFC 8446) and present a certificate
  for the identity key. A self-signed certificate is expected; it SHOULD
  include the provider's host names and addresses as SANs, and SHOULD set
  `basicConstraints CA:TRUE` so that clients whose TLS stack lacks custom
  verification can use the certificate as its own trust anchor.
* **Loopback listeners** (127.0.0.0/8, ::1) MAY use plain HTTP. They MUST
  reject requests whose `Host` header is not a loopback address or
  `localhost`, with status 421, to defeat DNS rebinding from web pages.
* **Unix domain sockets** MAY be offered for local clients; their URL form is
  outside the scope of this version.

Plain HTTP MUST NOT be used on non-loopback interfaces.

## 4.3 Pinning

A client connecting over TLS MUST verify that the SPKI of the server's leaf
certificate matches the provider it intends to reach:

* the full fingerprint, if it has one (from a credential or a beacon), else
* the provider ID (from discovery, a pairing URI or `MAGIC_PROVIDER`).

Host name validation and certificate chains are not used; the pin replaces
them. A client MUST NOT send a token over a connection that fails the pin,
and SHOULD tell the user that the provider's key changed, or that someone is
impersonating it.

For a plain HTTP loopback connection there is no TLS key to check; the client
relies on the beacon file, which only local users can write.

The only time a client connects without a pin is the first contact with a
provider known only by address, such as a URL typed by the user. The client
then learns the fingerprint from the TLS handshake and MUST confirm it by
pairing (part 5) before trusting it.

## 4.4 Proxies

Clients SHOULD NOT send requests to local-network providers through HTTP
proxies configured for internet access. Provider addresses are usually
private and proxies would see the plaintext.

## 4.5 Key changes

In this version a new key is a new provider: clients must pair again. A
provider SHOULD keep its key for its lifetime and renew its certificate with
the same key. The reference implementation renews 30 days before expiry.
