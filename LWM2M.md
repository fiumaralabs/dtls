# fiumaralabs/dtls: pion/dtls v3, patched for LwM2M

This branch (`lwm2m-v3`) is github.com/pion/dtls/v3 (MIT, copyright the Pion community) from the upstream `v3` branch (v3.1.10 plus later fixes), with five patches that [github.com/fiumaralabs/lwm2m](https://github.com/fiumaralabs/lwm2m) needs. The module path is renamed to `github.com/fiumaralabs/dtls/v3`, so consumers can require it without a `replace` directive (Go ignores `replace` outside the main module).
It is a stopgap: each patch is being proposed upstream, and this fork goes away once pion ships them. Every patched line is marked `lwm2m patch`. The first commit on top of upstream is the whole patch, the second is the rename, and later commits fix the patches.

Tags are `v3.1.11-lwm2m.N` (a pre-release of the next v3 patch release).

## Why a patch

pion has no RFC 7250 raw public keys, which security mode 1 (RPK) needs (T §5.2.9.2, SEC-09; the Bootstrap-Server MUST support it, BS-10). RPK changes the handshake itself: the certificate-type extensions and the form of the Certificate message, which is a bare `SubjectPublicKeyInfo<1..2^24-1>` instead of a `certificate_list`. Both ends hash these messages into Finished and CertificateVerify, so a record-layer shim cannot rewrite them. pion's hooks only cover Hello and CertificateRequest.

We ruled out the alternatives:

- A cgo binding to mbedTLS (or OpenSSL) would replace the whole DTLS stack under go-coap, and go-coap's DTLS server builds on pion. It would also break pure-Go cross-compilation.
The patches do nothing unless enabled: pion's whole upstream test suite passes on the patched tree.

## Changes

1. **RFC 7250 raw public keys.**
   - `Config.ClientCertificateTypes` and `Config.ServerCertificateTypes` hold the types in preference order. nil means X.509 only and sends no extension.
   - The `client_certificate_type` (19) and `server_certificate_type` (20) extensions are added to `pkg/protocol/extension`.
   - The server selects the types in `negotiateCertificateTypes` and answers `unsupported_certificate` (43) when there is no common type.
   - The client checks the ServerHello's selections against what it offered.
   - `MessageCertificate.RawPublicKey` selects the RFC 7250 §3 wire form. The handshake rejects a Certificate whose form differs from the negotiated type.
   - A raw key's credential is the SPKI of `Certificates[0].PrivateKey`. `VerifyPeerCertificate` receives `[]{SPKI}` and makes the trust decision, since a raw key has no chain. Without it a raw key is refused unless the config opts out (`InsecureSkipVerify` on a client, `ClientAuth` below `VerifyClientCertIfGiven` on a server).
   - CA names from a CertificateRequest do not filter a raw key.
2. **`unknown_psk_identity` (115)** is the alert for an unknown PSK identity (RFC 4279 §2) in place of `internal_error` (80). LwM2M clients class 115 as "Fail" (T Tbl 5.2.10-1). Table 5.2.10-1 does not list 80 at all.
3. **The PSK identity is kept in `Session.IdentityHint`**, so a resumed session keeps its authenticated identity (SEC-11, README C2).
4. **ECDHE curve selection** takes the client's most preferred curve that we support (RFC 8422 §5.1, the /0/x/18 order). Upstream took the first offered curve, even an unsupported one.
5. **A new handshake from an address that already has a session** (RFC 6347 §4.2.8, `internal/net/udp`). Upstream routed every datagram from a known address to the existing connection, so an epoch-0 ClientHello from a client that reuses its port was swallowed and the new handshake hung. Anjay reuses its last local port after bootstrap, a re-Register or a restart, and NATs do the same. Now such a ClientHello starts a pending connection. Epoch-0 records go only to the pending connection, and later epochs go to both (each drops what it cannot decrypt). The pending connection takes over the address only once its handshake completes (`HandshakeDone`, called from `conn.go`), so a spoofed ClientHello cannot steal an established session. A ClientHello with a different client random replaces the pending connection (the replaced one stops reading and writing, so its handshake fails), so a spoofed or half-open attempt cannot block the client's next handshake from that address until it times out. A retransmitted ClientHello, or the one answering a cookie, keeps the random and leaves the pending handshake alone. `PacketConn.Close` deletes only map entries it still owns, and the listener counts open connections rather than map entries, so a pending or superseded connection cannot make `Close` wait forever. Found by `interop/peers` and pinned by `server.TestDTLSNewHandshakeFromSamePort`, `TestNewHandshakeFromSameAddress` and `udp.TestListenerNewHandshakeOnAddress`.

## Upgrading

Rebase `lwm2m-v3` onto the new upstream v3 release, rerun `go test -race ./...` and `golangci-lint run`, tag `v3.X.Y-lwm2m.1`, then in fiumaralabs/lwm2m run `go get github.com/fiumaralabs/dtls/v3@<tag>` and `go test -race ./server ./dtlssuite` (including `TestOpenSSLInterop`, which runs RPK against OpenSSL 3.2+).
