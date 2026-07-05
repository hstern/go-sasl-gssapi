# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-05

First release: a working RFC 4752 SASL GSSAPI **client** (initiator),
authentication-only with mandatory mutual authentication.

### Added
- `Client` implementing the `emersion/go-sasl` `Client` contract
  (`Start`/`Next`), so it drops into `go-imap` and `go-smtp`.
- `NewClient(Config)` with `Config{Client, Service, AuthzID}`, and `FromCCache`
  to build a holder-of-key Kerberos client from an MIT credential cache.
- The RFC 4752 handshake: GSSAPI initial-context token (AP-REQ with the RFC 4121
  §4.1.1 checksum), AP-REP mutual-authentication verification, and the
  no-security-layer negotiation over GSS Wrap tokens. The Kerberos GSS context
  layer is provided by `github.com/hstern/krb5`.
- Cross-implementation interop verified against MIT krb5 (`test/interop`, Docker):
  an MIT `python-gssapi` acceptor drives the client through a full handshake over
  a real KDC.

### Notes
- Client-only, authentication-only (`no_security_layer`); consumers must run over
  TLS. GSS security layers and GS2/channel binding are out of scope for v0.

[Unreleased]: https://github.com/hstern/go-sasl-gssapi/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hstern/go-sasl-gssapi/releases/tag/v0.1.0
