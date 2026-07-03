# go-sasl-gssapi

The **SASL GSSAPI mechanism** ([RFC 4752](https://www.rfc-editor.org/rfc/rfc4752))
for Go — the Kerberos 5 GSS-API mechanism (OID `1.2.840.113554.1.2.2`) exposed as
a SASL client mechanism, so a Go program can authenticate to IMAP, SMTP, LDAP,
XMPP, AMQP, and other SASL-protected services with a Kerberos credential.

No pure-Go SASL GSSAPI mechanism exists today: it is absent from
[`emersion/go-sasl`](https://github.com/emersion/go-sasl) and from the `gokrb5`
family (which ship SPNEGO/HTTP-Negotiate and the raw krb5 primitives, but no SASL
mechanism). This library fills that gap.

> **Status:** pre-publication. The first tagged release will be `v0.1.0`.
> The API is unstable until then.

## Install

```sh
go get github.com/hstern/go-sasl-gssapi
```

Requires Go 1.26+.

## Scope (v0)

- **Client (initiator) only** — the caller is the SASL client.
- **Authentication only** (`no_security_layer`) — transport confidentiality is
  expected from TLS. GSS integrity/confidentiality layers and GS2
  ([RFC 5801](https://www.rfc-editor.org/rfc/rfc5801)) channel binding are
  planned follow-ups.
- **Mutual authentication** is always performed (the server's `AP-REP` is
  required and verified).
- Satisfies the `emersion/go-sasl` client contract (`Start`/`Next`), so it drops
  straight into `go-imap` and `go-smtp`.

## How it works

```
Kerberos credential (holder-of-key: service ticket + session key)
        │
        ▼  Start()  → GSSAPI initial-context token (AP-REQ, RFC 4121 GSS checksum, mutual)
        ▼  Next()   ← acceptor AP-REP  → verify mutual auth
        ▼  Next()   ← security-layer offer (GSS Wrap token)
        ▼           → selected layer + max buffer + authzid (GSS Wrap token)
        ▼
   authenticated SASL session
```

The credential is supplied as a Kerberos service ticket plus its session key
(holder-of-key). An adapter loads it from an MIT credential cache (ccache), so a
ticket minted out-of-band — for example by an OAuth2-to-Kerberos exchange, or a
filesystem `KRB5CCNAME` — plugs in directly.

## License

[Apache-2.0](LICENSE).
