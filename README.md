# go-sasl-gssapi

The **SASL GSSAPI mechanism** ([RFC 4752](https://www.rfc-editor.org/rfc/rfc4752))
for Go — the Kerberos 5 GSS-API mechanism (OID `1.2.840.113554.1.2.2`) exposed as
a SASL client mechanism, so a Go program can authenticate to IMAP, SMTP, LDAP,
XMPP, AMQP, and other SASL-protected services with a Kerberos credential.

No pure-Go SASL GSSAPI mechanism exists elsewhere: it is absent from
[`emersion/go-sasl`](https://github.com/emersion/go-sasl) and from the `gokrb5`
family (which ship SPNEGO/HTTP-Negotiate and the raw krb5 primitives, but no SASL
mechanism). This library fills that gap. The client is a thin wrapper over the
Kerberos GSS context layer in [`github.com/hstern/krb5`](https://github.com/hstern/krb5);
what it adds is the RFC 4752 SASL framing.

> **Status:** `v0.x`. The client works and is verified against the reference MIT
> krb5 implementation (see [Interop](#interop)). The API may change between minor
> versions until `v1.0.0`.

## Install

```sh
go get github.com/hstern/go-sasl-gssapi
```

Requires Go 1.26+.

## Quickstart

```go
package main

import (
	"log"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/hstern/krb5/credentials"

	"github.com/hstern/go-sasl-gssapi"
)

func main() {
	// A Kerberos credential cache already holding a service ticket for the
	// target (holder-of-key) — e.g. from kinit, KRB5CCNAME, or an
	// OAuth2-to-Kerberos exchange.
	cc, err := credentials.LoadCCache("/tmp/krb5cc_1000")
	if err != nil {
		log.Fatal(err)
	}
	krbClient, err := saslgssapi.FromCCache(cc)
	if err != nil {
		log.Fatal(err)
	}

	sc, err := saslgssapi.NewClient(saslgssapi.Config{
		Client:  krbClient,
		Service: "imap/mail.example.com", // the target service principal
	})
	if err != nil {
		log.Fatal(err)
	}

	// sc is an emersion/go-sasl Client — hand it straight to go-imap or go-smtp:
	c, err := imapclient.DialTLS("mail.example.com:993", nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := c.Authenticate(sc); err != nil { // go-smtp: c.Auth(sc)
		log.Fatal(err)
	}
}
```

`Config.AuthzID` sets an optional authorization identity; leaving it empty
authenticates as the ticket's client principal. Consumers **must** run over TLS —
v0 negotiates no security layer, so confidentiality comes from the transport.

## Scope (v0)

- **Client (initiator) only** — the caller is the SASL client.
- **Authentication only** (`no_security_layer`) — transport confidentiality is
  expected from TLS. GSS integrity/confidentiality layers and GS2
  ([RFC 5801](https://www.rfc-editor.org/rfc/rfc5801)) channel binding are out of
  scope (the latter is destined for a separate `GS2-KRB5` library).
- **Mutual authentication** is always performed (the server's `AP-REP` is
  required and verified).
- Satisfies the `emersion/go-sasl` client contract (`Start`/`Next`), so it drops
  straight into `go-imap` and `go-smtp`.

## How it works

```
Kerberos credential (holder-of-key: service ticket + session key, from a ccache)
        │
        ▼  Start()  → GSSAPI initial-context token (AP-REQ, RFC 4121 GSS checksum, mutual)
        ▼  Next()   ← acceptor AP-REP  → verify mutual auth
        ▼  Next()   ← security-layer offer (GSS Wrap token)
        ▼           → selected layer + authzid (GSS Wrap token)
        ▼
   authenticated SASL session
```

The Kerberos GSS context establishment (the AP-REQ with its RFC 4121 §4.1.1
checksum, AP-REP verification, and the per-message Wrap tokens) is handled by
`hstern/krb5`'s `krb5context.Initiator` / `gssapi.SecContext`; this library adds
the RFC 4752 SASL framing and the security-layer negotiation. `FromCCache` adapts
an MIT credential cache for the holder-of-key case — the ccache already holds the
service ticket, so no KDC is contacted.

## Interop

Verified against the reference **MIT krb5** C implementation: the client is
driven through a full RFC 4752 handshake by an MIT `python-gssapi` acceptor over
a real KDC — the ccache parse, the AP-REQ and its checksum, mutual authentication,
and the security-layer `GSS_Wrap`/`Unwrap` are all accepted by MIT
`libgssapi_krb5`. See [`test/interop/`](test/interop/) (Docker).

## License

[Apache-2.0](LICENSE).
