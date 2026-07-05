# Interop harness

Proves the go-sasl-gssapi client interoperates with the **reference MIT krb5 C
implementation** — a cross-implementation check that pure-Go (gokrb5 ↔ gokrb5)
tests cannot give, because gokrb5's parsers are lenient where MIT's are strict.

## What it does

Everything runs in one container against a local MIT KDC — no external network:

1. **KDC + credential.** `run.sh` stands up an MIT KDC (`kdb5_util` / `krb5kdc`),
   creates a user (`alice`) and a service (`imap/mail.example.com`) with a
   keytab, then uses the **MIT client tools** to mint a real credential:
   `kinit alice` for a TGT, `kvno` for the service ticket. The result is a
   genuine on-disk MIT ccache.
2. **Client.** `client/` (Go) loads that ccache with this library's
   `FromCCache` / `credentials.LoadCCache` and drives the SASL GSSAPI exchange,
   speaking a base64 line protocol on stdin/stdout.
3. **Acceptor.** `accept.py` plays the RFC 4752 acceptor using **MIT krb5 via
   `python-gssapi`** (which binds `libgssapi_krb5`): it accepts the client's
   AP-REQ, returns the AP-REP (mutual auth), sends a GSS-wrapped
   no-security-layer offer, and unwraps + checks the client's reply. It exits 0
   only if MIT accepts every step and the client selected the no-security-layer
   option with the expected authzid.

Together this validates the whole client path against MIT: the on-disk ccache
parse, the AP-REQ and its RFC 4121 §4.1.1 checksum, mutual authentication via
the AP-REP, and the security-layer `GSS_Wrap`/`Unwrap` — end to end, with no
fakes on the credential path.

## Run it

```sh
# from the repository root
docker compose -f test/interop/docker-compose.yml up --build \
  --exit-code-from interop --abort-on-container-exit
```

or without compose:

```sh
docker build -f test/interop/Dockerfile -t saslgssapi-interop .
docker run --rm saslgssapi-interop
```

The GitHub Actions `interop` workflow runs the same image on demand
(`workflow_dispatch`); it is intentionally **not** a required check (it stands
up a KDC and is slower than the unit suite).
