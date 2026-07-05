#!/usr/bin/env python3
# Copyright 2026 The go-sasl-gssapi Authors
# SPDX-License-Identifier: Apache-2.0
"""Interop acceptor: drive the go-sasl-gssapi client through a full RFC 4752
handshake and validate every step with the MIT krb5 C GSSAPI implementation
(via python-gssapi / libgssapi_krb5).

Spawns interop-client ($INTEROP_CLIENT) as the SASL client, then plays the
acceptor: accepts the AP-REQ, returns the AP-REP (mutual auth), sends a
GSS-wrapped no-security-layer offer, and unwraps + checks the client's reply.
The service keytab is taken from $KRB5_KTNAME. Exits 0 and prints INTEROP OK iff
the whole exchange succeeds and the client selected the no-security-layer option
with the expected authzid.

argv: <spn> [expected-authzid]
"""
import base64
import os
import subprocess
import sys

import gssapi


def main() -> int:
    spn = sys.argv[1]
    expect_authzid = sys.argv[2] if len(sys.argv) > 2 else ""
    client_bin = os.environ.get("INTEROP_CLIENT", "/usr/local/bin/interop-client")

    proc = subprocess.Popen(
        [client_bin, spn, expect_authzid],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    def read_token() -> bytes:
        line = proc.stdout.readline()
        if line == "":
            err = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"client closed unexpectedly: {err}")
        line = line.strip()
        return base64.b64decode(line) if line else b""

    def send_token(b: bytes) -> None:
        proc.stdin.write(base64.b64encode(b).decode() + "\n")
        proc.stdin.flush()

    # 1. AP-REQ from the client → accept it, producing the AP-REP.
    init = read_token()
    server_creds = gssapi.Credentials(usage="accept")
    ctx = gssapi.SecurityContext(creds=server_creds, usage="accept")
    ap_rep = ctx.step(init)
    if not ctx.complete:
        raise RuntimeError("acceptor context not complete after AP-REQ")
    print(f"accepted: initiator={ctx.initiator_name} target={ctx.target_name}", file=sys.stderr)

    # 2. AP-REP → the client verifies mutual auth and returns an empty token.
    send_token(ap_rep or b"")
    empty = read_token()
    if empty:
        raise RuntimeError(f"expected empty token after AP-REP, got {len(empty)} bytes")

    # 3. Security-layer offer: no-security-layer supported, zero buffer, GSS-wrapped
    #    with conf=FALSE (integrity only).
    offer = bytes([0x01, 0x00, 0x00, 0x00])
    send_token(ctx.wrap(offer, False).message)

    # 4. The client's wrapped reply → unwrap and validate.
    reply = read_token()
    payload = ctx.unwrap(reply).message
    if len(payload) < 4:
        raise RuntimeError(f"reply payload too short: {payload!r}")
    if payload[0] != 0x01:
        raise RuntimeError(f"selected layer {payload[0]:#x}, want 0x01 (no security layer)")
    authzid = payload[4:].decode()
    if authzid != expect_authzid:
        raise RuntimeError(f"authzid {authzid!r} != expected {expect_authzid!r}")

    proc.stdin.close()
    rc = proc.wait(timeout=10)
    if rc != 0:
        raise RuntimeError(f"client exited with status {rc}")

    print("INTEROP OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - top-level harness guard
        print(f"INTEROP FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
