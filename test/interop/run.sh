#!/usr/bin/env bash
# Copyright 2026 The go-sasl-gssapi Authors
# SPDX-License-Identifier: Apache-2.0
#
# Interop harness entrypoint: stand up a local MIT KDC, mint a real credential
# with the MIT client tools (kinit + kvno), then drive the go-sasl-gssapi client
# through a full RFC 4752 handshake against an MIT acceptor (accept.py via
# python-gssapi). Exits 0 only if every exchange is accepted by MIT krb5.
set -euo pipefail

REALM=EXAMPLE.COM
CLIENT_SPN=imap/mail.example.com          # service/host form the client requests
SPN_PRINC="$CLIENT_SPN@$REALM"            # full principal for the KDC tools
KT=/tmp/service.keytab
export KRB5CCNAME=/tmp/alice.ccache

echo "==> creating the KDC database"
kdb5_util create -s -r "$REALM" -P masterkey

echo "==> creating principals (alice, $SPN_PRINC) + service keytab"
kadmin.local -q "addprinc -pw alicepw alice@$REALM"
kadmin.local -q "addprinc -randkey $SPN_PRINC"
kadmin.local -q "ktadd -k $KT $SPN_PRINC"

echo "==> starting the KDC"
krb5kdc
sleep 1

echo "==> kinit alice + fetch the $CLIENT_SPN service ticket into the ccache"
printf '%s' alicepw | kinit alice@"$REALM"
kvno "$SPN_PRINC"
klist

export KRB5_KTNAME="$KT"
export INTEROP_CLIENT=/usr/local/bin/interop-client

echo "==> [1/2] full handshake, empty authzid"
python3 /src/test/interop/accept.py "$CLIENT_SPN" ""

echo "==> [2/2] full handshake, authzid=alice@$REALM"
python3 /src/test/interop/accept.py "$CLIENT_SPN" "alice@$REALM"

echo "==> Phase 6 interop PASSED — the Go client is accepted by MIT krb5 over a full RFC 4752 handshake (AP-REQ, AP-REP, security-layer wrap/unwrap)"
