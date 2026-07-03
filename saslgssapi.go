// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

// Package saslgssapi implements the SASL GSSAPI mechanism (RFC 4752) — the
// Kerberos 5 GSS-API mechanism (OID 1.2.840.113554.1.2.2) exposed as a SASL
// mechanism — so a Go client can authenticate to IMAP, SMTP, LDAP, XMPP, and
// other SASL-protected services with a Kerberos credential.
//
// v0 is the client (initiator) side only, negotiating the "no security layer"
// protection (authentication only); transport confidentiality is expected from
// TLS. It is built to satisfy the emersion/go-sasl client contract so it drops
// into go-imap and go-smtp.
package saslgssapi

// SpecVersion is the SASL GSSAPI profile this build implements.
const SpecVersion = "v0 (SASL GSSAPI client; RFC 4752)"
