// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

// Package gsstoken marshals and unmarshals the binary tokens exchanged by the
// SASL GSSAPI mechanism (RFC 4752) built on the Kerberos 5 GSS-API mechanism
// (RFC 4121). It is the wire layer: the GSSAPI initial-context token framing
// (RFC 2743 §3.1), the RFC 4121 §4.1.1 authenticator checksum (type 0x8003),
// and the RFC 4752 §3.3 security-layer negotiation tokens.
//
// The package is intentionally free of any Kerberos dependency — it operates on
// byte slices only, so the token shapes can be tested against exact vectors
// without a KDC or a credential. The AP-REQ/AP-REP that ride inside these
// tokens are built by the parent package over the krb5 substrate.
//
// Endianness is the load-bearing hazard here and differs by field: the 0x8003
// checksum's Lgth and Flags are little-endian (RFC 4121 §4.1.1), while the
// security-layer max-buffer size is big-endian/network order (RFC 4752 §3.3).
// Each marshaler names its byte order at the call site.
package gsstoken

// The Kerberos 5 GSS-API mechanism OID (1.2.840.113554.1.2.2) in DER form:
// tag 0x06, length 0x09, then the nine identifier octets. This is the mech OID
// carried in the initial-context token framing (RFC 2743 §3.1).
var mechOIDDER = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02}

// Token identifiers (RFC 4121 §4.1). Each is the two literal leading octets of
// the inner token that follows the mech OID in the initial-context token.
var (
	// TokIDAPReq marks a KRB_AP_REQ inner token (the client's message 1).
	TokIDAPReq = [2]byte{0x01, 0x00}
	// TokIDAPRep marks a KRB_AP_REP inner token (the acceptor's mutual-auth reply).
	TokIDAPRep = [2]byte{0x02, 0x00}
	// TokIDWrap marks a GSS WrapToken v2 (RFC 4121 §4.2.6), the framing the
	// security-layer negotiation tokens ride in.
	TokIDWrap = [2]byte{0x05, 0x04}
)

// ChecksumTypeGSSAPI is the Kerberos checksum type for the RFC 4121 §4.1.1
// GSS-API authenticator checksum (IANA "Checksum Type Numbers", 32771).
const ChecksumTypeGSSAPI = 0x8003
