// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

// Package seclayer marshals and unmarshals the RFC 4752 §3.3 security-layer
// negotiation tokens — the acceptor's offer and the client's selection. These
// are the SASL-GSSAPI-specific bodies carried inside the GSS Wrap tokens; the
// GSS layer itself (AP-REQ/AP-REP, the RFC 4121 checksum, Wrap/Unwrap) lives in
// github.com/hstern/krb5.
package seclayer

import "fmt"

// SecurityLayer is the RFC 4752 §3.3 security-layer bit-mask. The server's
// offer is a union of the layers it supports; the client's reply names the
// single layer it selects.
type SecurityLayer byte

// Security-layer bits (RFC 4752 §3.3).
const (
	// LayerNone is authentication only, no security layer (the v0 selection).
	LayerNone SecurityLayer = 1 << iota
	// LayerIntegrity is GSS integrity protection (GSS_Wrap with conf=FALSE).
	LayerIntegrity
	// LayerConfidentiality is GSS confidentiality protection (GSS_Wrap with conf=TRUE).
	LayerConfidentiality
)

// maxBuffer24 is the largest value the 3-byte max-buffer field can hold.
const maxBuffer24 = 1<<24 - 1

// secLayerLen is the length of the fixed part of a security-layer token: the
// one layer-mask byte plus the three max-buffer bytes.
const secLayerLen = 4

// SecurityLayerOffer is the acceptor's security-layer token (RFC 4752 §3.3),
// after it has been GSS_Unwrap-ped: a bit-mask of the layers the server
// supports and the maximum cipher-text buffer it can receive.
type SecurityLayerOffer struct {
	// Layers is the set of security layers the server supports.
	Layers SecurityLayer
	// MaxBuffer is the largest message the server can receive, in bytes
	// (a 24-bit big-endian field on the wire).
	MaxBuffer uint32
}

// ParseSecurityLayerOffer decodes the 4-byte unwrapped server offer. The
// max-buffer field is network byte order (big-endian), in contrast to the
// little-endian checksum integers.
func ParseSecurityLayerOffer(b []byte) (SecurityLayerOffer, error) {
	if len(b) != secLayerLen {
		return SecurityLayerOffer{}, fmt.Errorf("seclayer: security-layer offer is %d bytes, want %d", len(b), secLayerLen)
	}
	return SecurityLayerOffer{
		Layers:    SecurityLayer(b[0]),
		MaxBuffer: uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]),
	}, nil
}

// ClientReply is the client's security-layer response (RFC 4752 §3.3), the
// payload that gets GSS_Wrap-ped as the final client message: the single
// selected layer, the client's own max-buffer, and the optional authorization
// identity.
type ClientReply struct {
	// Selected is the single security layer the client chooses. It must be one
	// of the offered layers; v0 always selects LayerNone.
	Selected SecurityLayer
	// MaxBuffer is the largest message the client can receive (24-bit on the
	// wire). It is zero when Selected is LayerNone — no application data is
	// wrapped, so no buffer is advertised.
	MaxBuffer uint32
	// AuthzID is the authorization identity, UTF-8 with no NUL terminator. An
	// empty AuthzID authenticates as the ticket's client principal.
	AuthzID string
}

// Marshal encodes the client reply: the selected-layer byte, the 3-byte
// big-endian max-buffer, then the raw authzid bytes.
func (r ClientReply) Marshal() ([]byte, error) {
	if r.MaxBuffer > maxBuffer24 {
		return nil, fmt.Errorf("seclayer: max-buffer %d exceeds 24-bit field", r.MaxBuffer)
	}
	if r.Selected == LayerNone && r.MaxBuffer != 0 {
		return nil, fmt.Errorf("seclayer: no-security-layer reply must advertise a zero max-buffer")
	}
	out := make([]byte, secLayerLen+len(r.AuthzID))
	out[0] = byte(r.Selected)
	out[1] = byte(r.MaxBuffer >> 16)
	out[2] = byte(r.MaxBuffer >> 8)
	out[3] = byte(r.MaxBuffer)
	copy(out[secLayerLen:], r.AuthzID)
	return out, nil
}
