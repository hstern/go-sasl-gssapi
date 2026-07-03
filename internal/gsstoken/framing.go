// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package gsstoken

import (
	"bytes"
	"fmt"
)

// WrapInitialContextToken frames an inner token as a GSSAPI initial-context
// token (RFC 2743 §3.1): the [APPLICATION 0] tag 0x60, a DER definite length
// covering the mech OID plus the inner token, the Kerberos 5 mech OID, and the
// inner token itself. The inner token is the two-byte Tok_ID followed by the
// mechanism-specific message (e.g. TokIDAPReq ‖ AP-REQ DER).
func WrapInitialContextToken(inner []byte) []byte {
	body := make([]byte, 0, len(mechOIDDER)+len(inner))
	body = append(body, mechOIDDER...)
	body = append(body, inner...)

	length := encodeDERLength(len(body))
	out := make([]byte, 0, 1+len(length)+len(body))
	out = append(out, 0x60)
	out = append(out, length...)
	out = append(out, body...)
	return out
}

// UnwrapInitialContextToken reverses WrapInitialContextToken: it verifies the
// 0x60 tag, the DER length, and the Kerberos 5 mech OID, and returns the inner
// token (Tok_ID ‖ message). It is lenient about trailing content only insofar
// as the DER length must exactly frame the remaining bytes.
//
// The returned slice aliases b (no copy); a caller that needs the inner token
// to outlive b must copy it.
func UnwrapInitialContextToken(b []byte) (inner []byte, err error) {
	if len(b) == 0 || b[0] != 0x60 {
		return nil, fmt.Errorf("gsstoken: initial-context token missing 0x60 tag")
	}
	length, n, err := decodeDERLength(b[1:])
	if err != nil {
		return nil, err
	}
	body := b[1+n:]
	if length != len(body) {
		return nil, fmt.Errorf("gsstoken: DER length %d != %d body bytes", length, len(body))
	}
	if !bytes.HasPrefix(body, mechOIDDER) {
		return nil, fmt.Errorf("gsstoken: initial-context token is not the Kerberos 5 mech OID")
	}
	return body[len(mechOIDDER):], nil
}

// encodeDERLength renders a definite-form DER length. Lengths below 128 use the
// short form (one byte); larger lengths use the long form (0x80|n followed by n
// big-endian length octets).
func encodeDERLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for v := n; v > 0; v >>= 8 {
		tmp = append([]byte{byte(v)}, tmp...)
	}
	return append([]byte{0x80 | byte(len(tmp))}, tmp...)
}

// decodeDERLength reads a definite-form DER length, returning the length value
// and the number of bytes consumed. The indefinite form (0x80) is rejected — it
// is not valid DER and does not appear in GSSAPI tokens.
func decodeDERLength(b []byte) (length, consumed int, err error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("gsstoken: missing DER length")
	}
	first := b[0]
	if first < 0x80 {
		return int(first), 1, nil
	}
	count := int(first & 0x7F)
	if count == 0 {
		return 0, 0, fmt.Errorf("gsstoken: indefinite DER length not permitted")
	}
	if count > 4 || 1+count > len(b) {
		return 0, 0, fmt.Errorf("gsstoken: DER length of %d octets is unsupported or truncated", count)
	}
	v := 0
	for i := 0; i < count; i++ {
		v = v<<8 | int(b[1+i])
	}
	return v, 1 + count, nil
}
