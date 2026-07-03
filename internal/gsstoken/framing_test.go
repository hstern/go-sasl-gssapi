// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package gsstoken

import (
	"bytes"
	"testing"
)

func TestWrapInitialContextTokenVector(t *testing.T) {
	// A minimal inner token: the AP-REQ Tok_ID followed by three stand-in
	// AP-REQ bytes. The framing is what is asserted, not the AP-REQ content.
	inner := append(TokIDAPReq[:], 0xAA, 0xBB, 0xCC)
	got := WrapInitialContextToken(inner)
	want := []byte{
		0x60,                                                             // [APPLICATION 0]
		0x10,                                                             // DER length = 11 (OID) + 5 (inner) = 16
		0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02, // mech OID
		0x01, 0x00, 0xAA, 0xBB, 0xCC, // inner token
	}
	if !bytes.Equal(got, want) {
		t.Errorf("WrapInitialContextToken =\n %x\nwant\n %x", got, want)
	}
}

func TestInitialContextTokenRoundTrip(t *testing.T) {
	// Include a long inner token (>127 bytes total body) to exercise the DER
	// long-form length path.
	for _, size := range []int{0, 3, 200} {
		inner := make([]byte, size)
		for i := range inner {
			inner[i] = byte(i)
		}
		wrapped := WrapInitialContextToken(inner)
		got, err := UnwrapInitialContextToken(wrapped)
		if err != nil {
			t.Fatalf("size %d: Unwrap: %v", size, err)
		}
		if !bytes.Equal(got, inner) {
			t.Errorf("size %d: round-trip =\n %x\nwant\n %x", size, got, inner)
		}
	}
}

func TestUnwrapInitialContextTokenErrors(t *testing.T) {
	good := WrapInitialContextToken([]byte{0x01, 0x00})
	cases := map[string][]byte{
		"empty":          nil,
		"wrong tag":      {0x30, 0x0B, 0x06, 0x09},
		"truncated body": good[:len(good)-1],
		"indefinite len": {0x60, 0x80, 0x06, 0x09},
		"wrong mech OID": {0x60, 0x02, 0x06, 0x01},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := UnwrapInitialContextToken(b); err == nil {
				t.Errorf("Unwrap(%x): want error, got nil", b)
			}
		})
	}
}

func TestDERLengthRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 255, 256, 65535, 65536, 1 << 23} {
		enc := encodeDERLength(n)
		got, consumed, err := decodeDERLength(enc)
		if err != nil {
			t.Fatalf("n=%d decode: %v", n, err)
		}
		if got != n || consumed != len(enc) {
			t.Errorf("n=%d: decoded (%d, consumed %d) from %x", n, got, consumed, enc)
		}
	}
}

func TestDERLengthShortForm(t *testing.T) {
	// 127 must use the single-byte short form; 128 must switch to long form.
	if enc := encodeDERLength(127); len(enc) != 1 || enc[0] != 0x7F {
		t.Errorf("encodeDERLength(127) = %x, want 7f", enc)
	}
	if enc := encodeDERLength(128); !bytes.Equal(enc, []byte{0x81, 0x80}) {
		t.Errorf("encodeDERLength(128) = %x, want 8180", enc)
	}
}
