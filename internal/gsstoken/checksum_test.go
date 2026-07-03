// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package gsstoken

import (
	"bytes"
	"testing"
)

// The v0 flag word: MUTUAL|REPLAY|SEQUENCE|INTEG. Pinned here because it is the
// exact set the client requests, and a wrong-endian encoding of it is the
// classic GSSAPI interop bug.
const v0Flags = FlagMutual | FlagReplay | FlagSequence | FlagInteg

func TestGSSChecksumMarshalV0Vector(t *testing.T) {
	c := GSSChecksum{Flags: v0Flags} // Bnd left zero: no channel binding.
	got, err := c.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := []byte{
		0x10, 0x00, 0x00, 0x00, // Lgth = 16, little-endian
		0, 0, 0, 0, 0, 0, 0, 0, // Bnd: 16 zero octets
		0, 0, 0, 0, 0, 0, 0, 0,
		0x2E, 0x00, 0x00, 0x00, // Flags = 0x2E, little-endian
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Marshal =\n %x\nwant\n %x", got, want)
	}
}

func TestGSSChecksumRoundTrip(t *testing.T) {
	cases := map[string]GSSChecksum{
		"v0 flags, zero bnd": {Flags: v0Flags},
		"nonzero bnd": {
			Bnd:   [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Flags: FlagMutual,
		},
		"with delegation": {
			Flags: FlagMutual | FlagDeleg,
			Deleg: []byte("delegated-cred-blob"),
		},
		"deleg flag, empty blob": {Flags: FlagDeleg},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b, err := c.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			got, err := UnmarshalChecksum(b)
			if err != nil {
				t.Fatalf("UnmarshalChecksum: %v", err)
			}
			if got.Bnd != c.Bnd || got.Flags != c.Flags || !bytes.Equal(got.Deleg, c.Deleg) {
				t.Errorf("round-trip = %+v, want %+v", got, c)
			}
			// Marshal(Unmarshal(b)) must reproduce b byte-for-byte.
			reb, err := got.Marshal()
			if err != nil {
				t.Fatalf("re-Marshal: %v", err)
			}
			if !bytes.Equal(reb, b) {
				t.Errorf("re-Marshal =\n %x\nwant\n %x", reb, b)
			}
		})
	}
}

func TestGSSChecksumMarshalErrors(t *testing.T) {
	t.Run("deleg without flag", func(t *testing.T) {
		if _, err := (GSSChecksum{Deleg: []byte("x")}).Marshal(); err == nil {
			t.Fatal("want error, got nil")
		}
	})
}

func TestUnmarshalChecksumErrors(t *testing.T) {
	valid, err := GSSChecksum{Flags: v0Flags}.Marshal()
	if err != nil {
		t.Fatalf("setup Marshal: %v", err)
	}
	cases := map[string][]byte{
		"empty":                  nil,
		"too short for Lgth":     {0x10, 0x00},
		"wrong Bnd length":       append([]byte{0x08, 0x00, 0x00, 0x00}, make([]byte, checksumMinLen-4)...),
		"trailing without deleg": append(bytes.Clone(valid), 0xFF),
		"Lgth overruns buffer":   {0xFF, 0xFF, 0xFF, 0xFF, 0x00},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := UnmarshalChecksum(b); err == nil {
				t.Errorf("UnmarshalChecksum(%x): want error, got nil", b)
			}
		})
	}
}
