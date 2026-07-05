// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package seclayer

import (
	"bytes"
	"testing"
)

func TestParseSecurityLayerOffer(t *testing.T) {
	// Server offers all three layers with a 1024-byte max buffer. The buffer
	// is big-endian: 0x00 0x04 0x00 = 1024.
	off, err := ParseSecurityLayerOffer([]byte{0x07, 0x00, 0x04, 0x00})
	if err != nil {
		t.Fatalf("ParseSecurityLayerOffer: %v", err)
	}
	wantLayers := LayerNone | LayerIntegrity | LayerConfidentiality
	if off.Layers != wantLayers {
		t.Errorf("Layers = %#x, want %#x", off.Layers, wantLayers)
	}
	if off.MaxBuffer != 1024 {
		t.Errorf("MaxBuffer = %d, want 1024", off.MaxBuffer)
	}
}

func TestParseSecurityLayerOfferWrongLength(t *testing.T) {
	for _, b := range [][]byte{nil, {0x01}, {0x01, 0x00, 0x00}, {0x01, 0, 0, 0, 0}} {
		if _, err := ParseSecurityLayerOffer(b); err == nil {
			t.Errorf("ParseSecurityLayerOffer(%x): want error, got nil", b)
		}
	}
}

func TestClientReplyMarshalVectors(t *testing.T) {
	cases := []struct {
		name  string
		reply ClientReply
		want  []byte
	}{
		{
			name:  "no security layer, no authzid",
			reply: ClientReply{Selected: LayerNone},
			want:  []byte{0x01, 0x00, 0x00, 0x00},
		},
		{
			name:  "no security layer with authzid",
			reply: ClientReply{Selected: LayerNone, AuthzID: "user"},
			want:  append([]byte{0x01, 0x00, 0x00, 0x00}, []byte("user")...),
		},
		{
			name:  "integrity layer with max buffer",
			reply: ClientReply{Selected: LayerIntegrity, MaxBuffer: 65536},
			want:  []byte{0x02, 0x01, 0x00, 0x00},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.reply.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("Marshal =\n %x\nwant\n %x", got, tc.want)
			}
		})
	}
}

func TestClientReplyMarshalErrors(t *testing.T) {
	cases := map[string]ClientReply{
		"no-layer with nonzero buffer": {Selected: LayerNone, MaxBuffer: 1},
		"max buffer overflows 24 bits": {Selected: LayerIntegrity, MaxBuffer: 1 << 24},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := r.Marshal(); err == nil {
				t.Errorf("Marshal(%+v): want error, got nil", r)
			}
		})
	}
}
