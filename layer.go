// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import (
	"errors"
	"fmt"

	"github.com/hstern/krb5/gssapi"

	"github.com/hstern/go-sasl-gssapi/internal/seclayer"
)

// SecurityLayer identifies an RFC 4752 SASL security layer negotiated after
// authentication. Its value is the on-wire bit (RFC 4752 §3.3).
//
// v0.2.0 supports no-security-layer and integrity protection; confidentiality
// is planned once the substrate supports GSS sealing.
type SecurityLayer byte

const (
	// NoSecurityLayer is authentication only — application data is not wrapped.
	// It is the default and, over TLS, the recommended choice.
	NoSecurityLayer SecurityLayer = 1
	// IntegrityProtection wraps each application message with a GSS integrity
	// checksum (GSS_Wrap, conf=FALSE). Use Wrap/Unwrap after the handshake.
	IntegrityProtection SecurityLayer = 2
)

// defaultMaxBuffer is the maximum wrapped-message size each side advertises when
// a security layer is negotiated (bytes). It bounds the peer's Wrap output.
const defaultMaxBuffer = 65536

// wrapMessage wraps application data for a negotiated security layer. It errors
// if no layer (or the no-security-layer option) is in effect.
func wrapMessage(sc *gssapi.SecContext, layer SecurityLayer, peerMax uint32, p []byte) ([]byte, error) {
	if layer == 0 || layer == NoSecurityLayer {
		return nil, errors.New("saslgssapi: no security layer negotiated; Wrap is unavailable")
	}
	// IntegrityProtection uses GSS_Wrap with conf=FALSE (the only mode the
	// substrate supports today); confidentiality will select a sealed Wrap.
	wt, err := sc.Wrap(p)
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: wrapping message: %w", err)
	}
	out, err := wt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: marshaling wrapped message: %w", err)
	}
	if peerMax != 0 && uint32(len(out)) > peerMax {
		return nil, fmt.Errorf("saslgssapi: wrapped message is %d bytes, exceeds the peer's %d-byte buffer", len(out), peerMax)
	}
	return out, nil
}

// unwrapMessage reverses wrapMessage. fromAcceptor states whether the token is
// expected from the acceptor (true on the client, false on the server).
func unwrapMessage(sc *gssapi.SecContext, layer SecurityLayer, fromAcceptor bool, b []byte) ([]byte, error) {
	if layer == 0 || layer == NoSecurityLayer {
		return nil, errors.New("saslgssapi: no security layer negotiated; Unwrap is unavailable")
	}
	var wt gssapi.WrapToken
	if err := wt.Unmarshal(b, fromAcceptor); err != nil {
		return nil, fmt.Errorf("saslgssapi: parsing wrapped message: %w", err)
	}
	if ok, err := sc.Unwrap(&wt); !ok {
		return nil, fmt.Errorf("saslgssapi: wrapped message failed integrity check: %w", err)
	}
	return wt.Payload, nil
}

// selectLayer picks the strongest layer that is both offered by the peer and
// accepted by the caller, preferring stronger protection.
func selectLayer(offered seclayer.SecurityLayer, accepted []SecurityLayer) (SecurityLayer, error) {
	accepts := func(l SecurityLayer) bool {
		for _, a := range accepted {
			if a == l {
				return true
			}
		}
		return false
	}
	for _, l := range []SecurityLayer{IntegrityProtection, NoSecurityLayer} {
		if offered&seclayer.SecurityLayer(l) != 0 && accepts(l) {
			return l, nil
		}
	}
	return 0, fmt.Errorf("saslgssapi: no mutually supported security layer (peer offered %#x)", byte(offered))
}

// offeredMask folds a list of layers into the RFC 4752 offer bit-mask.
func offeredMask(layers []SecurityLayer) seclayer.SecurityLayer {
	var m seclayer.SecurityLayer
	for _, l := range layers {
		m |= seclayer.SecurityLayer(l)
	}
	return m
}
