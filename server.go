// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import (
	"errors"
	"fmt"

	"github.com/emersion/go-sasl"
	"github.com/hstern/krb5/gssapi"
	"github.com/hstern/krb5/gssapi/krb5context"
	"github.com/hstern/krb5/keytab"

	"github.com/hstern/go-sasl-gssapi/internal/seclayer"
)

// ServerConfig configures a Server.
type ServerConfig struct {
	// Keytab holds the service's long-term key(s); the acceptor decrypts the
	// client's AP-REQ ticket with it. Required.
	Keytab *keytab.Keytab

	// Layers is the set of security layers the server offers. Empty (the
	// default) means NoSecurityLayer only. Offering IntegrityProtection lets a
	// client select it (then Wrap/Unwrap protect application data); include
	// NoSecurityLayer to keep no-layer clients working.
	Layers []SecurityLayer
}

// Server is the RFC 4752 SASL GSSAPI acceptor (server). It implements
// github.com/emersion/go-sasl's Server interface and mirrors Client: the
// Kerberos GSS context is handled by hstern/krb5's krb5context.Acceptor, and
// this type adds the RFC 4752 SASL framing and the security-layer negotiation.
//
// It performs mandatory mutual authentication and negotiates a security layer
// (no-security-layer by default, or integrity when both ends support it, in
// which case Wrap/Unwrap protect application data). A Server is single-use.
// After a successful exchange, Complete reports true and ClientName / AuthzID
// return the authenticated identity.
type Server struct {
	acceptor *krb5context.Acceptor
	secCtx   *gssapi.SecContext
	offered  seclayer.SecurityLayer

	step       int
	clientName string
	authzID    string
	layer      SecurityLayer
	peerMax    uint32
	complete   bool
}

// compile-time check that Server satisfies the SASL server contract.
var _ sasl.Server = (*Server)(nil)

// NewServer returns a Server ready to accept an authentication exchange.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Keytab == nil {
		return nil, errors.New("saslgssapi: ServerConfig.Keytab is required")
	}
	layers := cfg.Layers
	if len(layers) == 0 {
		layers = []SecurityLayer{NoSecurityLayer}
	}
	return &Server{
		acceptor: krb5context.NewAcceptor(cfg.Keytab),
		offered:  offeredMask(layers),
	}, nil
}

// Next advances the acceptor. It is called with the client's AP-REQ (returning
// the AP-REP), then the client's empty token (returning the GSS-wrapped
// security-layer offer), then the client's wrapped selection (completing the
// exchange with done == true).
func (s *Server) Next(response []byte) (challenge []byte, done bool, err error) {
	switch s.step {
	case 0:
		return s.acceptAPReq(response)
	case 1:
		return s.offerSecurityLayer(response)
	case 2:
		return s.finish(response)
	default:
		return nil, false, errors.New("saslgssapi: unexpected client response after authentication completed")
	}
}

// acceptAPReq verifies the client's AP-REQ against the keytab, establishes the
// security context, and returns the AP-REP for mutual authentication.
func (s *Server) acceptAPReq(response []byte) ([]byte, bool, error) {
	apRep, gssDone, err := s.acceptor.AcceptSecContext(response)
	if err != nil {
		return nil, false, fmt.Errorf("saslgssapi: accepting AP-REQ: %w", err)
	}
	if !gssDone {
		return nil, false, errors.New("saslgssapi: acceptor did not complete on the AP-REQ")
	}
	sc, err := s.acceptor.Context()
	if err != nil {
		return nil, false, fmt.Errorf("saslgssapi: obtaining security context: %w", err)
	}
	s.secCtx = sc
	if creds := s.acceptor.Credentials(); creds != nil {
		s.clientName = creds.DisplayName()
	}
	s.step = 1
	return apRep, false, nil
}

// offerSecurityLayer consumes the client's empty post-AP-REP token and returns
// the GSS-wrapped offer of the configured security layers.
func (s *Server) offerSecurityLayer(response []byte) ([]byte, bool, error) {
	if len(response) != 0 {
		return nil, false, fmt.Errorf("saslgssapi: expected an empty token before the security-layer offer, got %d bytes", len(response))
	}
	var maxBuf uint32
	if s.offered&^seclayer.SecurityLayer(NoSecurityLayer) != 0 {
		maxBuf = defaultMaxBuffer // the largest wrapped message we can receive
	}
	payload, err := seclayer.SecurityLayerOffer{Layers: s.offered, MaxBuffer: maxBuf}.Marshal()
	if err != nil {
		return nil, false, fmt.Errorf("saslgssapi: %w", err)
	}
	wrapped, err := s.secCtx.Wrap(payload)
	if err != nil {
		return nil, false, fmt.Errorf("saslgssapi: wrapping security-layer offer: %w", err)
	}
	out, err := wrapped.Marshal()
	if err != nil {
		return nil, false, fmt.Errorf("saslgssapi: marshaling security-layer offer: %w", err)
	}
	s.step = 2
	return out, false, nil
}

// finish unwraps and validates the client's security-layer selection, captures
// the authorization identity, and completes the exchange.
func (s *Server) finish(response []byte) ([]byte, bool, error) {
	var wt gssapi.WrapToken
	if err := wt.Unmarshal(response, false); err != nil {
		return nil, false, fmt.Errorf("saslgssapi: parsing security-layer reply: %w", err)
	}
	if ok, err := s.secCtx.Unwrap(&wt); !ok {
		return nil, false, fmt.Errorf("saslgssapi: security-layer reply failed integrity check: %w", err)
	}
	reply, err := seclayer.ParseClientReply(wt.Payload)
	if err != nil {
		return nil, false, fmt.Errorf("saslgssapi: %w", err)
	}
	// The client must select exactly one layer we offered.
	if reply.Selected&s.offered == 0 || reply.Selected&(reply.Selected-1) != 0 {
		return nil, false, fmt.Errorf("saslgssapi: client selected security layer %#x, not among the offered %#x", byte(reply.Selected), byte(s.offered))
	}
	s.layer = SecurityLayer(reply.Selected)
	s.peerMax = reply.MaxBuffer
	s.authzID = reply.AuthzID
	s.complete = true
	s.step = 3
	return nil, true, nil
}

// SecurityLayer returns the security layer negotiated during the handshake.
// Meaningful only after Complete reports true.
func (s *Server) SecurityLayer() SecurityLayer { return s.layer }

// Wrap protects an application message under the negotiated security layer,
// returning the token to send to the client. It errors when no security layer
// was negotiated.
func (s *Server) Wrap(p []byte) ([]byte, error) {
	return wrapMessage(s.secCtx, s.layer, s.peerMax, p)
}

// Unwrap reverses Wrap for a token received from the client. The returned slice
// shares storage with b; copy it before reusing or mutating b if you need to
// retain the plaintext.
func (s *Server) Unwrap(b []byte) ([]byte, error) {
	return unwrapMessage(s.secCtx, s.layer, false, b)
}

// ClientName returns the authenticated client principal (e.g. "alice@REALM").
// It is meaningful only after Complete reports true.
func (s *Server) ClientName() string { return s.clientName }

// AuthzID returns the authorization identity the client requested. An empty
// value means the client principal. Meaningful only after Complete reports true.
func (s *Server) AuthzID() string { return s.authzID }

// Complete reports whether the authentication exchange finished successfully.
func (s *Server) Complete() bool { return s.complete }
