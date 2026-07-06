// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import (
	"errors"
	"fmt"

	"github.com/emersion/go-sasl"
	"github.com/hstern/krb5/client"
	"github.com/hstern/krb5/gssapi"
	"github.com/hstern/krb5/gssapi/krb5context"

	"github.com/hstern/go-sasl-gssapi/internal/seclayer"
)

// Mechanism is the SASL mechanism name this client advertises.
const Mechanism = "GSSAPI"

// Config configures a Client.
type Config struct {
	// Client is the Kerberos client holding the credential — typically from
	// FromCCache, or built directly with client.NewFromCCache. Required.
	Client *client.Client

	// Service is the target service principal name (SPN), e.g.
	// "imap/mail.example.com" or "imap/mail.example.com@EXAMPLE.COM". Required.
	Service string

	// AuthzID is the optional authorization identity (authzid) sent in the
	// final security-layer message. Empty means authenticate as the ticket's
	// client principal.
	AuthzID string

	// Layers is the set of security layers the client is willing to use, in
	// addition to what the server offers. The client selects the strongest layer
	// offered by both. Empty (the default) means NoSecurityLayer only. Include
	// NoSecurityLayer as a fallback alongside IntegrityProtection.
	Layers []SecurityLayer
}

// Client is the RFC 4752 SASL GSSAPI client (initiator). It implements
// github.com/emersion/go-sasl's Client interface, so it drops into go-imap and
// go-smtp. A Client is single-use: one authentication exchange per Client.
//
// It performs mandatory mutual authentication and negotiates a security layer:
// no-security-layer by default (authentication only, confidentiality from TLS),
// or integrity protection when both ends support it — in which case Wrap/Unwrap
// protect application data after the handshake. The Kerberos GSS context
// establishment (AP-REQ / AP-REP / the RFC 4121 checksum) is handled by
// github.com/hstern/krb5's krb5context.Initiator; this type adds the RFC 4752
// SASL framing and the security-layer negotiation on top.
type Client struct {
	initiator *krb5context.Initiator
	authzID   string
	layers    []SecurityLayer

	step    int
	secCtx  *gssapi.SecContext
	layer   SecurityLayer
	peerMax uint32
}

// compile-time check that Client satisfies the SASL client contract.
var _ sasl.Client = (*Client)(nil)

// NewClient returns a Client ready to Start an authentication exchange.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Client == nil {
		return nil, errors.New("saslgssapi: Config.Client is required")
	}
	if cfg.Service == "" {
		return nil, errors.New("saslgssapi: Config.Service is required")
	}
	layers := cfg.Layers
	if len(layers) == 0 {
		layers = []SecurityLayer{NoSecurityLayer}
	}
	return &Client{
		initiator: krb5context.NewInitiator(cfg.Client, cfg.Service),
		authzID:   cfg.AuthzID,
		layers:    layers,
	}, nil
}

// Start begins the exchange. It returns the mechanism name and the GSSAPI
// initial-context token (the AP-REQ) as the SASL initial response.
func (c *Client) Start() (mech string, ir []byte, err error) {
	out, _, err := c.initiator.InitSecContext(nil)
	if err != nil {
		return "", nil, fmt.Errorf("saslgssapi: building initial-context token: %w", err)
	}
	c.step = 1
	return Mechanism, out, nil
}

// Next continues the exchange. It is called twice: first with the acceptor's
// AP-REP (returning an empty token), then with the GSS-wrapped security-layer
// offer (returning the wrapped selection).
func (c *Client) Next(challenge []byte) ([]byte, error) {
	switch c.step {
	case 1:
		return c.verifyAPRep(challenge)
	case 2:
		return c.negotiateSecurityLayer(challenge)
	default:
		return nil, errors.New("saslgssapi: unexpected server challenge after handshake completed")
	}
}

// verifyAPRep feeds the acceptor's AP-REP to the initiator, which confirms
// mutual authentication and establishes the security context. Per RFC 4752
// §3.1 the client then emits an empty token before the security-layer exchange.
func (c *Client) verifyAPRep(challenge []byte) ([]byte, error) {
	_, done, err := c.initiator.InitSecContext(challenge)
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: mutual authentication failed: %w", err)
	}
	if !done {
		return nil, errors.New("saslgssapi: security context not established after AP-REP")
	}
	sc, err := c.initiator.Context()
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: obtaining security context: %w", err)
	}
	c.secCtx = sc
	c.step = 2
	return []byte{}, nil
}

// negotiateSecurityLayer processes the acceptor's GSS-wrapped security-layer
// offer, selects the strongest mutually supported layer, and returns the
// client's wrapped selection.
func (c *Client) negotiateSecurityLayer(challenge []byte) ([]byte, error) {
	var offer gssapi.WrapToken
	if err := offer.Unmarshal(challenge, true); err != nil {
		return nil, fmt.Errorf("saslgssapi: parsing security-layer offer: %w", err)
	}
	if ok, err := c.secCtx.Unwrap(&offer); !ok {
		return nil, fmt.Errorf("saslgssapi: security-layer offer failed integrity check: %w", err)
	}
	parsed, err := seclayer.ParseSecurityLayerOffer(offer.Payload)
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: %w", err)
	}

	selected, err := selectLayer(parsed.Layers, c.layers)
	if err != nil {
		return nil, err
	}

	var maxBuf uint32
	if selected != NoSecurityLayer {
		maxBuf = defaultMaxBuffer // the largest wrapped message we can receive
	}
	reply := seclayer.ClientReply{
		Selected:  seclayer.SecurityLayer(selected),
		MaxBuffer: maxBuf,
		AuthzID:   c.authzID,
	}
	payload, err := reply.Marshal()
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: building security-layer reply: %w", err)
	}
	wrapped, err := c.secCtx.Wrap(payload)
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: wrapping security-layer reply: %w", err)
	}
	out, err := wrapped.Marshal()
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: marshaling security-layer reply: %w", err)
	}

	c.layer = selected
	c.peerMax = parsed.MaxBuffer
	c.step = 3
	return out, nil
}

// SecurityLayer returns the security layer negotiated during the handshake. It
// is meaningful only after the exchange completes.
func (c *Client) SecurityLayer() SecurityLayer { return c.layer }

// Wrap protects an application message under the negotiated security layer,
// returning the token to send to the peer. It errors when no security layer was
// negotiated (the no-security-layer case).
func (c *Client) Wrap(p []byte) ([]byte, error) {
	return wrapMessage(c.secCtx, c.layer, c.peerMax, p)
}

// Unwrap reverses Wrap for a token received from the server. The returned slice
// shares storage with b; copy it before reusing or mutating b if you need to
// retain the plaintext.
func (c *Client) Unwrap(b []byte) ([]byte, error) {
	return unwrapMessage(c.secCtx, c.layer, true, b)
}
