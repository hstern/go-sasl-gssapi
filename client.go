// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import (
	"errors"
	"fmt"

	"github.com/emersion/go-sasl"
	"github.com/hstern/krb5/crypto"
	"github.com/hstern/krb5/gssapi"
	"github.com/hstern/krb5/iana/chksumtype"
	"github.com/hstern/krb5/iana/flags"
	"github.com/hstern/krb5/iana/keyusage"
	"github.com/hstern/krb5/messages"
	"github.com/hstern/krb5/types"

	"github.com/hstern/go-sasl-gssapi/internal/gsstoken"
)

// Mechanism is the SASL mechanism name this client advertises.
const Mechanism = "GSSAPI"

// v0ContextFlags are the GSS context-establishment flags requested in the
// AP-REQ authenticator checksum. MUTUAL is mandatory (mutual auth is always
// performed); INTEG is required so the security-layer WrapTokens carry a
// verifiable integrity checksum; REPLAY and SEQUENCE match what conventional
// GSSAPI initiators request. CONF is omitted — v0 offers no confidentiality
// layer.
const v0ContextFlags = gsstoken.FlagMutual | gsstoken.FlagReplay | gsstoken.FlagSequence | gsstoken.FlagInteg

// Config configures a Client.
type Config struct {
	// Credential supplies the service ticket, session key, and client
	// principal. Required.
	Credential Credential

	// AuthzID is the optional authorization identity (authzid) sent in the
	// final security-layer message. Empty means authenticate as the ticket's
	// client principal.
	AuthzID string
}

// Client is the RFC 4752 SASL GSSAPI client (initiator). It implements
// github.com/emersion/go-sasl's Client interface, so it drops into go-imap and
// go-smtp. A Client is single-use: one authentication exchange per Client.
//
// v0 performs authentication only ("no security layer") with mandatory mutual
// authentication; transport confidentiality is expected from TLS.
type Client struct {
	cred    Credential
	authzID string

	step       int
	sessionKey types.EncryptionKey // ticket session key; decrypts the AP-REP
	ctxKey     types.EncryptionKey // per-message key: acceptor subkey or session key
}

// compile-time check that Client satisfies the SASL client contract.
var _ sasl.Client = (*Client)(nil)

// NewClient returns a Client ready to Start an authentication exchange.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Credential == nil {
		return nil, errors.New("saslgssapi: Config.Credential is required")
	}
	return &Client{cred: cfg.Credential, authzID: cfg.AuthzID}, nil
}

// Start begins the exchange. It returns the mechanism name and the GSSAPI
// initial-context token (the AP-REQ) as the SASL initial response.
func (c *Client) Start() (mech string, ir []byte, err error) {
	tkt, sessionKey, err := c.cred.ServiceTicket()
	if err != nil {
		return "", nil, fmt.Errorf("saslgssapi: obtaining service ticket: %w", err)
	}
	realm, cname := c.cred.ClientPrincipal()

	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		return "", nil, fmt.Errorf("saslgssapi: building authenticator: %w", err)
	}
	cksum, err := gsstoken.GSSChecksum{Flags: v0ContextFlags}.Marshal()
	if err != nil {
		return "", nil, fmt.Errorf("saslgssapi: building GSS checksum: %w", err)
	}
	auth.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: cksum}

	apReq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		return "", nil, fmt.Errorf("saslgssapi: building AP-REQ: %w", err)
	}
	// Mutual authentication is mandatory (design decision): require the
	// acceptor to answer with an AP-REP.
	types.SetFlag(&apReq.APOptions, flags.APOptionMutualRequired)

	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return "", nil, fmt.Errorf("saslgssapi: marshaling AP-REQ: %w", err)
	}

	inner := make([]byte, 0, len(gsstoken.TokIDAPReq)+len(apReqBytes))
	inner = append(inner, gsstoken.TokIDAPReq[:]...)
	inner = append(inner, apReqBytes...)

	c.sessionKey = sessionKey
	c.step = 1
	return Mechanism, gsstoken.WrapInitialContextToken(inner), nil
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
		return nil, fmt.Errorf("saslgssapi: unexpected server challenge after handshake completed")
	}
}

// verifyAPRep processes the acceptor's AP-REP: it confirms mutual authentication
// by decrypting EncAPRepPart with the session key, and captures the acceptor
// subkey (if any) as the per-message key. Per RFC 4752 §3.1 the client then
// emits an empty token before the security-layer exchange.
func (c *Client) verifyAPRep(challenge []byte) ([]byte, error) {
	inner := challenge
	// Only the initial token carries the generic 0x60 framing (RFC 4121 §4.1),
	// but tolerate an acceptor that wraps its AP-REP anyway.
	if len(inner) > 0 && inner[0] == 0x60 {
		var err error
		if inner, err = gsstoken.UnwrapInitialContextToken(inner); err != nil {
			return nil, fmt.Errorf("saslgssapi: unwrapping AP-REP token: %w", err)
		}
	}
	// Strip the AP-REP Tok_ID (02 00) if present.
	if len(inner) >= 2 && inner[0] == gsstoken.TokIDAPRep[0] && inner[1] == gsstoken.TokIDAPRep[1] {
		inner = inner[2:]
	}

	var apRep messages.APRep
	if err := apRep.Unmarshal(inner); err != nil {
		return nil, fmt.Errorf("saslgssapi: mutual authentication failed: parsing AP-REP: %w", err)
	}
	plain, err := crypto.DecryptEncPart(apRep.EncPart, c.sessionKey, uint32(keyusage.AP_REP_ENCPART))
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: mutual authentication failed: decrypting AP-REP: %w", err)
	}
	var encPart messages.EncAPRepPart
	if err := encPart.Unmarshal(plain); err != nil {
		return nil, fmt.Errorf("saslgssapi: mutual authentication failed: parsing EncAPRepPart: %w", err)
	}

	// The per-message tokens use the acceptor subkey when the acceptor supplied
	// one, otherwise the ticket session key.
	if len(encPart.Subkey.KeyValue) > 0 {
		c.ctxKey = encPart.Subkey
	} else {
		c.ctxKey = c.sessionKey
	}

	c.step = 2
	return []byte{}, nil
}

// negotiateSecurityLayer processes the acceptor's GSS-wrapped security-layer
// offer and returns the client's wrapped selection. v0 always selects the
// no-security-layer option.
func (c *Client) negotiateSecurityLayer(challenge []byte) ([]byte, error) {
	var wrapped gssapi.WrapToken
	if err := wrapped.Unmarshal(challenge, true); err != nil {
		return nil, fmt.Errorf("saslgssapi: parsing security-layer offer: %w", err)
	}
	if ok, err := wrapped.Verify(c.ctxKey, uint32(keyusage.GSSAPI_ACCEPTOR_SEAL)); !ok {
		return nil, fmt.Errorf("saslgssapi: security-layer offer failed integrity check: %w", err)
	}

	offer, err := gsstoken.ParseSecurityLayerOffer(wrapped.Payload)
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: %w", err)
	}
	if offer.Layers&gsstoken.LayerNone == 0 {
		return nil, fmt.Errorf("saslgssapi: acceptor does not offer the no-security-layer option (offered %#x)", byte(offer.Layers))
	}

	reply := gsstoken.ClientReply{Selected: gsstoken.LayerNone, AuthzID: c.authzID}
	payload, err := reply.Marshal()
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: building security-layer reply: %w", err)
	}
	out, err := gssapi.NewInitiatorWrapToken(payload, c.ctxKey)
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: wrapping security-layer reply: %w", err)
	}
	re, err := out.Marshal()
	if err != nil {
		return nil, fmt.Errorf("saslgssapi: marshaling security-layer reply: %w", err)
	}

	c.step = 3
	return re, nil
}
