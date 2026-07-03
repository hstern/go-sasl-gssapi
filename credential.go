// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import (
	"errors"
	"fmt"

	"github.com/hstern/krb5/credentials"
	"github.com/hstern/krb5/messages"
	"github.com/hstern/krb5/types"
)

// Credential supplies the holder-of-key material the client needs to build the
// AP-REQ: the initiator's own principal (for the authenticator) plus the
// service ticket and the session key that seals it.
//
// It is deliberately provenance-agnostic. FromCCache adapts an MIT credential
// cache, but a ticket minted out-of-band — by an OAuth2-to-Kerberos exchange,
// or read straight from a KRB5CCNAME file — can implement this interface
// directly.
//
// The interface exposes github.com/hstern/krb5 types (messages.Ticket,
// types.EncryptionKey, types.PrincipalName). That coupling is intentional and
// load-bearing: swapping the Kerberos substrate is a breaking change (see the
// module's design notes), not an internal refactor.
type Credential interface {
	// ClientPrincipal returns the initiator's realm and principal name, used as
	// the CRealm and CName of the AP-REQ authenticator.
	ClientPrincipal() (realm string, cname types.PrincipalName)

	// ServiceTicket returns the service ticket for the target service and the
	// session key used to seal the authenticator inside the AP-REQ.
	ServiceTicket() (messages.Ticket, types.EncryptionKey, error)
}

// ccacheCredential adapts a resolved MIT credential-cache entry to Credential.
// Resolution (locating the service ticket, unmarshaling it) happens once in
// FromCCache, so the accessors cannot fail.
type ccacheCredential struct {
	realm  string
	cname  types.PrincipalName
	ticket messages.Ticket
	key    types.EncryptionKey
}

func (c *ccacheCredential) ClientPrincipal() (string, types.PrincipalName) {
	return c.realm, c.cname
}

func (c *ccacheCredential) ServiceTicket() (messages.Ticket, types.EncryptionKey, error) {
	return c.ticket, c.key, nil
}

// FromCCache adapts an MIT credential cache to a Credential for the given
// service principal name (SPN), e.g. "imap/mail.example.com" or
// "imap/mail.example.com@EXAMPLE.COM". This is the holder-of-key path: the
// ccache is expected to already hold the service ticket and its session key, so
// no KDC is contacted.
//
// The returned Credential draws the initiator identity from the ccache's
// default principal.
func FromCCache(cc *credentials.CCache, spn string) (Credential, error) {
	if cc == nil {
		return nil, errors.New("saslgssapi: nil credential cache")
	}
	// ParseSPNString drops any @REALM suffix; GetEntry matches on the service
	// name components only, which is what a ccache stores.
	sname, _ := types.ParseSPNString(spn)
	entry, ok := cc.GetEntry(sname)
	if !ok {
		return nil, fmt.Errorf("saslgssapi: no service ticket for %q in credential cache", spn)
	}

	var tkt messages.Ticket
	if err := tkt.Unmarshal(entry.Ticket); err != nil {
		return nil, fmt.Errorf("saslgssapi: unmarshaling service ticket for %q: %w", spn, err)
	}

	return &ccacheCredential{
		realm:  cc.GetClientRealm(),
		cname:  cc.GetClientPrincipalName(),
		ticket: tkt,
		key:    entry.Key,
	}, nil
}
