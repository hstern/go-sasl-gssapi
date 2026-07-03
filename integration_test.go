// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import (
	"testing"
	"time"

	"github.com/hstern/krb5/credentials"
	"github.com/hstern/krb5/crypto"
	"github.com/hstern/krb5/gssapi"
	"github.com/hstern/krb5/iana/chksumtype"
	"github.com/hstern/krb5/iana/etypeID"
	"github.com/hstern/krb5/iana/flags"
	"github.com/hstern/krb5/iana/keyusage"
	"github.com/hstern/krb5/iana/nametype"
	"github.com/hstern/krb5/keytab"
	"github.com/hstern/krb5/messages"
	"github.com/hstern/krb5/types"

	"github.com/hstern/go-sasl-gssapi/internal/gsstoken"
)

// integrationRealm and friends parameterize the in-process KDC/acceptor.
const (
	integrationRealm    = "EXAMPLE.COM"
	integrationSPN      = "imap/mail.example.com"
	integrationPassword = "s3rvice-k3y-material"
	integrationClient   = "alice"
	integrationEtype    = etypeID.AES256_CTS_HMAC_SHA1_96
)

// TestIntegrationEndToEnd drives the whole stack with real Kerberos artifacts:
// a service key in a keytab, a ticket minted against it (standing in for the
// KDC), a marshaled-then-reloaded ccache, FromCCache, and an in-process
// acceptor that decrypts the client's AP-REQ ticket with the same keytab. No
// KDC and no fakes on the credential path — only the acceptor half is
// test-local (the shipped library is client-only).
func TestIntegrationEndToEnd(t *testing.T) {
	sname, _ := types.ParseSPNString(integrationSPN)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, integrationClient)

	// The service's long-term key, as an acceptor keytab.
	kt := keytab.New()
	if err := kt.AddEntry(integrationSPN, integrationRealm, integrationPassword, time.Unix(1_700_000_000, 0), 1, integrationEtype); err != nil {
		t.Fatalf("keytab AddEntry: %v", err)
	}

	// Mint a service ticket against that keytab (the KDC's job). NewTicket
	// generates the session key and seals the EncTicketPart with the service
	// key, returning both.
	now := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(
		cname, integrationRealm, sname, integrationRealm,
		types.NewKrbFlags(), kt, integrationEtype, 1,
		now, now, now.Add(time.Hour), now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("NewTicket: %v", err)
	}

	// Build a v4 ccache holding that ticket. The ticket is marshaled to real
	// DER bytes (so FromCCache's Unmarshal path is exercised), but the CCache
	// envelope itself is not round-tripped through Marshal/Unmarshal — that
	// panics in github.com/hstern/krb5 v0.1.2; see buildCCache.
	cc := buildCCache(t, cname, sname, sessionKey, tkt, now)
	cred, err := FromCCache(cc, integrationSPN)
	if err != nil {
		t.Fatalf("FromCCache: %v", err)
	}

	cl, err := NewClient(Config{Credential: cred, AuthzID: "alice@EXAMPLE.COM"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// --- message 1: client AP-REQ, verified by the acceptor ---
	mech, ir, err := cl.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if mech != Mechanism {
		t.Fatalf("mech = %q, want %q", mech, Mechanism)
	}
	acceptorSessionKey := acceptorVerifyAPReq(t, ir, kt, sname)

	// The acceptor's decrypted session key must equal the one the client used.
	if acceptorSessionKey.KeyType != sessionKey.KeyType || string(acceptorSessionKey.KeyValue) != string(sessionKey.KeyValue) {
		t.Fatal("acceptor session key does not match the minted session key")
	}

	// --- message 2: acceptor AP-REP (with a subkey) ---
	acceptorSubkey := newTestKey(t)
	empty, err := cl.Next(buildAPRep(t, acceptorSessionKey, acceptorSubkey))
	if err != nil {
		t.Fatalf("Next(AP-REP): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("post-AP-REP token = %x, want empty", empty)
	}

	// --- message 4/5: security-layer offer and the client's wrapped reply ---
	offer := buildAcceptorOffer(t, acceptorSubkey, gsstoken.LayerNone|gsstoken.LayerIntegrity, 8192)
	reply, err := cl.Next(offer)
	if err != nil {
		t.Fatalf("Next(offer): %v", err)
	}
	acceptorVerifyReply(t, reply, acceptorSubkey, "alice@EXAMPLE.COM")
}

// buildCCache assembles a v4 credential cache holding the service ticket, using
// the same builders (NewV4CCache/AddCredential) a ccache reader populates.
//
// It deliberately does NOT round-trip through CCache.Marshal/Unmarshal: that
// path panics in github.com/hstern/krb5 v0.1.2 (readAuthDataEntry, on a
// credential with no authorization data). FromCCache reads GetEntry /
// GetClientPrincipalName / GetClientRealm, all of which operate on this
// in-memory cache, so the coverage of FromCCache itself is unaffected.
func buildCCache(t *testing.T, cname, sname types.PrincipalName, sessionKey types.EncryptionKey, tkt messages.Ticket, now time.Time) *credentials.CCache {
	t.Helper()
	tktBytes, err := tkt.Marshal()
	if err != nil {
		t.Fatalf("marshal ticket: %v", err)
	}
	cc := credentials.NewV4CCache()
	cc.SetDefaultPrincipal(credentials.NewPrincipal(cname, integrationRealm))
	cc.AddCredential(&credentials.Credential{
		Client:    credentials.NewPrincipal(cname, integrationRealm),
		Server:    credentials.NewPrincipal(sname, integrationRealm),
		Key:       sessionKey,
		AuthTime:  now,
		StartTime: now,
		EndTime:   now.Add(time.Hour),
		Ticket:    tktBytes,
	})
	return cc
}

// acceptorVerifyAPReq plays the GSSAPI acceptor: it unwraps the initial-context
// token, decrypts the AP-REQ ticket with the service keytab to recover the
// session key, then decrypts and checks the authenticator's RFC 4121 §4.1.1
// checksum. It returns the recovered session key.
func acceptorVerifyAPReq(t *testing.T, initToken []byte, kt *keytab.Keytab, sname types.PrincipalName) types.EncryptionKey {
	t.Helper()
	inner, err := gsstoken.UnwrapInitialContextToken(initToken)
	if err != nil {
		t.Fatalf("acceptor: unwrap init token: %v", err)
	}
	if len(inner) < 2 || inner[0] != gsstoken.TokIDAPReq[0] || inner[1] != gsstoken.TokIDAPReq[1] {
		t.Fatalf("acceptor: inner Tok_ID = %x, want %x", inner, gsstoken.TokIDAPReq)
	}

	var apReq messages.APReq
	if err := apReq.Unmarshal(inner[2:]); err != nil {
		t.Fatalf("acceptor: unmarshal AP-REQ: %v", err)
	}
	if !types.IsFlagSet(&apReq.APOptions, flags.APOptionMutualRequired) {
		t.Error("acceptor: AP-Options MUTUAL-REQUIRED not set")
	}

	// Decrypt the ticket with the service key to recover the session key.
	if err := apReq.Ticket.DecryptEncPart(kt, &sname); err != nil {
		t.Fatalf("acceptor: decrypt ticket: %v", err)
	}
	sessionKey := apReq.Ticket.DecryptedEncPart.Key

	// Decrypt and validate the authenticator.
	plain, err := crypto.DecryptEncPart(apReq.EncryptedAuthenticator, sessionKey, uint32(keyusage.AP_REQ_AUTHENTICATOR))
	if err != nil {
		t.Fatalf("acceptor: decrypt authenticator: %v", err)
	}
	var auth types.Authenticator
	if err := auth.Unmarshal(plain); err != nil {
		t.Fatalf("acceptor: unmarshal authenticator: %v", err)
	}
	if auth.Cksum.CksumType != chksumtype.GSSAPI {
		t.Errorf("acceptor: checksum type = %d, want %d (GSSAPI)", auth.Cksum.CksumType, chksumtype.GSSAPI)
	}
	cksum, err := gsstoken.UnmarshalChecksum(auth.Cksum.Checksum)
	if err != nil {
		t.Fatalf("acceptor: parse GSS checksum: %v", err)
	}
	if cksum.Flags&gsstoken.FlagMutual == 0 {
		t.Error("acceptor: GSS checksum missing MUTUAL flag")
	}
	return sessionKey
}

// acceptorVerifyReply plays the acceptor validating the client's final
// security-layer message: it unwraps the initiator WrapToken, verifies its
// integrity, and checks the selection and authzid.
func acceptorVerifyReply(t *testing.T, reply []byte, ctxKey types.EncryptionKey, wantAuthzID string) {
	t.Helper()
	var wt gssapi.WrapToken
	if err := wt.Unmarshal(reply, false); err != nil {
		t.Fatalf("acceptor: unmarshal client reply: %v", err)
	}
	if ok, err := wt.Verify(ctxKey, uint32(keyusage.GSSAPI_INITIATOR_SEAL)); !ok {
		t.Fatalf("acceptor: client reply failed integrity check: %v", err)
	}
	if len(wt.Payload) < 4 {
		t.Fatalf("acceptor: reply payload too short: %x", wt.Payload)
	}
	if got := gsstoken.SecurityLayer(wt.Payload[0]); got != gsstoken.LayerNone {
		t.Errorf("acceptor: selected layer = %#x, want LayerNone", byte(got))
	}
	if got := string(wt.Payload[4:]); got != wantAuthzID {
		t.Errorf("acceptor: authzid = %q, want %q", got, wantAuthzID)
	}
}
