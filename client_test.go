// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	xasn1 "github.com/hstern/x/encoding/asn1"

	"github.com/hstern/krb5/credentials"
	"github.com/hstern/krb5/crypto"
	"github.com/hstern/krb5/gssapi"
	"github.com/hstern/krb5/iana"
	"github.com/hstern/krb5/iana/asn1apptag"
	"github.com/hstern/krb5/iana/chksumtype"
	"github.com/hstern/krb5/iana/etypeID"
	"github.com/hstern/krb5/iana/flags"
	"github.com/hstern/krb5/iana/keyusage"
	"github.com/hstern/krb5/iana/msgtype"
	"github.com/hstern/krb5/iana/nametype"
	"github.com/hstern/krb5/messages"
	"github.com/hstern/krb5/types"

	"github.com/hstern/go-sasl-gssapi/internal/gsstoken"
)

// newTestKey returns an aes256-cts-hmac-sha1-96 key with random material. The
// key bytes are used directly (no string-to-key), which is all the AP-REP and
// WrapToken crypto in these tests needs.
func newTestKey(t *testing.T) types.EncryptionKey {
	t.Helper()
	kv := make([]byte, 32)
	if _, err := rand.Read(kv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: kv}
}

// newTestCredential builds a Credential over a synthetic service ticket. The
// ticket's encrypted part is opaque — the client never decrypts it — so any
// bytes suffice; only the session key and client principal are load-bearing.
func newTestCredential(t *testing.T, sessionKey types.EncryptionKey) *fakeCredential {
	t.Helper()
	return &fakeCredential{
		realm: "EXAMPLE.COM",
		cname: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"),
		ticket: messages.Ticket{
			TktVNO:  iana.PVNO,
			Realm:   "EXAMPLE.COM",
			SName:   types.NewPrincipalName(nametype.KRB_NT_SRV_HST, "imap/mail.example.com"),
			EncPart: types.EncryptedData{EType: sessionKey.KeyType, KVNO: 1, Cipher: []byte("opaque")},
		},
		key: sessionKey,
	}
}

type fakeCredential struct {
	realm  string
	cname  types.PrincipalName
	ticket messages.Ticket
	key    types.EncryptionKey
}

func (f *fakeCredential) ClientPrincipal() (string, types.PrincipalName) { return f.realm, f.cname }
func (f *fakeCredential) ServiceTicket() (messages.Ticket, types.EncryptionKey, error) {
	return f.ticket, f.key, nil
}

// buildAPRep hand-builds the acceptor's AP-REP: it marshals an EncAPRepPart
// (carrying an acceptor subkey), encrypts it under the session key, and wraps
// it in an AP-REP. gokrb5's messages package has no AP-REP marshaler, so this
// mirrors what a real acceptor emits.
func buildAPRep(t *testing.T, sessionKey, acceptorSubkey types.EncryptionKey) []byte {
	t.Helper()
	encPart := messages.EncAPRepPart{
		CTime:          time.Unix(1_700_000_000, 0).UTC(),
		Cusec:          123,
		Subkey:         acceptorSubkey,
		SequenceNumber: 42,
	}
	epb, err := xasn1.MarshalWithParams(encPart, fmt.Sprintf("application,explicit,tag:%d", asn1apptag.EncAPRepPart))
	if err != nil {
		t.Fatalf("marshal EncAPRepPart: %v", err)
	}
	ed, err := crypto.GetEncryptedData(epb, sessionKey, uint32(keyusage.AP_REP_ENCPART), 0)
	if err != nil {
		t.Fatalf("encrypt EncAPRepPart: %v", err)
	}
	apRep := messages.APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: ed}
	b, err := xasn1.MarshalWithParams(apRep, fmt.Sprintf("application,explicit,tag:%d", asn1apptag.APREP))
	if err != nil {
		t.Fatalf("marshal AP-REP: %v", err)
	}
	return b
}

// buildAcceptorOffer hand-builds the acceptor's GSS-wrapped security-layer
// offer: a 4-byte {layer-mask, 24-bit max-buffer} payload in an acceptor
// WrapToken keyed with the context key.
func buildAcceptorOffer(t *testing.T, ctxKey types.EncryptionKey, layers gsstoken.SecurityLayer, maxBuf uint32) []byte {
	t.Helper()
	payload := []byte{byte(layers), byte(maxBuf >> 16), byte(maxBuf >> 8), byte(maxBuf)}
	wt := gssapi.WrapToken{Flags: 0x01, Payload: payload} // 0x01 = from acceptor
	if err := wt.SetCheckSum(ctxKey, uint32(keyusage.GSSAPI_ACCEPTOR_SEAL)); err != nil {
		t.Fatalf("acceptor SetCheckSum: %v", err)
	}
	wt.EC = uint16(len(wt.CheckSum))
	b, err := wt.Marshal()
	if err != nil {
		t.Fatalf("marshal acceptor WrapToken: %v", err)
	}
	return b
}

func TestNewClientRequiresCredential(t *testing.T) {
	if _, err := NewClient(Config{}); err == nil {
		t.Fatal("NewClient with no Credential: want error, got nil")
	}
}

func TestStartInitialToken(t *testing.T) {
	sessionKey := newTestKey(t)
	cl, err := NewClient(Config{Credential: newTestCredential(t, sessionKey)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	mech, ir, err := cl.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if mech != Mechanism {
		t.Errorf("mech = %q, want %q", mech, Mechanism)
	}

	inner, err := gsstoken.UnwrapInitialContextToken(ir)
	if err != nil {
		t.Fatalf("unwrap initial token: %v", err)
	}
	if inner[0] != gsstoken.TokIDAPReq[0] || inner[1] != gsstoken.TokIDAPReq[1] {
		t.Fatalf("inner Tok_ID = %x, want %x", inner[:2], gsstoken.TokIDAPReq)
	}

	var apReq messages.APReq
	if err := apReq.Unmarshal(inner[2:]); err != nil {
		t.Fatalf("unmarshal AP-REQ: %v", err)
	}
	if !types.IsFlagSet(&apReq.APOptions, flags.APOptionMutualRequired) {
		t.Error("AP-Options MUTUAL-REQUIRED not set")
	}

	// Decrypt the authenticator and confirm it carries the exact 0x8003 GSS
	// checksum with the v0 flag word.
	plain, err := crypto.DecryptEncPart(apReq.EncryptedAuthenticator, sessionKey, uint32(keyusage.AP_REQ_AUTHENTICATOR))
	if err != nil {
		t.Fatalf("decrypt authenticator: %v", err)
	}
	var auth types.Authenticator
	if err := auth.Unmarshal(plain); err != nil {
		t.Fatalf("unmarshal authenticator: %v", err)
	}
	if auth.Cksum.CksumType != chksumtype.GSSAPI {
		t.Errorf("Cksum type = %d, want %d", auth.Cksum.CksumType, chksumtype.GSSAPI)
	}
	wantCksum, _ := gsstoken.GSSChecksum{Flags: v0ContextFlags}.Marshal()
	if !bytes.Equal(auth.Cksum.Checksum, wantCksum) {
		t.Errorf("Cksum = %x, want %x", auth.Cksum.Checksum, wantCksum)
	}
}

func TestFullHandshake(t *testing.T) {
	for _, authzID := range []string{"", "alice@EXAMPLE.COM"} {
		t.Run("authzid="+authzID, func(t *testing.T) {
			sessionKey := newTestKey(t)
			acceptorSubkey := newTestKey(t)
			cl, err := NewClient(Config{Credential: newTestCredential(t, sessionKey), AuthzID: authzID})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			if _, _, err := cl.Start(); err != nil {
				t.Fatalf("Start: %v", err)
			}

			// Message 2: the acceptor's AP-REP. Client replies with an empty token.
			empty, err := cl.Next(buildAPRep(t, sessionKey, acceptorSubkey))
			if err != nil {
				t.Fatalf("Next(AP-REP): %v", err)
			}
			if len(empty) != 0 {
				t.Errorf("post-AP-REP token = %x, want empty", empty)
			}

			// Message 4: the acceptor's security-layer offer (keyed with the
			// acceptor subkey). Client replies with its wrapped selection.
			offer := buildAcceptorOffer(t, acceptorSubkey, gsstoken.LayerNone|gsstoken.LayerIntegrity, 4096)
			reply, err := cl.Next(offer)
			if err != nil {
				t.Fatalf("Next(offer): %v", err)
			}

			// The acceptor verifies the client's reply and inspects the payload.
			var rwt gssapi.WrapToken
			if err := rwt.Unmarshal(reply, false); err != nil {
				t.Fatalf("unmarshal client reply: %v", err)
			}
			if ok, err := rwt.Verify(acceptorSubkey, uint32(keyusage.GSSAPI_INITIATOR_SEAL)); !ok {
				t.Fatalf("client reply failed integrity check: %v", err)
			}
			if len(rwt.Payload) < 4 {
				t.Fatalf("reply payload too short: %x", rwt.Payload)
			}
			if got := gsstoken.SecurityLayer(rwt.Payload[0]); got != gsstoken.LayerNone {
				t.Errorf("selected layer = %#x, want LayerNone", byte(got))
			}
			if mb := rwt.Payload[1:4]; !bytes.Equal(mb, []byte{0, 0, 0}) {
				t.Errorf("reply max-buffer = %x, want 000000", mb)
			}
			if got := string(rwt.Payload[4:]); got != authzID {
				t.Errorf("authzid = %q, want %q", got, authzID)
			}
		})
	}
}

// TestFullHandshakeNoAcceptorSubkey exercises the RFC 4121 case where the
// acceptor returns no subkey: the per-message WrapTokens are keyed with the
// ticket session key instead.
func TestFullHandshakeNoAcceptorSubkey(t *testing.T) {
	sessionKey := newTestKey(t)
	cl, err := NewClient(Config{Credential: newTestCredential(t, sessionKey), AuthzID: "bob"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, err := cl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// AP-REP carrying no subkey (zero-value EncryptionKey).
	empty, err := cl.Next(buildAPRep(t, sessionKey, types.EncryptionKey{}))
	if err != nil {
		t.Fatalf("Next(AP-REP): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("post-AP-REP token = %x, want empty", empty)
	}

	// Offer and reply are both keyed with the session key.
	reply, err := cl.Next(buildAcceptorOffer(t, sessionKey, gsstoken.LayerNone, 0))
	if err != nil {
		t.Fatalf("Next(offer): %v", err)
	}
	var rwt gssapi.WrapToken
	if err := rwt.Unmarshal(reply, false); err != nil {
		t.Fatalf("unmarshal client reply: %v", err)
	}
	if ok, err := rwt.Verify(sessionKey, uint32(keyusage.GSSAPI_INITIATOR_SEAL)); !ok {
		t.Fatalf("client reply failed integrity check under session key: %v", err)
	}
	if got := string(rwt.Payload[4:]); got != "bob" {
		t.Errorf("authzid = %q, want %q", got, "bob")
	}
}

func TestVerifyAPRepRejectsGarbage(t *testing.T) {
	sessionKey := newTestKey(t)
	cl, _ := NewClient(Config{Credential: newTestCredential(t, sessionKey)})
	if _, _, err := cl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := cl.Next([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("Next with garbage AP-REP: want mutual-auth error, got nil")
	}
}

func TestSecurityLayerWrongKeyRejected(t *testing.T) {
	sessionKey := newTestKey(t)
	acceptorSubkey := newTestKey(t)
	cl, _ := NewClient(Config{Credential: newTestCredential(t, sessionKey)})
	if _, _, err := cl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := cl.Next(buildAPRep(t, sessionKey, acceptorSubkey)); err != nil {
		t.Fatalf("Next(AP-REP): %v", err)
	}
	// Offer keyed with the wrong key must fail the integrity check.
	offer := buildAcceptorOffer(t, newTestKey(t), gsstoken.LayerNone, 0)
	if _, err := cl.Next(offer); err == nil {
		t.Fatal("Next with wrong-keyed offer: want integrity error, got nil")
	}
}

func TestSecurityLayerNoneNotOffered(t *testing.T) {
	sessionKey := newTestKey(t)
	acceptorSubkey := newTestKey(t)
	cl, _ := NewClient(Config{Credential: newTestCredential(t, sessionKey)})
	if _, _, err := cl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := cl.Next(buildAPRep(t, sessionKey, acceptorSubkey)); err != nil {
		t.Fatalf("Next(AP-REP): %v", err)
	}
	// Acceptor offers only integrity/confidentiality — v0 cannot comply.
	offer := buildAcceptorOffer(t, acceptorSubkey, gsstoken.LayerIntegrity|gsstoken.LayerConfidentiality, 4096)
	if _, err := cl.Next(offer); err == nil {
		t.Fatal("Next with no LayerNone offered: want error, got nil")
	}
}

func TestNextAfterCompleteErrors(t *testing.T) {
	sessionKey := newTestKey(t)
	acceptorSubkey := newTestKey(t)
	cl, _ := NewClient(Config{Credential: newTestCredential(t, sessionKey)})
	if _, _, err := cl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := cl.Next(buildAPRep(t, sessionKey, acceptorSubkey)); err != nil {
		t.Fatalf("Next(AP-REP): %v", err)
	}
	if _, err := cl.Next(buildAcceptorOffer(t, acceptorSubkey, gsstoken.LayerNone, 0)); err != nil {
		t.Fatalf("Next(offer): %v", err)
	}
	if _, err := cl.Next([]byte{0x05, 0x04}); err == nil {
		t.Fatal("Next after completion: want error, got nil")
	}
}

func TestFromCCacheErrors(t *testing.T) {
	if _, err := FromCCache(nil, "imap/mail.example.com"); err == nil {
		t.Error("FromCCache(nil): want error, got nil")
	}
	// An empty ccache has no matching entry.
	if _, err := FromCCache(&credentials.CCache{}, "imap/mail.example.com"); err == nil {
		t.Error("FromCCache(empty): want not-found error, got nil")
	}
}
