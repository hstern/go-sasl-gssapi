// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import (
	"bytes"
	"testing"
	"time"

	"github.com/hstern/krb5/client"
	"github.com/hstern/krb5/credentials"
	"github.com/hstern/krb5/gssapi"
	"github.com/hstern/krb5/gssapi/krb5context"
	"github.com/hstern/krb5/iana/etypeID"
	"github.com/hstern/krb5/iana/nametype"
	"github.com/hstern/krb5/keytab"
	"github.com/hstern/krb5/messages"
	"github.com/hstern/krb5/types"

	"github.com/hstern/go-sasl-gssapi/internal/seclayer"
)

const (
	testRealm    = "EXAMPLE.COM"
	testSPN      = "imap/mail.example.com"
	testPassword = "s3rvice-k3y-material"
	testClientNm = "alice"
	testEtype    = etypeID.AES256_CTS_HMAC_SHA1_96
)

// newTestKRB5Client mints a real service ticket against a fresh keytab, builds a
// holder-of-key ccache from it, and returns the ccache-backed krb5 client plus
// the service keytab (which the acceptor uses to decrypt the AP-REQ). No KDC.
func newTestKRB5Client(t *testing.T) (*client.Client, *keytab.Keytab) {
	t.Helper()

	sname, _ := types.ParseSPNString(testSPN)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, testClientNm)

	kt := keytab.New()
	if err := kt.AddEntry(testSPN, testRealm, testPassword, time.Unix(1_700_000_000, 0), 1, testEtype); err != nil {
		t.Fatalf("keytab AddEntry: %v", err)
	}

	now := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(
		cname, testRealm, sname, testRealm,
		types.NewKrbFlags(), kt, testEtype, 1,
		now, now, now.Add(time.Hour), now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("NewTicket: %v", err)
	}

	tktBytes, err := tkt.Marshal()
	if err != nil {
		t.Fatalf("marshal ticket: %v", err)
	}
	cc := credentials.NewV4CCache()
	cc.SetDefaultPrincipal(credentials.NewPrincipal(cname, testRealm))
	cc.AddCredential(&credentials.Credential{
		Client:    credentials.NewPrincipal(cname, testRealm),
		Server:    credentials.NewPrincipal(sname, testRealm),
		Key:       sessionKey,
		AuthTime:  now,
		StartTime: now,
		EndTime:   now.Add(time.Hour),
		Ticket:    tktBytes,
	})

	cl, err := FromCCache(cc)
	if err != nil {
		t.Fatalf("FromCCache: %v", err)
	}
	return cl, kt
}

// newHandshakePair pairs our SASL client with the reference krb5context.Acceptor
// that holds the same service keytab.
func newHandshakePair(t *testing.T, authzID string) (*Client, *krb5context.Acceptor) {
	t.Helper()
	cl, kt := newTestKRB5Client(t)
	sc, err := NewClient(Config{Client: cl, Service: testSPN, AuthzID: authzID})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return sc, krb5context.NewAcceptor(kt)
}

// acceptorOffer builds the acceptor's GS-wrapped security-layer offer.
func acceptorOffer(t *testing.T, sc *gssapi.SecContext, layers seclayer.SecurityLayer, maxBuf uint32) []byte {
	t.Helper()
	payload := []byte{byte(layers), byte(maxBuf >> 16), byte(maxBuf >> 8), byte(maxBuf)}
	wt, err := sc.Wrap(payload)
	if err != nil {
		t.Fatalf("acceptor Wrap offer: %v", err)
	}
	b, err := wt.Marshal()
	if err != nil {
		t.Fatalf("marshal offer: %v", err)
	}
	return b
}

func TestNewClientValidation(t *testing.T) {
	if _, err := NewClient(Config{Service: testSPN}); err == nil {
		t.Error("NewClient with nil Client: want error, got nil")
	}
	cl, _ := newTestKRB5Client(t)
	if _, err := NewClient(Config{Client: cl, Service: ""}); err == nil {
		t.Error("NewClient with empty Service: want error, got nil")
	}
}

func TestFromCCacheNil(t *testing.T) {
	if _, err := FromCCache(nil); err == nil {
		t.Error("FromCCache(nil): want error, got nil")
	}
}

func TestFullHandshake(t *testing.T) {
	for _, authzID := range []string{"", "alice@EXAMPLE.COM"} {
		t.Run("authzid="+authzID, func(t *testing.T) {
			cl, acceptor := newHandshakePair(t, authzID)

			// Message 1: client AP-REQ → acceptor produces the AP-REP.
			mech, ir, err := cl.Start()
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			if mech != Mechanism {
				t.Fatalf("mech = %q, want %q", mech, Mechanism)
			}
			apRep, done, err := acceptor.AcceptSecContext(ir)
			if err != nil {
				t.Fatalf("acceptor.AcceptSecContext: %v", err)
			}
			if !done {
				t.Fatal("acceptor context not established in one step")
			}

			// Message 2: client verifies mutual auth, emits an empty token.
			empty, err := cl.Next(apRep)
			if err != nil {
				t.Fatalf("Next(AP-REP): %v", err)
			}
			if len(empty) != 0 {
				t.Errorf("post-AP-REP token = %x, want empty", empty)
			}

			accSC, err := acceptor.Context()
			if err != nil {
				t.Fatalf("acceptor.Context: %v", err)
			}

			// Messages 4/5: security-layer offer and the client's wrapped reply.
			offer := acceptorOffer(t, accSC, seclayer.LayerNone|seclayer.LayerIntegrity, 8192)
			reply, err := cl.Next(offer)
			if err != nil {
				t.Fatalf("Next(offer): %v", err)
			}

			// The acceptor verifies the client's reply and reads the payload.
			var rwt gssapi.WrapToken
			if err := rwt.Unmarshal(reply, false); err != nil {
				t.Fatalf("unmarshal client reply: %v", err)
			}
			if ok, err := accSC.Unwrap(&rwt); !ok {
				t.Fatalf("client reply failed integrity check: %v", err)
			}
			if len(rwt.Payload) < 4 {
				t.Fatalf("reply payload too short: %x", rwt.Payload)
			}
			if got := seclayer.SecurityLayer(rwt.Payload[0]); got != seclayer.LayerNone {
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

func TestVerifyAPRepRejectsGarbage(t *testing.T) {
	cl, _ := newHandshakePair(t, "")
	if _, _, err := cl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := cl.Next([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("Next with garbage AP-REP: want mutual-auth error, got nil")
	}
}

func TestSecurityLayerNoneNotOffered(t *testing.T) {
	cl, acceptor := newHandshakePair(t, "")
	_, ir, err := cl.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	apRep, _, err := acceptor.AcceptSecContext(ir)
	if err != nil {
		t.Fatalf("acceptor.AcceptSecContext: %v", err)
	}
	if _, err := cl.Next(apRep); err != nil {
		t.Fatalf("Next(AP-REP): %v", err)
	}
	accSC, err := acceptor.Context()
	if err != nil {
		t.Fatalf("acceptor.Context: %v", err)
	}
	// Acceptor offers only integrity/confidentiality — v0 cannot comply.
	offer := acceptorOffer(t, accSC, seclayer.LayerIntegrity|seclayer.LayerConfidentiality, 8192)
	if _, err := cl.Next(offer); err == nil {
		t.Fatal("Next with no LayerNone offered: want error, got nil")
	}
}

func TestNextAfterComplete(t *testing.T) {
	cl, acceptor := newHandshakePair(t, "")
	_, ir, err := cl.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	apRep, _, err := acceptor.AcceptSecContext(ir)
	if err != nil {
		t.Fatalf("acceptor.AcceptSecContext: %v", err)
	}
	if _, err := cl.Next(apRep); err != nil {
		t.Fatalf("Next(AP-REP): %v", err)
	}
	accSC, err := acceptor.Context()
	if err != nil {
		t.Fatalf("acceptor.Context: %v", err)
	}
	if _, err := cl.Next(acceptorOffer(t, accSC, seclayer.LayerNone, 0)); err != nil {
		t.Fatalf("Next(offer): %v", err)
	}
	if _, err := cl.Next([]byte{0x05, 0x04}); err == nil {
		t.Fatal("Next after completion: want error, got nil")
	}
}
