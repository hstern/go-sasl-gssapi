// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import (
	"strings"
	"testing"
	"time"

	"github.com/hstern/krb5/keytab"
)

// driveExchange runs our Client and Server through the full RFC 4752 exchange.
func driveExchange(t *testing.T, cl *Client, srv *Server) {
	t.Helper()

	_, ir, err := cl.Start()
	if err != nil {
		t.Fatalf("client Start: %v", err)
	}

	apRep, done, err := srv.Next(ir) // AP-REQ → AP-REP
	if err != nil {
		t.Fatalf("server Next(AP-REQ): %v", err)
	}
	if done {
		t.Fatal("server reported done after the AP-REQ")
	}

	empty, err := cl.Next(apRep) // AP-REP → empty token
	if err != nil {
		t.Fatalf("client Next(AP-REP): %v", err)
	}

	offer, done, err := srv.Next(empty) // empty → security-layer offer
	if err != nil {
		t.Fatalf("server Next(empty): %v", err)
	}
	if done {
		t.Fatal("server reported done after the empty token")
	}

	reply, err := cl.Next(offer) // offer → wrapped selection
	if err != nil {
		t.Fatalf("client Next(offer): %v", err)
	}

	fin, done, err := srv.Next(reply) // selection → done
	if err != nil {
		t.Fatalf("server Next(reply): %v", err)
	}
	if !done {
		t.Fatal("server not done after the client's selection")
	}
	if fin != nil {
		t.Errorf("final challenge = %x, want nil", fin)
	}
}

func TestClientServerRoundTrip(t *testing.T) {
	for _, authzID := range []string{"", "alice@EXAMPLE.COM"} {
		t.Run("authzid="+authzID, func(t *testing.T) {
			krbClient, kt := newTestKRB5Client(t)
			cl, err := NewClient(Config{Client: krbClient, Service: testSPN, AuthzID: authzID})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			srv, err := NewServer(ServerConfig{Keytab: kt})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}

			driveExchange(t, cl, srv)

			if !srv.Complete() {
				t.Error("server not complete after a successful exchange")
			}
			if srv.AuthzID() != authzID {
				t.Errorf("AuthzID = %q, want %q", srv.AuthzID(), authzID)
			}
			if !strings.Contains(srv.ClientName(), "alice") {
				t.Errorf("ClientName = %q, want it to contain %q", srv.ClientName(), "alice")
			}
		})
	}
}

func TestNewServerRequiresKeytab(t *testing.T) {
	if _, err := NewServer(ServerConfig{}); err == nil {
		t.Error("NewServer with nil Keytab: want error, got nil")
	}
}

func TestServerRejectsGarbageAPReq(t *testing.T) {
	_, kt := newTestKRB5Client(t)
	srv, err := NewServer(ServerConfig{Keytab: kt})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if _, _, err := srv.Next([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("server Next with garbage AP-REQ: want error, got nil")
	}
}

func TestServerWrongKeytabRejected(t *testing.T) {
	krbClient, _ := newTestKRB5Client(t)
	cl, err := NewClient(Config{Client: krbClient, Service: testSPN})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// A server whose keytab holds a different service key cannot decrypt the
	// client's ticket.
	otherKt := keytab.New()
	if err := otherKt.AddEntry(testSPN, testRealm, "a-different-password", time.Unix(1_700_000_000, 0), 1, testEtype); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	srv, err := NewServer(ServerConfig{Keytab: otherKt})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	_, ir, err := cl.Start()
	if err != nil {
		t.Fatalf("client Start: %v", err)
	}
	if _, _, err := srv.Next(ir); err == nil {
		t.Fatal("server with the wrong keytab: want error, got nil")
	}
}
