// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import (
	"bytes"
	"testing"
)

func TestIntegrityLayerRoundTrip(t *testing.T) {
	krbClient, kt := newTestKRB5Client(t)
	cl, err := NewClient(Config{
		Client:  krbClient,
		Service: testSPN,
		AuthzID: "alice@EXAMPLE.COM",
		Layers:  []SecurityLayer{IntegrityProtection, NoSecurityLayer},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		Keytab: kt,
		Layers: []SecurityLayer{IntegrityProtection, NoSecurityLayer},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	driveExchange(t, cl, srv)

	if cl.SecurityLayer() != IntegrityProtection {
		t.Fatalf("client layer = %#x, want IntegrityProtection", byte(cl.SecurityLayer()))
	}
	if srv.SecurityLayer() != IntegrityProtection {
		t.Fatalf("server layer = %#x, want IntegrityProtection", byte(srv.SecurityLayer()))
	}
	if srv.AuthzID() != "alice@EXAMPLE.COM" {
		t.Errorf("AuthzID = %q, want %q", srv.AuthzID(), "alice@EXAMPLE.COM")
	}

	// Application data: client wraps → server unwraps.
	msg := []byte("hello over the integrity layer")
	wrapped, err := cl.Wrap(msg)
	if err != nil {
		t.Fatalf("client Wrap: %v", err)
	}
	got, err := srv.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("server Unwrap: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("server unwrapped %q, want %q", got, msg)
	}

	// And the reverse: server wraps → client unwraps.
	reply := []byte("acknowledged")
	wrapped2, err := srv.Wrap(reply)
	if err != nil {
		t.Fatalf("server Wrap: %v", err)
	}
	got2, err := cl.Unwrap(wrapped2)
	if err != nil {
		t.Fatalf("client Unwrap: %v", err)
	}
	if !bytes.Equal(got2, reply) {
		t.Errorf("client unwrapped %q, want %q", got2, reply)
	}

	// A tampered token fails the integrity check.
	tampered := bytes.Clone(wrapped)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := srv.Unwrap(tampered); err == nil {
		t.Error("server Unwrap of a tampered token: want error, got nil")
	}
}

func TestNoLayerWrapUnavailable(t *testing.T) {
	krbClient, kt := newTestKRB5Client(t)
	cl, _ := NewClient(Config{Client: krbClient, Service: testSPN}) // default: no layer
	srv, _ := NewServer(ServerConfig{Keytab: kt})
	driveExchange(t, cl, srv)

	if cl.SecurityLayer() != NoSecurityLayer {
		t.Errorf("client layer = %#x, want NoSecurityLayer", byte(cl.SecurityLayer()))
	}
	if _, err := cl.Wrap([]byte("x")); err == nil {
		t.Error("client Wrap with no security layer: want error, got nil")
	}
	if _, err := srv.Wrap([]byte("x")); err == nil {
		t.Error("server Wrap with no security layer: want error, got nil")
	}
}

func TestLayerNegotiationFallsBackToNone(t *testing.T) {
	// Client prefers integrity but the server offers only no-layer.
	krbClient, kt := newTestKRB5Client(t)
	cl, _ := NewClient(Config{
		Client:  krbClient,
		Service: testSPN,
		Layers:  []SecurityLayer{IntegrityProtection, NoSecurityLayer},
	})
	srv, _ := NewServer(ServerConfig{Keytab: kt}) // offers only no-layer
	driveExchange(t, cl, srv)

	if cl.SecurityLayer() != NoSecurityLayer {
		t.Errorf("client negotiated %#x, want NoSecurityLayer", byte(cl.SecurityLayer()))
	}
	if srv.SecurityLayer() != NoSecurityLayer {
		t.Errorf("server negotiated %#x, want NoSecurityLayer", byte(srv.SecurityLayer()))
	}
}

func TestLayerNegotiationNoOverlap(t *testing.T) {
	// Client accepts only integrity; the server offers only no-layer → the
	// client cannot comply and errors when it processes the offer.
	krbClient, kt := newTestKRB5Client(t)
	cl, _ := NewClient(Config{
		Client:  krbClient,
		Service: testSPN,
		Layers:  []SecurityLayer{IntegrityProtection},
	})
	srv, _ := NewServer(ServerConfig{Keytab: kt}) // offers only no-layer

	_, ir, err := cl.Start()
	if err != nil {
		t.Fatalf("client Start: %v", err)
	}
	apRep, _, err := srv.Next(ir)
	if err != nil {
		t.Fatalf("server Next(AP-REQ): %v", err)
	}
	empty, err := cl.Next(apRep)
	if err != nil {
		t.Fatalf("client Next(AP-REP): %v", err)
	}
	offer, _, err := srv.Next(empty)
	if err != nil {
		t.Fatalf("server Next(empty): %v", err)
	}
	if _, err := cl.Next(offer); err == nil {
		t.Fatal("client with no overlapping layer: want error, got nil")
	}
}
