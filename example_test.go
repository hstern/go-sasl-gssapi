// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi_test

import (
	"log"

	"github.com/emersion/go-sasl"
	"github.com/hstern/krb5/credentials"

	"github.com/hstern/go-sasl-gssapi"
)

// Example builds the SASL client from a holder-of-key credential cache. The
// result satisfies emersion/go-sasl's Client, so it plugs straight into
// go-imap's Authenticate or go-smtp's Auth.
func Example() {
	// A ccache already holding a service ticket for the target — from kinit,
	// KRB5CCNAME, or an OAuth2-to-Kerberos exchange. No KDC is contacted.
	cc, err := credentials.LoadCCache("/tmp/krb5cc_1000")
	if err != nil {
		log.Fatal(err)
	}
	krbClient, err := saslgssapi.FromCCache(cc)
	if err != nil {
		log.Fatal(err)
	}

	var sc sasl.Client
	sc, err = saslgssapi.NewClient(saslgssapi.Config{
		Client:  krbClient,
		Service: "imap/mail.example.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Hand sc to a SASL-capable client, e.g. imapClient.Authenticate(sc).
	_ = sc
}
