// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import (
	"errors"

	"github.com/hstern/krb5/client"
	"github.com/hstern/krb5/config"
	"github.com/hstern/krb5/credentials"
)

// FromCCache builds a holder-of-key Kerberos client from an MIT credential
// cache for use as Config.Client. It is a thin wrapper over
// client.NewFromCCache: the ccache is expected to already hold the service
// ticket and its session key, so the client never contacts a KDC.
//
// The returned *client.Client can also be built directly with
// client.NewFromCCache if the caller needs a non-default krb5 configuration
// (e.g. to allow a live TGS exchange for tickets not yet cached).
func FromCCache(cc *credentials.CCache) (*client.Client, error) {
	if cc == nil {
		return nil, errors.New("saslgssapi: nil credential cache")
	}
	// A default (empty) config is sufficient for the holder-of-key path:
	// GetServiceTicket serves the cached ticket without consulting a KDC.
	return client.NewFromCCache(cc, config.New())
}
