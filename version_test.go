// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package saslgssapi

import "testing"

func TestSpecVersion(t *testing.T) {
	// Pin the exact value. SpecVersion ships in public source, so this guards
	// both that it is set and that no stray internal reference creeps in: any
	// change must be deliberate and update this expectation.
	const want = "v0 (SASL GSSAPI client; RFC 4752)"
	if SpecVersion != want {
		t.Errorf("SpecVersion = %q, want %q", SpecVersion, want)
	}
}
