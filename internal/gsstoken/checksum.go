// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

package gsstoken

import (
	"encoding/binary"
	"fmt"
)

// ChecksumFlags is the 4-byte GSS context-establishment flag word carried in
// the RFC 4121 §4.1.1 authenticator checksum. The bits mirror the GSS_C_*_FLAG
// request flags. The field is encoded little-endian (RFC 4121 §4.1.1) — unlike
// the network-order integers elsewhere in the handshake.
type ChecksumFlags uint32

// GSS context-establishment flags (RFC 4121 §4.1.1.1, values from RFC 2744).
const (
	FlagDeleg    ChecksumFlags = 1 << iota // GSS_C_DELEG_FLAG
	FlagMutual                             // GSS_C_MUTUAL_FLAG
	FlagReplay                             // GSS_C_REPLAY_FLAG
	FlagSequence                           // GSS_C_SEQUENCE_FLAG
	FlagConf                               // GSS_C_CONF_FLAG
	FlagInteg                              // GSS_C_INTEG_FLAG
)

// bndLen is the fixed length of the channel-binding field: an MD5 hash, or 16
// zero octets when no channel binding is used (RFC 4121 §4.1.1).
const bndLen = 16

// checksumMinLen is the length of a delegation-free checksum: the 4-byte Lgth,
// the 16-byte Bnd, and the 4-byte Flags.
const checksumMinLen = 4 + bndLen + 4

// GSSChecksum is the RFC 4121 §4.1.1 GSS-API authenticator checksum (Kerberos
// checksum type 0x8003). It is not a cryptographic checksum over the
// authenticator — it is a structured field carrying the requested context
// flags and the channel bindings.
//
// v0 never sets the delegation flag, so Deleg is always empty on marshal; it is
// captured on unmarshal only to round-trip an acceptor- or interop-produced
// checksum verbatim.
type GSSChecksum struct {
	// Bnd is the channel-binding value: 16 bytes, all zero when no channel
	// binding is in effect. A short or over-long Bnd is a marshal error.
	Bnd [bndLen]byte
	// Flags is the GSS context-establishment flag word.
	Flags ChecksumFlags
	// Deleg is the optional delegated-credential blob (KRB_CRED), present only
	// when FlagDeleg is set. Empty in v0.
	Deleg []byte
}

// Marshal encodes the checksum in its type-0x8003 wire form: a little-endian
// Lgth (always 16, the Bnd length), the 16-byte Bnd, and the little-endian
// Flags, followed by the delegation fields only when FlagDeleg is set.
func (c GSSChecksum) Marshal() ([]byte, error) {
	if c.Flags&FlagDeleg == 0 {
		if len(c.Deleg) != 0 {
			return nil, fmt.Errorf("gsstoken: Deleg set without FlagDeleg")
		}
		out := make([]byte, checksumMinLen)
		binary.LittleEndian.PutUint32(out[0:4], bndLen)
		copy(out[4:4+bndLen], c.Bnd[:])
		binary.LittleEndian.PutUint32(out[4+bndLen:], uint32(c.Flags))
		return out, nil
	}

	// Delegation form: DlgOpt (2) + Dlgth (2) + Deleg follow the flags.
	if len(c.Deleg) > 0xFFFF {
		return nil, fmt.Errorf("gsstoken: Deleg too long: %d bytes", len(c.Deleg))
	}
	out := make([]byte, checksumMinLen+4+len(c.Deleg))
	binary.LittleEndian.PutUint32(out[0:4], bndLen)
	copy(out[4:4+bndLen], c.Bnd[:])
	binary.LittleEndian.PutUint32(out[4+bndLen:], uint32(c.Flags))
	// DlgOpt is fixed at 1 for a KRB_CRED delegation (RFC 4121 §4.1.1).
	binary.LittleEndian.PutUint16(out[checksumMinLen:], 1)
	binary.LittleEndian.PutUint16(out[checksumMinLen+2:], uint16(len(c.Deleg)))
	copy(out[checksumMinLen+4:], c.Deleg)
	return out, nil
}

// UnmarshalChecksum decodes a type-0x8003 checksum. It is lenient: it accepts
// any Lgth the sender declares (so long as the Bnd it frames is present) and
// captures the delegation blob when the flags advertise one, so an
// acceptor-produced checksum round-trips through Marshal unchanged.
func UnmarshalChecksum(b []byte) (GSSChecksum, error) {
	var c GSSChecksum
	// The fixed part (Lgth + Bnd + Flags) is always checksumMinLen bytes; a
	// shorter buffer cannot carry a valid checksum.
	if len(b) < checksumMinLen {
		return c, fmt.Errorf("gsstoken: checksum too short: %d bytes, want at least %d", len(b), checksumMinLen)
	}
	// Only the 16-byte channel-binding form is defined. Rejecting any other
	// declared Lgth up front keeps the field within the already-validated
	// fixed part and sidesteps any length-arithmetic overflow reasoning.
	if bnd := binary.LittleEndian.Uint32(b[0:4]); bnd != bndLen {
		return c, fmt.Errorf("gsstoken: checksum Bnd length %d, want %d", bnd, bndLen)
	}
	copy(c.Bnd[:], b[4:4+bndLen])
	c.Flags = ChecksumFlags(binary.LittleEndian.Uint32(b[4+bndLen : checksumMinLen]))

	rest := b[checksumMinLen:]
	if c.Flags&FlagDeleg == 0 {
		if len(rest) != 0 {
			return c, fmt.Errorf("gsstoken: %d trailing bytes without FlagDeleg", len(rest))
		}
		return c, nil
	}
	if len(rest) < 4 {
		return c, fmt.Errorf("gsstoken: FlagDeleg set but delegation header truncated")
	}
	dlgth := binary.LittleEndian.Uint16(rest[2:4])
	if int(dlgth) != len(rest)-4 {
		return c, fmt.Errorf("gsstoken: delegation Dlgth %d != %d trailing bytes", dlgth, len(rest)-4)
	}
	if dlgth > 0 {
		c.Deleg = append([]byte(nil), rest[4:4+dlgth]...)
	}
	return c, nil
}
