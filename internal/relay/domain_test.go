// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"net/netip"
	"testing"
)

func TestPublicAddrRefusesSpecialPurposeIPv6(t *testing.T) {
	for _, a := range []string{
		"64:ff9b::a00:1",   // well-known NAT64
		"64:ff9b:1::a00:1", // local-use translation, RFC 8215
		"2002:a00:1::1",    // 6to4 wrapping 10.0.0.1
		"2001:0:a00:1::1",  // Teredo
		"2001:db8::1",      // documentation
		"3fff::1",          // documentation, RFC 9637
		"100::1",           // discard-only
		"fd00::1",
		"fe80::1",
		"::ffff:10.0.0.1",
	} {
		if publicAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s counted as public", a)
		}
	}
	for _, a := range []string{"2606:4700::1111", "1.1.1.1", "2a00:1450::1"} {
		if !publicAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s refused", a)
		}
	}
}
