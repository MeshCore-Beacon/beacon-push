// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package disposable

import "testing"

func TestBlocked(t *testing.T) {
	for d, want := range map[string]bool{
		"mailinator.com":       true,
		"MAILINATOR.COM.":      true,
		"inbox.mailinator.com": true,
		"gmail.com":            false,
		"example.ca":           false,
		"":                     false,
		"com":                  false,
	} {
		if got := Blocked(d); got != want {
			t.Errorf("Blocked(%q) = %v, want %v", d, got, want)
		}
	}
	if len(domains) < 1000 {
		t.Fatalf("blocklist looks truncated: %d domains", len(domains))
	}
}
