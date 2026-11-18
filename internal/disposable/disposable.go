// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package disposable knows the throwaway email domains registration refuses. The list is the CC0
// disposable-email-domains blocklist, vendored as list.txt.
package disposable

import (
	_ "embed"
	"strings"
)

//go:embed list.txt
var raw string

var domains = func() map[string]struct{} {
	m := map[string]struct{}{}
	for _, line := range strings.Split(raw, "\n") {
		if d := strings.ToLower(strings.TrimSpace(line)); d != "" && !strings.HasPrefix(d, "#") {
			m[d] = struct{}{}
		}
	}
	return m
}()

// Blocked reports whether the domain, or any domain it sits under, is a disposable mail provider.
func Blocked(domain string) bool {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	for d != "" {
		if _, ok := domains[d]; ok {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return false
		}
		d = d[i+1:]
	}
	return false
}
