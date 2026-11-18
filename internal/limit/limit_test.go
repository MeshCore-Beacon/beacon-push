// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package limit

import (
	"testing"
	"time"
)

func TestWindow(t *testing.T) {
	w := New(time.Minute)
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if ok, _ := w.Allow("a", 3, now); !ok {
			t.Fatalf("event %d refused", i)
		}
	}
	ok, wait := w.Allow("a", 3, now.Add(20*time.Second))
	if ok || wait != 40*time.Second {
		t.Fatalf("fourth event: ok %v wait %v", ok, wait)
	}
	if ok, _ := w.Allow("b", 3, now); !ok {
		t.Fatal("keys must be counted apart")
	}
	if ok, _ := w.Allow("a", 3, now.Add(time.Minute)); !ok {
		t.Fatal("a new window must start over")
	}
	if n := w.Count("a", now.Add(time.Minute)); n != 1 {
		t.Fatalf("count %d", n)
	}
	if ok, _ := w.Allow("c", 0, now); ok {
		t.Fatal("a zero limit must refuse")
	}
}
