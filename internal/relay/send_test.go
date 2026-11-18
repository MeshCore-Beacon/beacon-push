// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestValidTokenTakesOnlyFCMCharacters(t *testing.T) {
	good := "dXk3Hn_Q-1E:APA91bF" + strings.Repeat("a1B2_-", 20)
	if !validToken(good) {
		t.Fatalf("real-looking token refused")
	}
	for _, bad := range []string{"", "tok!", "tok<script>", "tok\"x", "a/b", "a+b=", "tok%00", strings.Repeat("a", 4097)} {
		if validToken(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTTLOverflowIsInvalid(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	dev := h.handle(id, "tok")
	res, _ := h.send(auth, SendItem{Handle: dev.Handle, Ciphertext: ct, TTLSeconds: 9223372037},
		SendItem{Handle: dev.Handle, Ciphertext: ct, TTLSeconds: int(MaxTTL / time.Second)})
	if res[0].Status != StatusInvalid || res[1].Status != StatusOK {
		t.Fatalf("%+v", res)
	}
	if sent := h.push.messages(); len(sent) != 1 || sent[0].TTL != MaxTTL {
		t.Fatalf("%+v", sent)
	}
}

func TestMaxBatchFitsTheBodyLimit(t *testing.T) {
	h := newHarness(t)
	_, auth := h.register("A", "a@example.org", "")
	big := base64.StdEncoding.EncodeToString(make([]byte, MaxCiphertext))
	items := make([]SendItem, MaxBatch)
	for i := range items {
		items[i] = SendItem{Handle: fmt.Sprintf("h_%022d", i), Ciphertext: big, CollapseKey: strings.Repeat("k", MaxCollapseKey),
			TTLSeconds: int(MaxTTL / time.Second)}
	}
	res, resp := h.send(auth, items...)
	if resp.StatusCode != 200 || len(res) != MaxBatch {
		t.Fatalf("largest batch: %d, %d results", resp.StatusCode, len(res))
	}
}

func TestRevokedForeignHandlesAreNotHarvesting(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	victimID, _ := h.register("Victim", "v@example.org", "")
	id, auth := h.register("A", "a@example.org", "")
	items := make([]SendItem, MaxBatch)
	for i := range items {
		hd := h.handle(victimID, fmt.Sprintf("victim-tok-%d", i)).Handle
		if err := h.store.RevokeHandle(ctx, hd, h.clock.now()); err != nil {
			t.Fatal(err)
		}
		items[i] = SendItem{Handle: hd, Ciphertext: ct}
	}
	res, resp := h.send(auth, items...)
	if resp.StatusCode != 200 || res[0].Status != StatusInvalidHandle {
		t.Fatalf("%d %+v", resp.StatusCode, res)
	}
	if inst, _ := h.store.Instance(ctx, id); inst.Status != "active" {
		t.Fatalf("suspended for revoked handles: %s", inst.Status)
	}
}
