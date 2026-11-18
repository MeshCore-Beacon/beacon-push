// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MeshCore-Beacon/beacon-push/internal/push"
	"github.com/MeshCore-Beacon/beacon-push/internal/store"
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

// devices registers n handles for a server and lifts its quotas out of the way.
func (h *harness) devices(id string, n int) []string {
	h.t.Helper()
	if err := h.store.SetQuota(context.Background(), id, 10_000, 10_000); err != nil {
		h.t.Fatal(err)
	}
	out := make([]string, n)
	for i := range out {
		out[i] = h.handle(id, fmt.Sprintf("tok-%d", i)).Handle
	}
	return out
}

func items(handles ...string) []SendItem {
	out := make([]SendItem, len(handles))
	for i, hd := range handles {
		out[i] = SendItem{Handle: hd, Ciphertext: ct}
	}
	return out
}

func count(res []SendResult, status string) int {
	n := 0
	for _, r := range res {
		if r.Status == status {
			n++
		}
	}
	return n
}

func TestBatchSendsConcurrently(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 40)
	h.push.set(func(f *fakePush) { f.delay = 200 * time.Millisecond })
	start := time.Now()
	res, _ := h.send(auth, items(devs...)...)
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("40 sends of 200 ms took %s", took)
	}
	if count(res, StatusOK) != 40 {
		t.Fatalf("%+v", res)
	}
}

func TestBatchDeadlineDefersUnstartedItems(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 10)
	h.relay.batchDeadline, h.relay.sendWorkers = 150*time.Millisecond, 2
	h.push.set(func(f *fakePush) { f.delay = 200 * time.Millisecond })
	res, resp := h.send(auth, items(devs...)...)
	ok, later := count(res, StatusOK), count(res, StatusRateLimited)
	if ok == 0 || later == 0 || ok+later != 10 || ok != len(h.push.messages()) || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("ok %d, deferred %d, pushed %d: %+v", ok, later, len(h.push.messages()), res)
	}
	for _, r := range res {
		if r.Status == StatusRateLimited && r.RetryAfterSeconds != 5 {
			t.Fatalf("deferred item: %+v", r)
		}
	}
}

func TestIdempotencyKey(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 2)
	item := SendItem{Handle: devs[0], Ciphertext: ct, ID: "1234:9b2c-uuid"}

	first, _ := h.send(auth, item)
	again, _ := h.send(auth, item)
	if first[0].Status != StatusOK || again[0].Status != StatusOK || again[0].MessageID != first[0].MessageID {
		t.Fatalf("%+v %+v", first, again)
	}
	if n, _ := h.store.SentToday(ctx, id, h.clock.now()); n != 1 || len(h.push.messages()) != 1 {
		t.Fatalf("a repeat was sent or counted: %d counted, %d pushed", n, len(h.push.messages()))
	}

	// A failed try is sent again on repeat.
	h.push.set(func(f *fakePush) { f.errs["tok-1"] = &push.Error{Provider: push.FCM, Status: 502} })
	item = SendItem{Handle: devs[1], Ciphertext: ct, ID: "1235:x"}
	if res, _ := h.send(auth, item); res[0].Status != StatusFailed {
		t.Fatalf("%+v", res)
	}
	h.push.set(func(f *fakePush) { delete(f.errs, "tok-1") })
	if res, _ := h.send(auth, item); res[0].Status != StatusOK || len(h.push.messages()) != 2 {
		t.Fatalf("repeat of a failed id: %+v", res)
	}

	// A reservation left by a crash holds the id for two minutes, then lets it go.
	if _, _, err := h.store.Reserve(ctx, store.Reservation{MessageID: "m_crash", InstanceID: id, Handle: devs[1], ClientID: "1236:y",
		At: h.clock.now(), CiphertextSHA256: []byte("x"), InstancePerDay: 100, GlobalPerDay: 100, HandlePerDay: 100}); err != nil {
		t.Fatal(err)
	}
	item.ID = "1236:y"
	if res, _ := h.send(auth, item); res[0].Status != StatusRateLimited || res[0].RetryAfterSeconds != 30 {
		t.Fatalf("in flight: %+v", res)
	}
	h.clock.add(3 * time.Minute)
	if res, _ := h.send(auth, item); res[0].Status != StatusOK {
		t.Fatalf("after the timeout: %+v", res)
	}

	// The same id twice in one batch goes out once: the second waits for the first or shares its answer.
	h.clock.add(time.Minute)
	before := len(h.push.messages())
	dup := SendItem{Handle: devs[0], Ciphertext: ct, ID: "1237:z"}
	res, _ := h.send(auth, dup, dup)
	if len(h.push.messages()) != before+1 || count(res, StatusOK)+count(res, StatusRateLimited) != 2 ||
		(count(res, StatusOK) == 2 && res[0].MessageID != res[1].MessageID) {
		t.Fatalf("duplicate in a batch: %+v", res)
	}

	for _, bad := range []string{"has space", strings.Repeat("a", 65), "a/b"} {
		if res, _ := h.send(auth, SendItem{Handle: devs[0], Ciphertext: ct, ID: bad}); res[0].Status != StatusInvalid {
			t.Errorf("id %q: %+v", bad, res)
		}
	}
}

func TestQueuedBatchSeesASuspension(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 1)
	unlock, err := h.relay.lockInstance(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *http.Response)
	go func() {
		_, resp := h.send(auth, items(devs...)...)
		done <- resp
	}()
	time.Sleep(200 * time.Millisecond) // let the request authenticate and queue
	if err := h.store.SetStatus(context.Background(), id, store.StatusSuspended, nil, h.clock.now()); err != nil {
		t.Fatal(err)
	}
	unlock()
	if resp := <-done; resp.StatusCode != 403 || len(h.push.messages()) != 0 {
		t.Fatalf("queued batch after suspension: %d, %d pushed", resp.StatusCode, len(h.push.messages()))
	}
}

func TestSendLockWaitEndsWithTheRequest(t *testing.T) {
	h := newHarness(t)
	unlock, _ := h.relay.lockInstance(context.Background(), "inst_x")
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.relay.lockInstance(ctx, "inst_x"); err == nil {
		t.Fatal("second lock taken while the first is held")
	}
}

func TestSendIsCountedWhenTheClientLeaves(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 1)
	ctx, cancel := context.WithCancel(context.Background())
	h.push.set(func(f *fakePush) {
		f.hook = func(push.Message) error {
			cancel()
			time.Sleep(200 * time.Millisecond) // the relay notices the closed connection
			return nil
		}
	})
	b, _ := json.Marshal(SendRequest{Messages: items(devs...)})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.srv.URL+"/v1/send", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+auth)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	for i := 0; ; i++ {
		n, _ := h.store.SentToday(context.Background(), id, h.clock.now())
		var status string
		_ = h.store.DB().QueryRow(`SELECT status FROM send_log`).Scan(&status)
		if n == 1 && status == store.SendOK {
			break
		}
		if i == 40 {
			t.Fatalf("delivered send not recorded: %d counted, status %q", n, status)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestGlobalQuotaHoldsAcrossServers(t *testing.T) {
	h := newHarness(t)
	idA, authA := h.register("A", "a@example.org", "")
	idB, authB := h.register("B", "b@example.org", "")
	devA, devB := h.handle(idA, "tok-a").Handle, h.handle(idB, "tok-b").Handle
	if _, err := h.store.DB().Exec(`INSERT INTO usage_daily (instance_id, day, sent) VALUES ('inst_other', ?, ?)`,
		store.Day(h.clock.now()), GlobalPerDay-1); err != nil {
		t.Fatal(err)
	}
	// Hold each FCM call until both servers are in, or long enough that only one ever will be.
	var mu sync.Mutex
	arrived := 0
	h.push.set(func(f *fakePush) {
		f.hook = func(push.Message) error {
			mu.Lock()
			arrived++
			mu.Unlock()
			for i := 0; i < 20; i++ {
				mu.Lock()
				n := arrived
				mu.Unlock()
				if n >= 2 {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			return nil
		}
	})
	var wg sync.WaitGroup
	for _, c := range [][2]string{{authA, devA}, {authB, devB}} {
		wg.Add(1)
		go func(auth, dev string) {
			defer wg.Done()
			h.send(auth, items(dev)...)
		}(c[0], c[1])
	}
	wg.Wait()
	if n := len(h.push.messages()); n != 1 {
		t.Fatalf("%d sent with one left under the global cap", n)
	}
}

func TestMissingHandlesDoNotDiluteHarvesting(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	victimID, _ := h.register("Victim", "v@example.org", "")
	id, auth := h.register("A", "a@example.org", "")
	own := h.devices(id, 75)
	missing := func(n int) []SendItem {
		out := make([]SendItem, n)
		for i := range out {
			out[i] = SendItem{Handle: fmt.Sprintf("h_gone%d", i), Ciphertext: ct}
		}
		return out
	}
	h.send(auth, append(items(own...), missing(25)...)...)
	for i := 0; i < 3; i++ {
		h.send(auth, missing(100)...)
	}
	foreign := make([]string, 25)
	for i := range foreign {
		foreign[i] = h.handle(victimID, fmt.Sprintf("victim-tok-%d", i)).Handle
	}
	if _, resp := h.send(auth, append(items(foreign...), missing(75)...)...); resp.StatusCode != 403 {
		t.Fatalf("25 of 100 live handles foreign: %d", resp.StatusCode)
	}
	if inst, _ := h.store.Instance(ctx, id); inst.Status != store.StatusSuspended {
		t.Fatalf("status %s", inst.Status)
	}
}

func TestManyForeignHandlesSuspendWhateverTheRatio(t *testing.T) {
	h := newHarness(t)
	victimID, _ := h.register("Victim", "v@example.org", "")
	id, auth := h.register("A", "a@example.org", "")
	foreign := make([]string, harvestForeignMax)
	for i := range foreign {
		foreign[i] = h.handle(victimID, fmt.Sprintf("victim-tok-%d", i)).Handle
	}
	if _, resp := h.send(auth, items(foreign...)...); resp.StatusCode != 403 {
		t.Fatalf("%d foreign handles: %d", harvestForeignMax, resp.StatusCode)
	}
	if inst, _ := h.store.Instance(context.Background(), id); inst.Status != store.StatusSuspended {
		t.Fatalf("status %s", inst.Status)
	}
}

func TestStaleUnregisteredKeepsARefreshedHandle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	id, auth := h.register("A", "a@example.org", "")
	dev := h.handle(id, "tok-a").Handle
	h.push.set(func(f *fakePush) {
		f.hook = func(m push.Message) error {
			if err := h.store.RefreshHandleToken(ctx, dev, id, "tok-b", h.clock.now()); err != nil {
				t.Error(err)
			}
			return push.ErrUnregistered
		}
	})
	if res, _ := h.send(auth, items(dev)...); res[0].Status != StatusFailed {
		t.Fatalf("%+v", res)
	}
	if hd, _ := h.store.Handle(ctx, dev); hd.RevokedAt != 0 || hd.FCMToken != "tok-b" {
		t.Fatalf("refreshed handle revoked: %+v", hd)
	}
}

func TestFCMOutagePausesTheRelay(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 4)
	h.relay.sendWorkers = 1
	h.push.set(func(f *fakePush) {
		f.errs["tok-0"] = &push.Error{Provider: push.FCM, Status: 503, RetryAfter: 120 * time.Second, Kind: push.ErrUnavailable}
	})
	res, resp := h.send(auth, items(devs[:3]...)...)
	if res[0].Status != StatusFailed || res[0].RetryAfterSeconds != 120 || h.push.calls.Load() != 1 {
		t.Fatalf("%+v after %d calls", res, h.push.calls.Load())
	}
	for _, r := range res[1:] {
		if r.Status != StatusRateLimited || r.RetryAfterSeconds != 120 {
			t.Fatalf("%+v", res)
		}
	}
	if resp.Header.Get("Retry-After") != "120" {
		t.Fatalf("Retry-After %q", resp.Header.Get("Retry-After"))
	}
	h.clock.add(60 * time.Second)
	if res, _ := h.send(auth, items(devs[3])...); res[0].Status != StatusRateLimited || res[0].RetryAfterSeconds != 60 {
		t.Fatalf("still paused: %+v", res)
	}
	h.clock.add(61 * time.Second)
	if res, _ := h.send(auth, items(devs[3])...); res[0].Status != StatusOK {
		t.Fatalf("after the pause: %+v", res)
	}

	// No Retry-After pauses a minute; FCM's own wait is kept even past the hour the backoff stops at.
	h.push.set(func(f *fakePush) {
		f.errs["tok-0"] = &push.Error{Provider: push.FCM, Status: 500, Kind: push.ErrUnavailable}
	})
	if res, _ := h.send(auth, items(devs[0])...); res[0].RetryAfterSeconds != 60 {
		t.Fatalf("%+v", res)
	}
	h.clock.add(61 * time.Second)
	h.push.set(func(f *fakePush) {
		f.errs["tok-0"] = &push.Error{Provider: push.FCM, Status: 503, RetryAfter: 5 * time.Hour, Kind: push.ErrUnavailable}
	})
	if res, _ := h.send(auth, items(devs[0])...); res[0].RetryAfterSeconds != 5*3600 {
		t.Fatalf("%+v", res)
	}
}

func TestFCMThrottleLimitsOnlyThatItem(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 2)
	h.push.set(func(f *fakePush) {
		f.errs["tok-0"] = &push.Error{Provider: push.FCM, Status: 429, Kind: push.ErrThrottled}
	})
	res, _ := h.send(auth, items(devs...)...)
	if res[0].Status != StatusRateLimited || res[0].RetryAfterSeconds != 60 || res[1].Status != StatusOK {
		t.Fatalf("%+v", res)
	}
	if n, _ := h.store.SentToday(context.Background(), id, h.clock.now()); n != 1 {
		t.Fatalf("throttled send counted: %d", n)
	}
}

func TestFCMInvalidArgumentIsInvalid(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	dev := h.handle(id, "tok").Handle
	h.push.set(func(f *fakePush) { f.errs["tok"] = fmt.Errorf("wrapped: %w", push.ErrInvalid) })
	if res, _ := h.send(auth, items(dev)...); res[0].Status != StatusInvalid {
		t.Fatalf("%+v", res)
	}
	if hd, _ := h.store.Handle(context.Background(), dev); hd.RevokedAt != 0 {
		t.Fatal("a refused message revoked the handle")
	}
}

func TestSlowUpstreamCannotHoldTheBatch(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 3)
	h.relay.batchDeadline, h.relay.sendLimit = 100*time.Millisecond, 200*time.Millisecond
	h.push.set(func(f *fakePush) { f.delay = 5 * time.Second })
	start := time.Now()
	res, _ := h.send(auth, items(devs...)...)
	if took := time.Since(start); took > 2*time.Second || count(res, StatusFailed) != 3 {
		t.Fatalf("took %s: %+v", took, res)
	}
}

func TestUnrecordedSuccessIsNotOK(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 2)
	h.relay.sendWorkers = 1
	if _, err := h.store.DB().Exec(`CREATE TRIGGER no_ok BEFORE UPDATE OF status ON send_log WHEN NEW.status = 'ok'
		BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}
	res, _ := h.send(auth, SendItem{Handle: devs[0], Ciphertext: ct, ID: "1:a"}, SendItem{Handle: devs[1], Ciphertext: ct, ID: "1:b"})
	if res[0].Status != StatusFailed || res[1].Status != StatusFailed || len(h.push.messages()) != 1 {
		t.Fatalf("%+v, %d pushed", res, len(h.push.messages()))
	}
	// The send stays pending, so a repeat waits and, after two minutes, sends again.
	if res, _ := h.send(auth, SendItem{Handle: devs[0], Ciphertext: ct, ID: "1:a"}); res[0].Status != StatusRateLimited {
		t.Fatalf("repeat while pending: %+v", res)
	}
}

func TestSentIDAnswersOKWhateverElseChanged(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	id, auth := h.register("A", "a@example.org", "")
	dev := h.devices(id, 1)[0]
	item := SendItem{Handle: dev, Ciphertext: ct, ID: "7:x"}
	first, _ := h.send(auth, item)
	if first[0].Status != StatusOK {
		t.Fatalf("%+v", first)
	}
	usage := func() store.Usage {
		u, _ := h.store.UsageFor(ctx, id, 1)
		return u[0]
	}
	before := usage()
	h.relay.pauseProvider(push.FCM, h.clock.now(), time.Hour)
	if res, _ := h.send(auth, item); res[0].Status != StatusOK || res[0].MessageID != first[0].MessageID {
		t.Fatalf("repeat during a pause: %+v", res)
	}
	if err := h.store.RevokeHandle(ctx, dev, h.clock.now()); err != nil {
		t.Fatal(err)
	}
	if res, _ := h.send(auth, item); res[0].Status != StatusOK || res[0].MessageID != first[0].MessageID {
		t.Fatalf("repeat after the handle went: %+v", res)
	}
	if after := usage(); after != before || h.push.calls.Load() != 1 {
		t.Fatalf("a repeat was counted or sent: %+v -> %+v", before, after)
	}
}

func TestQuotaChangeAppliesMidBatch(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 3)
	h.relay.sendWorkers = 1
	lower := func(perMinute, perDay int) {
		var once sync.Once
		h.push.set(func(f *fakePush) {
			f.hook = func(push.Message) error {
				once.Do(func() {
					if err := h.store.SetQuota(context.Background(), id, perMinute, perDay); err != nil {
						t.Error(err)
					}
				})
				return nil
			}
		})
	}
	lower(0, 1)
	res, _ := h.send(auth, items(devs...)...)
	if count(res, StatusOK) != 1 || count(res, StatusRateLimited) != 2 {
		t.Fatalf("daily quota lowered mid-batch: %+v", res)
	}
	h.clock.add(24 * time.Hour)
	_ = h.store.SetQuota(context.Background(), id, 10_000, 10_000)
	lower(1, 10_000)
	res, _ = h.send(auth, items(devs...)...)
	if count(res, StatusOK) != 1 || count(res, StatusRateLimited) != 2 {
		t.Fatalf("minute quota lowered mid-batch: %+v", res)
	}
}

func TestFCMThrottleCoolsTheDevice(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 2)
	h.relay.sendWorkers = 1
	h.push.set(func(f *fakePush) {
		f.errs["tok-0"] = &push.Error{Provider: push.FCM, Status: 429, RetryAfter: 30 * time.Second, Kind: push.ErrThrottled}
	})
	res, _ := h.send(auth, items(devs[0], devs[0], devs[1])...)
	if res[0].Status != StatusRateLimited || res[0].RetryAfterSeconds != 30 || res[1].Status != StatusRateLimited ||
		res[1].RetryAfterSeconds != 30 || res[2].Status != StatusOK || h.push.calls.Load() != 2 {
		t.Fatalf("%+v after %d calls", res, h.push.calls.Load())
	}
	h.push.set(func(f *fakePush) { delete(f.errs, "tok-0") })
	h.clock.add(31 * time.Second)
	if res, _ := h.send(auth, items(devs[0])...); res[0].Status != StatusOK {
		t.Fatalf("after the cooldown: %+v", res)
	}
}

func TestRepeatedOutagesBackOff(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	dev := h.devices(id, 1)[0]
	down := func(on bool) {
		h.push.set(func(f *fakePush) {
			if on {
				f.errs["tok-0"] = &push.Error{Provider: push.FCM, Status: 503, Kind: push.ErrUnavailable}
			} else {
				delete(f.errs, "tok-0")
			}
		})
	}
	down(true)
	for _, want := range []int{60, 120, 240} {
		res, _ := h.send(auth, items(dev)...)
		if res[0].Status != StatusFailed || res[0].RetryAfterSeconds != want {
			t.Fatalf("want a %d s pause: %+v", want, res)
		}
		h.clock.add(time.Duration(want+1) * time.Second)
	}
	down(false)
	if res, _ := h.send(auth, items(dev)...); res[0].Status != StatusOK {
		t.Fatalf("%+v", res)
	}
	down(true)
	h.clock.add(time.Minute)
	if res, _ := h.send(auth, items(dev)...); res[0].RetryAfterSeconds != 60 {
		t.Fatalf("a success must reset the backoff: %+v", res)
	}
}

func TestSuccessDuringAPauseKeepsItAndCannotPanic(t *testing.T) {
	h := newHarness(t)
	now := h.clock.now()
	// 503, success, 503 from three sends that were in flight together.
	h.relay.pauseProvider(push.FCM, now, 0)
	h.relay.providerRecovered(push.FCM, now)
	if d := h.relay.pauseProvider(push.FCM, now, 0); d != OutagePauseDefault {
		t.Fatalf("pause %s", d)
	}
	if d := h.relay.pausedFor(push.FCM, now); d != OutagePauseDefault {
		t.Fatalf("a success cleared an outstanding pause: %s left", d)
	}
	// The outage goes on after the pause: the backoff did not restart.
	h.clock.add(OutagePauseDefault)
	if d := h.relay.pauseProvider(push.FCM, h.clock.now(), 0); d != 2*OutagePauseDefault {
		t.Fatalf("next pause %s", d)
	}
}

func TestWorkerPanicFailsOnlyThatItem(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	devs := h.devices(id, 2)
	h.push.set(func(f *fakePush) {
		f.hook = func(m push.Message) error {
			if m.Token == "tok-0" {
				panic("boom")
			}
			return nil
		}
	})
	res, resp := h.send(auth, items(devs...)...)
	if resp.StatusCode != 200 || res[0].Status != StatusFailed || res[1].Status != StatusOK {
		t.Fatalf("%d %+v", resp.StatusCode, res)
	}
	// The panicked send's reservation is given back once it is older than the pending timeout.
	if err := h.store.SetQuota(context.Background(), id, 10_000, 2); err != nil {
		t.Fatal(err)
	}
	h.push.set(func(f *fakePush) { f.hook = nil })
	h.clock.add(store.PendingTimeout + time.Second)
	if res, _ := h.send(auth, items(devs[1])...); res[0].Status != StatusOK {
		t.Fatalf("quota still held by the abandoned send: %+v", res)
	}
}

func TestDuplicateIDInABatchSpendsNoLimit(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	dev := h.devices(id, 1)[0]
	if err := h.store.SetQuota(context.Background(), id, 1, 10_000); err != nil {
		t.Fatal(err)
	}
	h.relay.sendWorkers = 1
	item := SendItem{Handle: dev, Ciphertext: ct, ID: "9:dup"}
	res, _ := h.send(auth, item, item)
	if res[0].Status != StatusOK || res[1].Status != StatusOK || res[1].MessageID != res[0].MessageID || len(h.push.messages()) != 1 {
		t.Fatalf("%+v", res)
	}
	if u, _ := h.store.UsageFor(context.Background(), id, 1); u[0].RateLimited != 0 || u[0].Sent != 1 {
		t.Fatalf("%+v", u)
	}
}

func TestCooldownKeepsTheLaterExpiry(t *testing.T) {
	h := newHarness(t)
	now := h.clock.now()
	h.relay.coolHandle("h_x", now.Add(time.Hour), now)
	if until := h.relay.coolHandle("h_x", now.Add(time.Minute), now); !until.Equal(now.Add(time.Hour)) {
		t.Fatalf("effective expiry %s", until)
	}
	if d := h.relay.cooledFor("h_x", now); d != time.Hour {
		t.Fatalf("cooldown shrank to %s", d)
	}
}

func TestFCMThrottleKeepsALongWait(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	dev := h.devices(id, 1)[0]
	h.push.set(func(f *fakePush) {
		f.errs["tok-0"] = &push.Error{Provider: push.FCM, Status: 429, RetryAfter: 2 * time.Hour, Kind: push.ErrThrottled}
	})
	if res, _ := h.send(auth, items(dev)...); res[0].RetryAfterSeconds != 7200 {
		t.Fatalf("%+v", res)
	}
	if d := h.relay.cooledFor(dev, h.clock.now()); d != 2*time.Hour {
		t.Fatalf("cooldown %s", d)
	}
}
