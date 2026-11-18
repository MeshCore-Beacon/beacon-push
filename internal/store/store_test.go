// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

var t0 = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func inst(id, email string) Instance {
	return Instance{ID: id, Name: id, Email: email, SecretHash: []byte("h"), TermsVersion: 1, TermsAcceptedAt: Ms(t0), CreatedAt: Ms(t0)}
}

func TestReopenKeepsSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	ctx := context.Background()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInstance(ctx, inst("inst_a", "a@x.org"), 2); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Instance(ctx, "inst_a"); err != nil {
		t.Fatal(err)
	}
}

func TestCreateInstanceLimitHoldsUnderRace(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- s.CreateInstance(ctx, inst("inst_"+string(rune('a'+i)), "same@x.org"), 2)
		}(i)
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrLimit):
			t.Fatal(err)
		}
	}
	if n, _ := s.CountInstancesByEmail(ctx, "same@x.org"); ok != 2 || n != 2 {
		t.Fatalf("created %d, stored %d", ok, n)
	}
}

func TestEmailTokenOnce(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.CreateEmailToken(ctx, []byte("tok"), "register", "a@x.org", `{"name":"A"}`, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ConsumeEmailToken(ctx, []byte("tok"), "login", t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong purpose: %v", err)
	}
	email, payload, err := s.ConsumeEmailToken(ctx, []byte("tok"), "register", t0)
	if err != nil || email != "a@x.org" || payload != `{"name":"A"}` {
		t.Fatalf("%q %q %v", email, payload, err)
	}
	if _, _, err := s.ConsumeEmailToken(ctx, []byte("tok"), "register", t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second use: %v", err)
	}
}

func TestHandleLifecycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.CreateInstance(ctx, inst("inst_a", "a@x.org"), 2)
	h1, err := s.UpsertHandle(ctx, "h_1", "inst_a", "ios", "tok", "sandbox", []byte("s1"), t0)
	if err != nil || h1 != "h_1" {
		t.Fatalf("%q %v", h1, err)
	}
	if h, _ := s.UpsertHandle(ctx, "h_2", "inst_a", "ios", "tok", "sandbox", []byte("s2"), t0); h != "h_1" {
		t.Fatalf("same token: %q", h)
	}
	if got, _ := s.Handle(ctx, "h_1"); string(got.SecretHash) != "s2" {
		t.Fatal("secret not replaced")
	}
	// A second handle that later refreshes onto the first one's token takes it over.
	_, _ = s.UpsertHandle(ctx, "h_3", "inst_a", "android", "other", "", []byte("s3"), t0)
	if err := s.RefreshHandleToken(ctx, "h_3", "inst_a", "tok", "", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Handle(ctx, "h_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the old holder of the token should be gone: %v", err)
	}
	if err := s.RevokeHandle(ctx, "h_3", t0); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountHandles(ctx, "inst_a"); n != 0 {
		t.Fatalf("live handles %d", n)
	}
	if h, _ := s.UpsertHandle(ctx, "h_4", "inst_a", "android", "tok", "", []byte("s4"), t0); h != "h_4" {
		t.Fatalf("a revoked registration must be replaced: %q", h)
	}
}

func TestUsageAndCleanup(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.CreateInstance(ctx, inst("inst_a", "a@x.org"), 2)
	_, _ = s.UpsertHandle(ctx, "h_1", "inst_a", "ios", "tok", "sandbox", []byte("s"), t0)
	for i, at := range []time.Time{t0.Add(-40 * 24 * time.Hour), t0} {
		id := "m_" + string(rune('a'+i))
		if o, _, err := s.Reserve(ctx, reservation(id, "h_1", "", at)); err != nil || o != Reserved {
			t.Fatal(o, err)
		}
		if err := s.FinishSend(ctx, id, true, at); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.BumpUsage(ctx, "inst_a", t0, UsageRateLimited)
	if n, _ := s.SentToday(ctx, "inst_a", t0); n != 1 {
		t.Fatalf("sent today %d", n)
	}
	if n, _ := s.GlobalSentToday(ctx, t0); n != 1 {
		t.Fatalf("global %d", n)
	}
	if n, _ := s.HandleSentSince(ctx, "h_1", t0.Add(-time.Hour)); n != 1 {
		t.Fatalf("handle %d", n)
	}
	if err := s.Cleanup(ctx, t0); err != nil {
		t.Fatal(err)
	}
	var logRows int
	_ = s.db.QueryRow(`SELECT count(*) FROM send_log`).Scan(&logRows)
	if logRows != 1 {
		t.Fatalf("send log rows after cleanup %d", logRows)
	}
	u, _ := s.UsageFor(ctx, "inst_a", 14)
	if len(u) != 2 || u[0].Day != "2026-11-17" || u[0].Sent != 1 || u[0].RateLimited != 1 {
		t.Fatalf("%+v", u)
	}
	if err := s.BumpUsage(ctx, "inst_a", t0, "sent; DROP TABLE x"); err == nil {
		t.Fatal("unknown usage field accepted")
	}
}

func TestDomainCheckState(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	i := inst("inst_a", "a@x.org")
	i.URL = "https://b.example.org"
	_ = s.CreateInstance(ctx, i, 2)
	if due, _ := s.DueForDomainCheck(ctx, t0); len(due) != 1 {
		t.Fatalf("due %d", len(due))
	}
	_ = s.SetDomainCheck(ctx, "inst_a", true, t0)
	_ = s.SetDomainCheck(ctx, "inst_a", true, t0.Add(time.Hour))
	got, _ := s.Instance(ctx, "inst_a")
	if got.DomainVerifiedAt != Ms(t0) || got.DomainCheckedAt != Ms(t0.Add(time.Hour)) {
		t.Fatalf("%+v", got)
	}
	if due, _ := s.DueForDomainCheck(ctx, t0); len(due) != 0 {
		t.Fatal("just checked, not due")
	}
	_ = s.SetDomainCheck(ctx, "inst_a", false, t0.Add(2*time.Hour))
	if got, _ := s.Instance(ctx, "inst_a"); got.DomainVerifiedAt != 0 {
		t.Fatal("failure must clear verification")
	}
}

func reservation(msgID, handle, clientID string, at time.Time) Reservation {
	return Reservation{MessageID: msgID, InstanceID: "inst_a", Handle: handle, ClientID: clientID, At: at, Size: 10,
		CiphertextSHA256: []byte("x"), InstancePerDay: 100, GlobalPerDay: 100, HandlePerDay: 100}
}

func TestReserveCountsPendingSends(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.CreateInstance(ctx, inst("inst_a", "a@x.org"), 2)
	_ = s.CreateInstance(ctx, inst("inst_b", "b@x.org"), 2)
	_, _ = s.UpsertHandle(ctx, "h_1", "inst_a", "ios", "tok", "sandbox", []byte("s"), t0)

	// A pending send already holds the device's, the server's and the relay's quota.
	r := reservation("m_1", "h_1", "", t0)
	r.HandlePerDay = 1
	if o, _, _ := s.Reserve(ctx, r); o != Reserved {
		t.Fatalf("first: %v", o)
	}
	r.MessageID = "m_2"
	if o, _, _ := s.Reserve(ctx, r); o != OverHandleDay {
		t.Fatalf("device cap with a pending send: %v", o)
	}
	r.HandlePerDay, r.InstancePerDay = 100, 1
	if o, _, _ := s.Reserve(ctx, r); o != OverInstanceDay {
		t.Fatalf("server cap: %v", o)
	}
	r.InstancePerDay, r.GlobalPerDay = 100, 1
	if o, _, _ := s.Reserve(ctx, r); o != OverGlobalDay {
		t.Fatalf("global cap: %v", o)
	}
	// A failed send gives its quota back.
	if err := s.FinishSend(ctx, "m_1", false, t0); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.SentToday(ctx, "inst_a", t0); n != 0 {
		t.Fatalf("released send still counted: %d", n)
	}
	if n, _ := s.HandleSentSince(ctx, "h_1", t0.Add(-time.Hour)); n != 0 {
		t.Fatalf("failed send counted for the device: %d", n)
	}
	if o, _, _ := s.Reserve(ctx, r); o != Reserved {
		t.Fatalf("after release: %v", o)
	}
	if err := s.SetStatus(ctx, "inst_a", StatusSuspended, nil, t0); err != nil {
		t.Fatal(err)
	}
	r.MessageID, r.GlobalPerDay = "m_3", 100
	if o, _, _ := s.Reserve(ctx, r); o != NotActive {
		t.Fatalf("suspended server reserved: %v", o)
	}
}

func TestReserveClientID(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.CreateInstance(ctx, inst("inst_a", "a@x.org"), 2)
	_, _ = s.UpsertHandle(ctx, "h_1", "inst_a", "ios", "tok", "sandbox", []byte("s"), t0)
	if o, _, _ := s.Reserve(ctx, reservation("m_1", "h_1", "n1", t0)); o != Reserved {
		t.Fatalf("%v", o)
	}
	if o, _, _ := s.Reserve(ctx, reservation("m_2", "h_1", "n1", t0.Add(time.Minute))); o != InFlight {
		t.Fatalf("in flight: %v", o)
	}
	// An abandoned reservation counts as failed after the timeout and gives its quota back.
	if o, id, _ := s.Reserve(ctx, reservation("m_3", "h_1", "n1", t0.Add(PendingTimeout+time.Second))); o != Reserved || id != "m_3" {
		t.Fatalf("stale: %v %s", o, id)
	}
	if n, _ := s.SentToday(ctx, "inst_a", t0); n != 1 {
		t.Fatalf("stale reservation still counted: %d", n)
	}
	if err := s.FinishSend(ctx, "m_3", true, t0); err != nil {
		t.Fatal(err)
	}
	if o, id, _ := s.Reserve(ctx, reservation("m_4", "h_1", "n1", t0.Add(time.Hour))); o != AlreadySent || id != "m_3" {
		t.Fatalf("repeat of a sent id: %v %s", o, id)
	}
	if o, _, _ := s.Reserve(ctx, reservation("m_5", "h_1", "n2", t0)); o != Reserved {
		t.Fatalf("%v", o)
	}
	_ = s.FinishSend(ctx, "m_5", false, t0)
	if o, _, _ := s.Reserve(ctx, reservation("m_6", "h_1", "n2", t0)); o != Reserved {
		t.Fatalf("repeat of a failed id: %v", o)
	}
	// Another server may use the same id.
	_ = s.CreateInstance(ctx, inst("inst_b", "b@x.org"), 2)
	r := reservation("m_7", "h_1", "n1", t0)
	r.InstanceID = "inst_b"
	if o, _, _ := s.Reserve(ctx, r); o != Reserved {
		t.Fatalf("other server: %v", o)
	}
}

func TestSuspendIfActiveKeepsABan(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.CreateInstance(ctx, inst("inst_a", "a@x.org"), 2)
	_ = s.SetStatus(ctx, "inst_a", StatusBanned, nil, t0)
	if done, err := s.SuspendIfActive(ctx, "inst_a"); done || err != nil {
		t.Fatalf("%v %v", done, err)
	}
	if i, _ := s.Instance(ctx, "inst_a"); i.Status != StatusBanned {
		t.Fatalf("ban overwritten: %s", i.Status)
	}
	_ = s.SetStatus(ctx, "inst_a", StatusActive, nil, t0)
	if done, _ := s.SuspendIfActive(ctx, "inst_a"); !done {
		t.Fatal("active server not suspended")
	}
}

func TestRevokeHandleTokenNeedsTheSameRegistration(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.CreateInstance(ctx, inst("inst_a", "a@x.org"), 2)
	_, _ = s.UpsertHandle(ctx, "h_1", "inst_a", "ios", "tok-a", "sandbox", []byte("s"), t0)
	first, _ := s.Handle(ctx, "h_1")
	_ = s.RefreshHandleToken(ctx, "h_1", "inst_a", "tok-b", "production", t0.Add(time.Second))
	if err := s.RevokeHandleToken(ctx, first, t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old token revoked: %v", err)
	}
	// Only the environment changes.
	cur, _ := s.Handle(ctx, "h_1")
	_ = s.RefreshHandleToken(ctx, "h_1", "inst_a", "tok-b", "sandbox", t0.Add(2*time.Second))
	if err := s.RevokeHandleToken(ctx, cur, t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old environment revoked: %v", err)
	}
	// The same token and environment, registered again later.
	cur, _ = s.Handle(ctx, "h_1")
	_, _ = s.UpsertHandle(ctx, "h_2", "inst_a", "ios", "tok-b", "sandbox", []byte("s2"), t0.Add(3*time.Second))
	if err := s.RevokeHandleToken(ctx, cur, t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-registered handle revoked: %v", err)
	}
	cur, _ = s.Handle(ctx, "h_1")
	if err := s.RevokeHandleToken(ctx, cur, t0); err != nil {
		t.Fatal(err)
	}
}

func TestStalePendingSendsAreReleased(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.CreateInstance(ctx, inst("inst_a", "a@x.org"), 2)
	_, _ = s.UpsertHandle(ctx, "h_1", "inst_a", "ios", "tok", "sandbox", []byte("s"), t0)
	r := reservation("m_1", "h_1", "", t0)
	r.HandlePerDay = 1
	if o, _, _ := s.Reserve(ctx, r); o != Reserved {
		t.Fatalf("%v", o)
	}
	if err := s.Cleanup(ctx, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.SentToday(ctx, "inst_a", t0); n != 1 {
		t.Fatalf("a fresh pending send was released: %d", n)
	}
	if err := s.Cleanup(ctx, t0.Add(PendingTimeout+time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.SentToday(ctx, "inst_a", t0); n != 0 {
		t.Fatalf("stale pending send still counted: %d", n)
	}
	var status string
	_ = s.db.QueryRow(`SELECT status FROM send_log WHERE message_id = 'm_1'`).Scan(&status)
	if status != SendFailed {
		t.Fatalf("status %q", status)
	}
	// Reserve releases them too, without waiting for cleanup.
	r.MessageID, r.At = "m_2", t0.Add(time.Hour)
	if o, _, _ := s.Reserve(ctx, r); o != Reserved {
		t.Fatalf("%v", o)
	}
	r.MessageID, r.At = "m_3", t0.Add(time.Hour+PendingTimeout+time.Second)
	if o, _, _ := s.Reserve(ctx, r); o != Reserved {
		t.Fatalf("the device's quota is still held by a stale send: %v", o)
	}
}

func TestHandleKeepsItsAPNsEnvironment(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.CreateInstance(ctx, inst("inst_a", "a@x.org"), 2)
	if _, err := s.UpsertHandle(ctx, "h_1", "inst_a", "ios", "aa", "sandbox", []byte("s"), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshHandleToken(ctx, "h_1", "inst_a", "bb", "production", t0); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.Handle(ctx, "h_1"); h.Token != "bb" || h.APNsEnv != "production" || h.Platform != "ios" {
		t.Fatalf("%+v", h)
	}
	if _, err := s.UpsertHandle(ctx, "h_2", "inst_a", "android", "cc", "", []byte("s"), t0); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.Handle(ctx, "h_2"); h.APNsEnv != "" {
		t.Fatalf("%+v", h)
	}
	// The schema refuses an environment that does not fit the platform.
	for _, c := range []struct{ platform, env string }{{"ios", ""}, {"ios", "staging"}, {"android", "sandbox"}} {
		if _, err := s.UpsertHandle(ctx, "h_x", "inst_a", c.platform, "dd", c.env, []byte("s"), t0); err == nil {
			t.Errorf("%s with %q stored", c.platform, c.env)
		}
	}
}

func TestMigrationKeepsHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	ctx := context.Background()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	// Roll the schema back to the last version with fcm_token, as a database from before APNs would be.
	db := s.DB()
	for _, q := range []string{
		`DROP TABLE handles`,
		`CREATE TABLE handles (
			handle TEXT PRIMARY KEY,
			secret_hash BLOB NOT NULL,
			instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
			platform TEXT NOT NULL CHECK (platform IN ('ios', 'android')),
			fcm_token TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			refreshed_at INTEGER NOT NULL,
			last_sent_at INTEGER NOT NULL DEFAULT 0,
			revoked_at INTEGER NOT NULL DEFAULT 0,
			UNIQUE (instance_id, fcm_token)
		)`,
		`PRAGMA user_version = 3`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateInstance(ctx, inst("inst_a", "a@x.org"), 2); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		handle, platform, token string
		revoked                 int64
	}{{"h_a", "android", "fcm-a", 0}, {"h_i", "ios", "fcm-i", 0}, {"h_r", "android", "fcm-r", 7}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO handles (handle, secret_hash, instance_id, platform, fcm_token, created_at,
			refreshed_at, last_sent_at, revoked_at) VALUES (?, ?, 'inst_a', ?, ?, 1, 2, 3, ?)`,
			r.handle, []byte("s-"+r.handle), r.platform, r.token, r.revoked); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := s.Handle(ctx, "h_a")
	if err != nil || a.Token != "fcm-a" || a.APNsEnv != "" || string(a.SecretHash) != "s-h_a" || a.CreatedAt != 1 ||
		a.RefreshedAt != 2 || a.LastSentAt != 3 || a.RevokedAt != 0 {
		t.Fatalf("%+v %v", a, err)
	}
	if r, _ := s.Handle(ctx, "h_r"); r.RevokedAt != 7 || r.Token != "fcm-r" {
		t.Fatalf("%+v", r)
	}
	// A live iOS handle held an FCM token: it is kept but revoked, so the app registers again.
	if i, _ := s.Handle(ctx, "h_i"); i.RevokedAt == 0 || i.Token != "fcm-i" || i.Platform != "ios" {
		t.Fatalf("%+v", i)
	}
	// The unique pair and the cascade survived the rebuild.
	if h, _ := s.UpsertHandle(ctx, "h_b", "inst_a", "android", "fcm-a", "", []byte("s"), t0); h != "h_a" {
		t.Fatalf("same token got %q", h)
	}
	if _, err := s.DB().ExecContext(ctx, `DELETE FROM instances WHERE id = 'inst_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Handle(ctx, "h_a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("handles outlived their server: %v", err)
	}
}
