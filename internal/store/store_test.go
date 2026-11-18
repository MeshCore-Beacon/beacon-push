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
	h1, err := s.UpsertHandle(ctx, "h_1", "inst_a", "ios", "tok", []byte("s1"), t0)
	if err != nil || h1 != "h_1" {
		t.Fatalf("%q %v", h1, err)
	}
	if h, _ := s.UpsertHandle(ctx, "h_2", "inst_a", "ios", "tok", []byte("s2"), t0); h != "h_1" {
		t.Fatalf("same token: %q", h)
	}
	if got, _ := s.Handle(ctx, "h_1"); string(got.SecretHash) != "s2" {
		t.Fatal("secret not replaced")
	}
	// A second handle that later refreshes onto the first one's token takes it over.
	_, _ = s.UpsertHandle(ctx, "h_3", "inst_a", "android", "other", []byte("s3"), t0)
	if err := s.RefreshHandleToken(ctx, "h_3", "inst_a", "tok", t0); err != nil {
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
	if h, _ := s.UpsertHandle(ctx, "h_4", "inst_a", "android", "tok", []byte("s4"), t0); h != "h_4" {
		t.Fatalf("a revoked registration must be replaced: %q", h)
	}
}

func TestUsageAndCleanup(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.CreateInstance(ctx, inst("inst_a", "a@x.org"), 2)
	_, _ = s.UpsertHandle(ctx, "h_1", "inst_a", "ios", "tok", []byte("s"), t0)
	for i, at := range []time.Time{t0.Add(-40 * 24 * time.Hour), t0} {
		if err := s.RecordSend(ctx, Send{MessageID: "m_" + string(rune('a'+i)), InstanceID: "inst_a", Handle: "h_1", Status: "ok", At: at,
			Size: 10, CiphertextSHA256: []byte("x")}); err != nil {
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
