// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MeshCore-Beacon/beacon-push/internal/relay"
	"github.com/MeshCore-Beacon/beacon-push/internal/store"
)

func TestAdminCommands(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	if err := st.CreateInstance(ctx, store.Instance{ID: "inst_abc", Name: "Ottawa Mesh", Email: "Op@Example.org", SecretHash: []byte("h"),
		TermsVersion: 1, CreatedAt: store.Ms(now)}, 2); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := runAdmin(ctx, st, args, &out, now)
		return out.String(), err
	}

	if out, err := run("list"); err != nil || !strings.Contains(out, "inst_abc") || !strings.Contains(out, "Ottawa Mesh") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if out, err := run("show", "inst_abc"); err != nil || !strings.Contains(out, "email (30/min, 500/day)") || !strings.Contains(out, "no URL") {
		t.Fatalf("show: %v\n%s", err, out)
	}
	if out, err := run("set-quota", "inst_abc", "60", "2000"); err != nil || !strings.Contains(out, "custom tier, 60/min, 2000/day") {
		t.Fatalf("set-quota: %v\n%s", err, out)
	}
	if _, err := run("suspend", "inst_abc"); err != nil {
		t.Fatal(err)
	}
	if i, _ := st.Instance(ctx, "inst_abc"); i.Status != store.StatusSuspended {
		t.Fatalf("status %s", i.Status)
	}
	if _, err := run("ban", "inst_abc"); err != nil {
		t.Fatal(err)
	}
	if banned, _ := st.EmailBanned(ctx, relay.EmailHash("op@example.org")); !banned {
		t.Fatal("ban must remember the email")
	}
	if _, err := run("unsuspend", "inst_abc"); err == nil {
		t.Fatal("unsuspend must not lift a ban")
	}
	copyPath := filepath.Join(t.TempDir(), "copy.db")
	if out, err := run("backup", copyPath); err != nil || !strings.Contains(out, "wrote") {
		t.Fatalf("backup: %v %s", err, out)
	}
	cp, err := store.Open(ctx, copyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	if _, err := cp.Instance(ctx, "inst_abc"); err != nil {
		t.Fatalf("backup copy: %v", err)
	}
	if _, err := run("backup", copyPath); err == nil {
		t.Fatal("backup must not overwrite a file")
	}
	if err := st.CreateInstance(ctx, store.Instance{ID: "inst_del", Name: "Gone", Email: "gone@example.org", SecretHash: []byte("h"),
		TermsVersion: 1, CreatedAt: store.Ms(now)}, 2); err != nil {
		t.Fatal(err)
	}
	if out, err := run("delete", "inst_del"); err != nil || !strings.Contains(out, "deleted inst_del") {
		t.Fatalf("delete: %v\n%s", err, out)
	}
	if _, err := st.Instance(ctx, "inst_del"); err == nil {
		t.Fatal("delete left the server")
	}
	if banned, _ := st.EmailBanned(ctx, relay.EmailHash("gone@example.org")); banned {
		t.Fatal("delete must not ban the email")
	}
	if _, err := run("delete", "inst_del"); err == nil || !strings.Contains(err.Error(), "no server inst_del") {
		t.Fatalf("delete of unknown id: %v", err)
	}
	for _, bad := range [][]string{{"show"}, {"show", "inst_nope"}, {"set-quota", "inst_abc", "x", "1"}, {"delete"}, {"frobnicate"}} {
		if _, err := run(bad...); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
