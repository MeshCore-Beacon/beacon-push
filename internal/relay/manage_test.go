// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/MeshCore-Beacon/beacon-push/internal/store"
)

var (
	manageLinkRe = regexp.MustCompile(`/manage/open#token=([A-Za-z0-9_-]+)`)
	sessionRe    = regexp.MustCompile(`name="session" value="([A-Za-z0-9_-]+)"`)
)

// manageLink asks for a manage link and returns its token, or "" when no mail went out.
func (h *harness) manageLink(email string) string {
	h.t.Helper()
	before := len(h.mail.Messages())
	if code, body := h.form("/manage", h.nextIP(), url.Values{"email": {email}}); code != 200 || !strings.Contains(body, "Check your email") {
		h.t.Fatalf("manage %d: %s", code, body)
	}
	msgs := h.mail.Messages()
	if len(msgs) == before {
		return ""
	}
	m := manageLinkRe.FindStringSubmatch(msgs[len(msgs)-1].Text)
	if m == nil {
		h.t.Fatalf("no link in %q", msgs[len(msgs)-1].Text)
	}
	return m[1]
}

// openManage follows a manage link and returns the list page and its session.
func (h *harness) openManage(email string) (string, string) {
	h.t.Helper()
	token := h.manageLink(email)
	if token == "" {
		h.t.Fatal("no manage mail")
	}
	code, body := h.form("/manage/open", h.nextIP(), url.Values{"token": {token}})
	m := sessionRe.FindStringSubmatch(body)
	if code != 200 || m == nil {
		h.t.Fatalf("open %d: %s", code, body)
	}
	return body, m[1]
}

func TestManageNewSecret(t *testing.T) {
	h := newHarness(t)
	id, oldAuth := h.register("A", "a@example.org", "")
	dev := h.handle(id, "tok")
	h.send(oldAuth, SendItem{Handle: dev.Handle, Ciphertext: ct})
	list, session := h.openManage("A@example.org")
	if !strings.Contains(list, id) {
		t.Fatalf("server not listed: %s", list)
	}
	for _, want := range []string{"<strong>1</strong> sent today <span>of 500</span>", `<progress value="1" max="500">`,
		"Up to 30 a minute on the email tier", "<dt>Phones</dt><dd>1</dd>", "<dt>Sent in 7 days</dt><dd>1</dd>"} {
		if !strings.Contains(list, want) {
			t.Errorf("usage %q missing", want)
		}
	}
	code, body := h.form("/manage/secret", h.nextIP(), url.Values{"session": {session}, "push_id": {id}})
	secret := secretRe.FindStringSubmatch(body)
	if code != 200 || secret == nil || !strings.Contains(body, "New secret for A") {
		t.Fatalf("secret %d: %s", code, body)
	}
	if resp := h.api("POST", "/v1/hello", oldAuth, nil, nil); resp.StatusCode != 401 {
		t.Fatalf("old secret still works: %d", resp.StatusCode)
	}
	newAuth := id + "." + secret[1]
	if res, resp := h.send(newAuth, SendItem{Handle: dev.Handle, Ciphertext: ct}); resp.StatusCode != 200 || res[0].Status != StatusOK {
		t.Fatalf("new secret send: %d %+v", resp.StatusCode, res)
	}
	noticed := false
	for _, m := range h.mail.Messages() {
		noticed = noticed || (m.To == "a@example.org" && strings.Contains(m.Subject, "secret was changed"))
	}
	if !noticed {
		t.Fatal("no change notice mailed")
	}
	// The session is used up.
	if code, _ := h.form("/manage/secret", h.nextIP(), url.Values{"session": {session}, "push_id": {id}}); code != 400 {
		t.Fatalf("session reused: %d", code)
	}
}

func TestManageRemoveFreesTheSlot(t *testing.T) {
	h := newHarness(t)
	one, _ := h.register("One", "op@example.org", "")
	h.register("Two", "op@example.org", "")
	_, session := h.openManage("op@example.org")

	// Without the box ticked nothing goes, and a fresh session comes back.
	code, body := h.form("/manage/remove", h.nextIP(), url.Values{"session": {session}, "push_id": {one}})
	m := sessionRe.FindStringSubmatch(body)
	if code != 200 || m == nil || !strings.Contains(body, "Tick the box") {
		t.Fatalf("unconfirmed remove %d: %s", code, body)
	}
	code, body = h.form("/manage/remove", h.nextIP(), url.Values{"session": {m[1]}, "push_id": {one}, "confirm": {"on"}})
	if code != 200 || !strings.Contains(body, "One was removed") || strings.Contains(body, one) {
		t.Fatalf("remove %d: %s", code, body)
	}
	if _, err := h.store.Instance(context.Background(), one); err != store.ErrNotFound {
		t.Fatalf("still there: %v", err)
	}
	h.register("Three", "op@example.org", "")
}

func TestManageRefusals(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	idA, _ := h.register("A", "a@example.org", "")
	idB, _ := h.register("B", "b@example.org", "")

	// Unknown addresses get the same page and no mail.
	if h.manageLink("nobody@example.org") != "" {
		t.Fatal("mail sent to an address with no servers")
	}
	// The honeypot sends nothing.
	before := len(h.mail.Messages())
	if code, _ := h.form("/manage", h.nextIP(), url.Values{"email": {"a@example.org"}, "website": {"x"}}); code != 200 || len(h.mail.Messages()) != before {
		t.Fatal("honeypot sent mail")
	}

	// A's session cannot touch B's server.
	_, session := h.openManage("a@example.org")
	if code, _ := h.form("/manage/secret", h.nextIP(), url.Values{"session": {session}, "push_id": {idB}}); code != 403 {
		t.Fatalf("cross-account secret: %d", code)
	}

	// Sessions expire.
	_, session = h.openManage("a@example.org")
	h.clock.add(ManageSessionLifetime + time.Second)
	if code, _ := h.form("/manage/secret", h.nextIP(), url.Values{"session": {session}, "push_id": {idA}}); code != 400 {
		t.Fatalf("expired session: %d", code)
	}

	// Links are single use and expire.
	token := h.manageLink("a@example.org")
	h.form("/manage/open", h.nextIP(), url.Values{"token": {token}})
	if code, _ := h.form("/manage/open", h.nextIP(), url.Values{"token": {token}}); code != 400 {
		t.Fatalf("link reused: %d", code)
	}
	token = h.manageLink("a@example.org")
	h.clock.add(ManageLinkLifetime + time.Second)
	if code, _ := h.form("/manage/open", h.nextIP(), url.Values{"token_manual": {"token=" + token}}); code != 400 {
		t.Fatalf("late link: %d", code)
	}

	// A banned server's email gets nothing, and an open session stops working.
	_, session = h.openManage("b@example.org")
	if err := h.store.SetStatus(ctx, idB, store.StatusBanned, EmailHash("b@example.org"), h.clock.now()); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.form("/manage/remove", h.nextIP(), url.Values{"session": {session}, "push_id": {idB}, "confirm": {"on"}}); code != 403 {
		t.Fatalf("banned remove: %d", code)
	}
	if h.manageLink("b@example.org") != "" {
		t.Fatal("banned email got a link")
	}
}

func TestManageRateLimit(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < ManagePerHourPerIP; i++ {
		h.form("/manage", "198.51.100.9", url.Values{"email": {"x@example.org"}})
	}
	if code, _ := h.form("/manage", "198.51.100.9", url.Values{"email": {"x@example.org"}}); code != 429 {
		t.Fatalf("limit: %d", code)
	}
}
