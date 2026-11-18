// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MeshCore-Beacon/beacon-push/internal/config"
	"github.com/MeshCore-Beacon/beacon-push/internal/fcm"
	"github.com/MeshCore-Beacon/beacon-push/internal/mail"
	"github.com/MeshCore-Beacon/beacon-push/internal/store"
)

// fakePush records what would go to FCM. It can refuse a token, answer an error, wait, or run a hook first.
type fakePush struct {
	mu    sync.Mutex
	sent  []fcm.Message
	gone  map[string]bool
	errs  map[string]error
	delay time.Duration
	hook  func(fcm.Message) error
	calls atomic.Int64
}

func (f *fakePush) Send(_ context.Context, m fcm.Message) error {
	f.calls.Add(1)
	f.mu.Lock()
	gone, err, delay, hook := f.gone[m.Token], f.errs[m.Token], f.delay, f.hook
	f.mu.Unlock()
	time.Sleep(delay)
	if hook != nil {
		if err := hook(m); err != nil {
			return err
		}
	}
	if gone {
		return fcm.ErrUnregistered
	}
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.sent = append(f.sent, m)
	f.mu.Unlock()
	return nil
}

func (f *fakePush) set(fn func(f *fakePush)) {
	f.mu.Lock()
	fn(f)
	f.mu.Unlock()
}

func (f *fakePush) messages() []fcm.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fcm.Message(nil), f.sent...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type harness struct {
	t     *testing.T
	srv   *httptest.Server
	relay *Server
	store *store.Store
	push  *fakePush
	mail  *mail.Recorder
	clock *clock
	ip    atomic.Int64
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	u, _ := url.Parse("https://push.test")
	h := &harness{t: t, store: st, push: &fakePush{gone: map[string]bool{}, errs: map[string]error{}}, mail: &mail.Recorder{},
		clock: &clock{t: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)}}
	h.relay = New(Options{Config: config.Config{PublicURL: u, TrustProxy: true, DevMode: true, AdminEmail: "admin@test.example"},
		Store: st, Push: h.push, Mail: h.mail, Now: h.clock.now})
	h.srv = httptest.NewServer(h.relay.Handler())
	t.Cleanup(h.srv.Close)
	return h
}

// nextIP gives each request its own client address, so per-IP limits only bite where a test means them to.
func (h *harness) nextIP() string {
	return fmt.Sprintf("203.0.113.%d", h.ip.Add(1)%250+1)
}

func (h *harness) form(path, ip string, v url.Values) (int, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (h *harness) api(method, path, auth string, body any, out any) *http.Response {
	h.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", h.nextIP())
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp
}

var (
	linkRe   = regexp.MustCompile(`/verify#token=([A-Za-z0-9_-]+)`)
	idRe     = regexp.MustCompile(`id: (inst_[a-z0-9]+)`)
	secretRe = regexp.MustCompile(`BEACON_PUSH_SECRET=([A-Za-z0-9_-]+)`)
)

func registration(name, email, serverURL string) url.Values {
	return url.Values{"name": {name}, "email": {email}, "url": {serverURL}, "terms": {"on"}}
}

// register runs the whole flow and returns the push ID and "id.secret" credentials.
func (h *harness) register(name, email, serverURL string) (string, string) {
	h.t.Helper()
	before := len(h.mail.Messages())
	if code, body := h.form("/register", h.nextIP(), registration(name, email, serverURL)); code != 200 || !strings.Contains(body, "Check your email") {
		h.t.Fatalf("register %d: %s", code, body)
	}
	msgs := h.mail.Messages()
	if len(msgs) != before+1 {
		h.t.Fatalf("expected one mail, have %d", len(msgs)-before)
	}
	m := linkRe.FindStringSubmatch(msgs[len(msgs)-1].Text)
	if m == nil {
		h.t.Fatalf("no link in %q", msgs[len(msgs)-1].Text)
	}
	code, body := h.form("/verify", h.nextIP(), url.Values{"token": {m[1]}})
	id, secret := idRe.FindStringSubmatch(body), secretRe.FindStringSubmatch(body)
	if code != 200 || id == nil || secret == nil {
		h.t.Fatalf("verify %d: %s", code, body)
	}
	return id[1], id[1] + "." + secret[1]
}

func (h *harness) handle(pushID, token string) HandleResponse {
	h.t.Helper()
	var out HandleResponse
	if resp := h.api("POST", "/v1/handles", "", HandleRequest{PushID: pushID, Platform: "android", FCMToken: token}, &out); resp.StatusCode != 200 {
		h.t.Fatalf("handle: %d", resp.StatusCode)
	}
	return out
}

var ct = base64.StdEncoding.EncodeToString([]byte("nonce-and-ciphertext"))

func (h *harness) send(auth string, items ...SendItem) ([]SendResult, *http.Response) {
	h.t.Helper()
	var out struct {
		Results []SendResult `json:"results"`
	}
	resp := h.api("POST", "/v1/send", auth, SendRequest{Messages: items}, &out)
	return out.Results, resp
}

func TestRegisterHelloHandleSend(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("Ottawa Mesh", "Op@Example.org", "")
	if !strings.HasPrefix(id, "inst_") {
		t.Fatalf("push id %q", id)
	}
	inst, err := h.store.Instance(context.Background(), id)
	if err != nil || inst.Email != "op@example.org" || inst.Name != "Ottawa Mesh" || inst.TermsVersion != TermsVersion {
		t.Fatalf("%+v %v", inst, err)
	}

	var hello HelloResponse
	if resp := h.api("POST", "/v1/hello", auth, nil, &hello); resp.StatusCode != 200 {
		t.Fatalf("hello %d", resp.StatusCode)
	}
	if hello.PushID != id || hello.Name != "Ottawa Mesh" || hello.Status != "active" || hello.Tier != "email" ||
		hello.Limits.PerDay != EmailTierPerDay || hello.DomainVerified || hello.TermsOutdated {
		t.Fatalf("%+v", hello)
	}

	dev := h.handle(id, "fcm-token-1")
	again := h.handle(id, "fcm-token-1")
	if dev.Handle == "" || again.Handle != dev.Handle || again.HandleSecret == dev.HandleSecret {
		t.Fatalf("the same token must keep its handle with a new secret: %+v %+v", dev, again)
	}

	res, _ := h.send(auth, SendItem{Handle: dev.Handle, Ciphertext: ct, CollapseKey: "42", TTLSeconds: 600})
	if len(res) != 1 || res[0].Status != StatusOK || !strings.HasPrefix(res[0].MessageID, "m_") {
		t.Fatalf("%+v", res)
	}
	sent := h.push.messages()
	if len(sent) != 1 {
		t.Fatalf("%d pushes", len(sent))
	}
	m := sent[0]
	if m.Token != "fcm-token-1" || m.Data["pushId"] != id || m.Data["serverName"] != "Ottawa Mesh" || m.Data["ct"] != ct ||
		m.Data["messageId"] != res[0].MessageID || m.CollapseKey != id+":42" || m.TTL != 10*time.Minute || m.AlertTitle != "Ottawa Mesh" {
		t.Fatalf("%+v", m)
	}
	if n, _ := h.store.SentToday(context.Background(), id, h.clock.now()); n != 1 {
		t.Fatalf("usage %d", n)
	}
}

func TestAuthFailures(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	for name, cred := range map[string]string{"none": "", "no dot": id, "wrong secret": id + ".nope", "unknown id": "inst_zzzzzzzzzz.x"} {
		if resp := h.api("POST", "/v1/hello", cred, nil, nil); resp.StatusCode != 401 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	if resp := h.api("POST", "/v1/hello", auth, nil, nil); resp.StatusCode != 200 {
		t.Fatalf("good credentials: %d", resp.StatusCode)
	}
}

func TestRegistrationRules(t *testing.T) {
	h := newHarness(t)

	// The honeypot pretends success and sends nothing.
	v := registration("Bot", "bot@example.org", "")
	v.Set("website", "spam")
	if code, _ := h.form("/register", h.nextIP(), v); code != 200 || len(h.mail.Messages()) != 0 {
		t.Fatalf("honeypot: %d, %d mails", code, len(h.mail.Messages()))
	}
	for name, v := range map[string]url.Values{
		"disposable": registration("X", "x@mailinator.com", ""),
		"no terms":   {"name": {"X"}, "email": {"x@example.org"}},
		"bad email":  registration("X", "x at example", ""),
		"long name":  registration(strings.Repeat("n", 41), "x@example.org", ""),
		"angle name": registration("<b>", "x@example.org", ""),
		"bidi name":  registration("Ottawa\u202eMesh", "x@example.org", ""),
		"zwj name":   registration("Otta\u200dwa", "x@example.org", ""),
		"http url":   registration("X", "x@example.org", "ftp://example.org"),
	} {
		if code, body := h.form("/register", h.nextIP(), v); code != 400 || !strings.Contains(body, `class="error"`) {
			t.Errorf("%s: %d", name, code)
		}
	}

	// Two servers per email; the third ask gets a mail saying so and creates nothing.
	h.register("One", "op@example.org", "")
	h.register("Two", "op@example.org", "")
	before := len(h.mail.Messages())
	if code, body := h.form("/register", h.nextIP(), registration("Three", "op@example.org", "")); code != 200 || !strings.Contains(body, "Check your email") {
		t.Fatalf("third: %d", code)
	}
	msgs := h.mail.Messages()
	if len(msgs) <= before || !strings.Contains(msgs[len(msgs)-1].Text, "already has the most servers") || linkRe.MatchString(msgs[len(msgs)-1].Text) {
		t.Fatalf("third registration mail: %+v", msgs[len(msgs)-1])
	}

	// Per-IP limit, which mistakes do not use up.
	for i := 0; i < 5; i++ {
		h.form("/register", "198.51.100.7", registration("", "l@example.org", ""))
	}
	for i := 0; i < RegisterPerHourPerIP; i++ {
		h.form("/register", "198.51.100.7", registration("L", fmt.Sprintf("l%d@example.org", i), ""))
	}
	if code, _ := h.form("/register", "198.51.100.7", registration("L", "l9@example.org", "")); code != 429 {
		t.Fatalf("per-IP limit: %d", code)
	}
}

func TestVerifyLinkIsSingleUseAndExpires(t *testing.T) {
	h := newHarness(t)
	h.form("/register", h.nextIP(), registration("A", "a@example.org", ""))
	token := linkRe.FindStringSubmatch(h.mail.Messages()[0].Text)[1]
	if code, _ := h.form("/verify", h.nextIP(), url.Values{"token": {token}}); code != 200 {
		t.Fatalf("first use: %d", code)
	}
	if code, _ := h.form("/verify", h.nextIP(), url.Values{"token": {token}}); code != 400 {
		t.Fatalf("second use: %d", code)
	}
	h.form("/register", h.nextIP(), registration("B", "b@example.org", ""))
	msgs := h.mail.Messages()
	late := linkRe.FindStringSubmatch(msgs[len(msgs)-1].Text)[1]
	h.clock.add(LinkLifetime + time.Minute)
	if code, _ := h.form("/verify", h.nextIP(), url.Values{"token_manual": {"token=" + late}}); code != 400 {
		t.Fatalf("expired link: %d", code)
	}
}

func TestHandlesBelongToOneServer(t *testing.T) {
	h := newHarness(t)
	idA, authA := h.register("A", "a@example.org", "")
	_, authB := h.register("B", "b@example.org", "")
	dev := h.handle(idA, "tok-a")

	res, _ := h.send(authB, SendItem{Handle: dev.Handle, Ciphertext: ct}, SendItem{Handle: "h_unknown", Ciphertext: ct})
	if res[0].Status != StatusInvalidHandle || res[1].Status != StatusInvalidHandle || len(h.push.messages()) != 0 {
		t.Fatalf("another server's handle: %+v", res)
	}
	if res, _ := h.send(authA, SendItem{Handle: dev.Handle, Ciphertext: ct}); res[0].Status != StatusOK {
		t.Fatalf("own handle: %+v", res)
	}
}

func TestHandleRefreshAndDelete(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	dev := h.handle(id, "tok-1")
	path := "/v1/handles/" + dev.Handle

	if resp := h.api("PUT", path, "", HandleUpdate{HandleSecret: "wrong", FCMToken: "tok-2"}, nil); resp.StatusCode != 404 {
		t.Fatalf("wrong secret: %d", resp.StatusCode)
	}
	if resp := h.api("PUT", path, "", HandleUpdate{HandleSecret: dev.HandleSecret, FCMToken: "tok-2"}, nil); resp.StatusCode != 204 {
		t.Fatalf("refresh: %d", resp.StatusCode)
	}
	h.send(auth, SendItem{Handle: dev.Handle, Ciphertext: ct})
	if sent := h.push.messages(); len(sent) != 1 || sent[0].Token != "tok-2" {
		t.Fatalf("refreshed token not used: %+v", sent)
	}
	if resp := h.api("DELETE", path, "", HandleUpdate{HandleSecret: dev.HandleSecret}, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if res, _ := h.send(auth, SendItem{Handle: dev.Handle, Ciphertext: ct}); res[0].Status != StatusInvalidHandle {
		t.Fatalf("deleted handle: %+v", res)
	}
	// Registering the token again gives a fresh handle.
	if again := h.handle(id, "tok-2"); again.Handle == dev.Handle {
		t.Fatal("a revoked handle must not come back")
	}
}

func TestUnregisteredTokenRevokesTheHandle(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	dev := h.handle(id, "tok-gone")
	h.push.set(func(f *fakePush) { f.gone["tok-gone"] = true })
	if res, _ := h.send(auth, SendItem{Handle: dev.Handle, Ciphertext: ct}); res[0].Status != StatusInvalidHandle {
		t.Fatalf("%+v", res)
	}
	if hd, _ := h.store.Handle(context.Background(), dev.Handle); hd.RevokedAt == 0 {
		t.Fatal("handle not revoked")
	}
}

func TestBadItems(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	dev := h.handle(id, "tok")
	big := base64.StdEncoding.EncodeToString(make([]byte, MaxCiphertext+1))
	res, _ := h.send(auth,
		SendItem{Handle: dev.Handle, Ciphertext: "not base64!"},
		SendItem{Handle: dev.Handle, Ciphertext: big},
		SendItem{Handle: dev.Handle, Ciphertext: ct, CollapseKey: "has space"},
		SendItem{Handle: dev.Handle, Ciphertext: ct, TTLSeconds: int(MaxTTL/time.Second) + 1},
		SendItem{Handle: dev.Handle, Ciphertext: ""},
	)
	want := []string{StatusInvalid, StatusTooLarge, StatusInvalid, StatusInvalid, StatusInvalid}
	for i, w := range want {
		if res[i].Status != w {
			t.Errorf("item %d: %s, want %s", i, res[i].Status, w)
		}
	}
	if len(h.push.messages()) != 0 {
		t.Fatal("a bad item was sent")
	}
	if _, resp := h.send(auth); resp.StatusCode != 400 {
		t.Fatalf("empty batch: %d", resp.StatusCode)
	}
}

func TestRateLimits(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	dev := h.handle(id, "tok")
	items := make([]SendItem, HandlePerMinute+1)
	for i := range items {
		items[i] = SendItem{Handle: dev.Handle, Ciphertext: ct}
	}
	// Items go out concurrently, so which one is refused is not fixed.
	res, resp := h.send(auth, items...)
	if count(res, StatusOK) != HandlePerMinute || count(res, StatusRateLimited) != 1 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("per-device minute: %+v retry %q", res, resp.Header.Get("Retry-After"))
	}

	// A daily quota override stops the server for the rest of the UTC day.
	if err := h.store.SetQuota(context.Background(), id, 0, HandlePerMinute+2); err != nil {
		t.Fatal(err)
	}
	h.clock.add(time.Minute)
	other := h.handle(id, "tok-2")
	res, _ = h.send(auth, SendItem{Handle: other.Handle, Ciphertext: ct}, SendItem{Handle: other.Handle, Ciphertext: ct},
		SendItem{Handle: other.Handle, Ciphertext: ct})
	if count(res, StatusOK) != 2 || count(res, StatusRateLimited) != 1 {
		t.Fatalf("daily quota: %+v", res)
	}
	var hello HelloResponse
	h.api("POST", "/v1/hello", auth, nil, &hello)
	if hello.Tier != "custom" || hello.Limits.PerDay != HandlePerMinute+2 || hello.Limits.PerMinute != EmailTierPerMinute {
		t.Fatalf("%+v", hello)
	}
	h.clock.add(24 * time.Hour)
	if res, _ := h.send(auth, SendItem{Handle: other.Handle, Ciphertext: ct}); res[0].Status != StatusOK {
		t.Fatalf("next day: %+v", res)
	}
}

func TestSuspendAndBan(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	id, auth := h.register("A", "a@example.org", "")
	dev := h.handle(id, "tok")
	if err := h.store.SetStatus(ctx, id, store.StatusSuspended, nil, h.clock.now()); err != nil {
		t.Fatal(err)
	}
	var hello HelloResponse
	if resp := h.api("POST", "/v1/hello", auth, nil, &hello); resp.StatusCode != 200 || hello.Status != "suspended" {
		t.Fatalf("suspended hello: %d %+v", resp.StatusCode, hello)
	}
	if _, resp := h.send(auth, SendItem{Handle: dev.Handle, Ciphertext: ct}); resp.StatusCode != 403 {
		t.Fatalf("suspended send: %d", resp.StatusCode)
	}
	if resp := h.api("POST", "/v1/handles", "", HandleRequest{PushID: id, Platform: "ios", FCMToken: "t2"}, nil); resp.StatusCode != 403 {
		t.Fatalf("suspended handle: %d", resp.StatusCode)
	}

	if err := h.store.SetStatus(ctx, id, store.StatusBanned, EmailHash("A@example.org"), h.clock.now()); err != nil {
		t.Fatal(err)
	}
	if resp := h.api("POST", "/v1/hello", auth, nil, nil); resp.StatusCode != 403 {
		t.Fatalf("banned hello: %d", resp.StatusCode)
	}
	before := len(h.mail.Messages())
	if code, body := h.form("/register", h.nextIP(), registration("Again", "a@example.org", "")); code != 200 || !strings.Contains(body, "Check your email") {
		t.Fatalf("banned email register: %d", code)
	}
	if len(h.mail.Messages()) != before {
		t.Fatal("a banned email must get no link")
	}
}

func TestHarvestingSuspends(t *testing.T) {
	h := newHarness(t)
	victimID, _ := h.register("Victim", "v@example.org", "")
	id, auth := h.register("A", "a@example.org", "")

	// Handles that do not exist are only refused: they may have been purged, and they reach nobody.
	unknown := make([]SendItem, MaxBatch)
	for i := range unknown {
		unknown[i] = SendItem{Handle: fmt.Sprintf("h_gone%d", i), Ciphertext: ct}
	}
	if res, resp := h.send(auth, unknown...); resp.StatusCode != 200 || res[0].Status != StatusInvalidHandle {
		t.Fatalf("unknown handles: %d %+v", resp.StatusCode, res)
	}
	if inst, _ := h.store.Instance(context.Background(), id); inst.Status != store.StatusActive {
		t.Fatalf("suspended for unknown handles: %s", inst.Status)
	}

	// Another server's live handles are harvesting.
	h.clock.add(time.Hour)
	items := make([]SendItem, MaxBatch)
	for i := range items {
		items[i] = SendItem{Handle: h.handle(victimID, fmt.Sprintf("victim-tok-%d", i)).Handle, Ciphertext: ct}
	}
	if _, resp := h.send(auth, items...); resp.StatusCode != 403 {
		t.Fatalf("harvesting batch: %d", resp.StatusCode)
	}
	if inst, _ := h.store.Instance(context.Background(), id); inst.Status != store.StatusSuspended {
		t.Fatalf("status %s", inst.Status)
	}
}

// beaconServer answers the domain check the way beacon-server will.
func beaconServer(t *testing.T, pushID string, secretHash []byte, tamper bool) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ChallengePath {
			http.NotFound(w, r)
			return
		}
		mac := ChallengeMAC(secretHash, pushID, r.URL.Query().Get("challenge"))
		if tamper {
			mac = ChallengeMAC(secretHash, pushID, "something else")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"pushId": pushID, "mac": mac})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDomainCheck(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// Register with a placeholder URL, then point it at a local server that knows the secret.
	id, auth := h.register("A", "a@example.org", "https://beacon.example.org")
	secret := strings.SplitN(auth, ".", 2)[1]
	good := beaconServer(t, id, hash(secret), false)
	if _, err := h.store.Instance(ctx, id); err != nil {
		t.Fatal(err)
	}
	setURL := func(u string) {
		t.Helper()
		if _, err := h.store.DB().ExecContext(ctx, `UPDATE instances SET url = ? WHERE id = ?`, u, id); err != nil {
			t.Fatal(err)
		}
	}
	setURL(good.URL)

	var out map[string]any
	h.api("POST", "/v1/verify-domain", auth, nil, &out)
	if out["domainVerified"] != true {
		t.Fatalf("good answer: %+v", out)
	}
	var hello HelloResponse
	h.api("POST", "/v1/hello", auth, nil, &hello)
	if !hello.DomainVerified || hello.Tier != "verified" || hello.Limits.PerDay != VerifiedTierPerDay {
		t.Fatalf("%+v", hello)
	}

	bad := beaconServer(t, id, hash(secret), true)
	setURL(bad.URL)
	h.api("POST", "/v1/verify-domain", auth, nil, &out)
	if out["domainVerified"] != false || !strings.Contains(fmt.Sprint(out["reason"]), "does not match") {
		t.Fatalf("tampered answer: %+v", out)
	}
	if inst, _ := h.store.Instance(ctx, id); inst.DomainVerifiedAt != 0 {
		t.Fatal("a failed check must clear the verification")
	}
}

func TestChallengeClientRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) }))
	defer srv.Close()
	if _, err := challengeClient(false).Get(srv.URL); err == nil {
		t.Fatal("the production client reached a loopback address")
	}
	if resp, err := challengeClient(true).Get(srv.URL); err != nil {
		t.Fatalf("dev client: %v", err)
	} else {
		resp.Body.Close()
	}
}

func TestPages(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/", "/register", "/verify", "/terms", "/privacy", "/static/site.css", "/static/verify.js", "/healthz"} {
		resp, err := http.Get(h.srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("%s: no CSP", p)
		}
	}
}

func TestConcurrentBatchesKeepTheDailyQuota(t *testing.T) {
	h := newHarness(t)
	id, auth := h.register("A", "a@example.org", "")
	if err := h.store.SetQuota(context.Background(), id, 1000, 5); err != nil {
		t.Fatal(err)
	}
	devs := make([]HandleResponse, 8)
	for i := range devs {
		devs[i] = h.handle(id, fmt.Sprintf("tok-%d", i))
	}
	var wg sync.WaitGroup
	for _, d := range devs {
		wg.Add(1)
		go func(handle string) {
			defer wg.Done()
			h.send(auth, SendItem{Handle: handle, Ciphertext: ct}, SendItem{Handle: handle, Ciphertext: ct})
		}(d.Handle)
	}
	wg.Wait()
	if n := len(h.push.messages()); n != 5 {
		t.Fatalf("sent %d, the daily quota is 5", n)
	}
}

func TestClientIPTakesTheProxysEntry(t *testing.T) {
	s := New(Options{Config: config.Config{TrustProxy: true}})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.2:4000"
	r.Header.Add("X-Forwarded-For", "1.1.1.1")
	r.Header.Add("X-Forwarded-For", "9.9.9.9, 203.0.113.5")
	if ip := s.clientIP(r); ip != "203.0.113.5" {
		t.Fatalf("%s", ip)
	}
	s = New(Options{Config: config.Config{}})
	if ip := s.clientIP(r); ip != "10.0.0.2" {
		t.Fatalf("without TrustProxy: %s", ip)
	}
}
