// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MeshCore-Beacon/beacon-push/internal/push"
)

const deviceToken = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"

type apnsServer struct {
	t     *testing.T
	key   *ecdsa.PrivateKey
	srv   *httptest.Server
	mu    sync.Mutex
	hits  int
	reqs  []*http.Request
	auths []string
	body  map[string]any
	reply func(w http.ResponseWriter, hit int)
}

func newAPNsServer(t *testing.T) *apnsServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &apnsServer{t: t, key: key}
	a.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.hits++
		if r.ProtoMajor != 2 {
			t.Errorf("APNs spoken over %s", r.Proto)
		}
		a.reqs = append(a.reqs, r)
		a.auths = append(a.auths, r.Header.Get("Authorization"))
		b, _ := io.ReadAll(r.Body)
		a.body = map[string]any{}
		_ = json.Unmarshal(b, &a.body)
		if a.reply != nil {
			a.reply(w, a.hits)
			return
		}
		w.Header().Set("apns-id", "id")
	}))
	a.srv.EnableHTTP2 = true
	a.srv.StartTLS()
	t.Cleanup(a.srv.Close)
	return a
}

// sender points both environments at the test server, sandbox under /sandbox.
func (a *apnsServer) sender(now func() time.Time) *APNs {
	return New("KEY1234567", "TEAM123456", "meshcorebeacon.app", a.key, a.srv.URL, a.srv.URL+"/sandbox", a.srv.Client(), now)
}

func (a *apnsServer) last() *http.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reqs[len(a.reqs)-1]
}

// verify checks a provider token's header, claims and signature against the public key.
func (a *apnsServer) verify(auth string, iat int64) {
	a.t.Helper()
	jwt, ok := strings.CutPrefix(auth, "bearer ")
	parts := strings.Split(jwt, ".")
	if !ok || len(parts) != 3 {
		a.t.Fatalf("authorization %q", auth)
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var h map[string]string
	var c map[string]any
	_ = json.Unmarshal(hdr, &h)
	_ = json.Unmarshal(claims, &c)
	if len(h) != 2 || h["alg"] != "ES256" || h["kid"] != "KEY1234567" || len(c) != 2 || c["iss"] != "TEAM123456" || c["iat"] != float64(iat) {
		a.t.Errorf("header %s claims %s", hdr, claims)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&a.key.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		a.t.Error("provider token signature does not verify")
	}
}

var sample = push.Message{Platform: push.IOS, Token: deviceToken, APNsEnv: push.Production,
	Data:        map[string]string{"v": "1", "pushId": "inst_a", "serverName": "Ottawa Mesh", "messageId": "m_1", "ct": "c2VjcmV0"},
	CollapseKey: "inst_a:42", TTL: time.Hour, AlertTitle: "Ottawa Mesh", AlertBody: "New alert"}

func TestSendsTheAlertToAPNs(t *testing.T) {
	a := newAPNsServer(t)
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	if err := a.sender(func() time.Time { return clock }).Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	r := a.last()
	if r.Method != "POST" || r.URL.Path != "/3/device/"+deviceToken || r.Header.Get("apns-topic") != "meshcorebeacon.app" ||
		r.Header.Get("apns-push-type") != "alert" || r.Header.Get("apns-priority") != "10" ||
		r.Header.Get("apns-expiration") != "1794920400" || r.Header.Get("apns-collapse-id") != "inst_a:42" {
		t.Fatalf("%s %s %v", r.Method, r.URL.Path, r.Header)
	}
	a.verify(r.Header.Get("Authorization"), clock.Unix())
	// The keys the app's Notification Service Extension reads sit at the top level, next to aps.
	aps := a.body["aps"].(map[string]any)
	alert := aps["alert"].(map[string]any)
	if aps["mutable-content"] != float64(1) || alert["title"] != "Ottawa Mesh" || alert["body"] != "New alert" || len(a.body) != 6 {
		t.Fatalf("%+v", a.body)
	}
	for k, v := range sample.Data {
		if a.body[k] != v {
			t.Errorf("%s = %v", k, a.body[k])
		}
	}
}

func TestPicksTheEnvironmentPerMessage(t *testing.T) {
	a := newAPNsServer(t)
	s := a.sender(nil)
	m := sample
	m.APNsEnv = push.Sandbox
	m.CollapseKey = ""
	if err := s.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if r := a.last(); r.URL.Path != "/sandbox/3/device/"+deviceToken || r.Header.Get("apns-collapse-id") != "" {
		t.Fatalf("%s %v", r.URL.Path, r.Header)
	}
	if err := s.Send(context.Background(), sample); err != nil || a.last().URL.Path != "/3/device/"+deviceToken {
		t.Fatalf("%v %s", err, a.last().URL.Path)
	}
	m.APNsEnv = ""
	if err := s.Send(context.Background(), m); !errors.Is(err, push.ErrInvalid) || a.hits != 2 {
		t.Fatalf("no environment: %v after %d hits", err, a.hits)
	}
}

func TestCachesTheProviderToken(t *testing.T) {
	a := newAPNsServer(t)
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	s := a.sender(func() time.Time { return clock })
	for i := 0; i < 3; i++ {
		if err := s.Send(context.Background(), sample); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(20 * time.Minute) // 0, 20 and 40 minutes: one token
	}
	if a.auths[0] != a.auths[1] || a.auths[1] != a.auths[2] {
		t.Fatal("token re-signed within 45 minutes")
	}
	if err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	if a.auths[3] == a.auths[0] {
		t.Fatal("token not re-signed after 45 minutes")
	}
	a.verify(a.auths[3], clock.Unix())
}

func TestRenewsARefusedProviderTokenOnce(t *testing.T) {
	for _, reason := range []string{"ExpiredProviderToken", "InvalidProviderToken"} {
		a := newAPNsServer(t)
		clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
		s := a.sender(func() time.Time { return clock })
		_ = s.Send(context.Background(), sample)
		clock = clock.Add(time.Minute)
		a.reply = func(w http.ResponseWriter, hit int) {
			if hit == 2 {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(`{"reason":"` + reason + `"}`))
			}
		}
		if err := s.Send(context.Background(), sample); err != nil {
			t.Fatalf("%s: %v", reason, err)
		}
		if a.hits != 3 || a.auths[1] != a.auths[0] || a.auths[2] == a.auths[1] {
			t.Fatalf("%s: %d hits, token not renewed", reason, a.hits)
		}
		a.verify(a.auths[2], clock.Unix())

		a.reply = func(w http.ResponseWriter, _ int) {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"reason":"` + reason + `"}`))
		}
		err := s.Send(context.Background(), sample)
		var pe *push.Error
		if !errors.Is(err, push.ErrAuth) || !errors.As(err, &pe) || pe.Code != reason || a.hits != 5 {
			t.Fatalf("%s twice: %v after %d hits", reason, err, a.hits)
		}
	}
}

func TestMapsAppleAnswers(t *testing.T) {
	a := newAPNsServer(t)
	for _, c := range []struct {
		status int
		reason string
		header string
		kind   error
		wait   time.Duration
	}{
		{410, "Unregistered", "", push.ErrUnregistered, 0},
		{410, "ExpiredToken", "", push.ErrUnregistered, 0},
		{400, "BadDeviceToken", "", push.ErrUnregistered, 0},
		{400, "DeviceTokenNotForTopic", "", push.ErrUnregistered, 0},
		{400, "BadCollapseId", "", push.ErrInvalid, 0},
		{400, "IdleTimeout", "", nil, 0},
		{400, "", "", push.ErrInvalid, 0},
		{413, "PayloadTooLarge", "", push.ErrTooLarge, 0},
		{429, "TooManyRequests", "", push.ErrThrottled, 0},
		{429, "TooManyRequests", "30", push.ErrThrottled, 30 * time.Second},
		{429, "TooManyProviderTokenUpdates", "", push.ErrAuth, 0},
		{403, "MissingProviderToken", "", push.ErrAuth, 0},
		{500, "InternalServerError", "", push.ErrUnavailable, 0},
		{503, "ServiceUnavailable", "120", push.ErrUnavailable, 2 * time.Minute},
		{503, "Shutdown", "", push.ErrUnavailable, 0},
		{404, "BadPath", "", nil, 0},
	} {
		a.reply = func(w http.ResponseWriter, _ int) {
			if c.header != "" {
				w.Header().Set("Retry-After", c.header)
			}
			w.WriteHeader(c.status)
			if c.reason != "" {
				_, _ = w.Write([]byte(`{"reason":"` + c.reason + `"}`))
			}
		}
		err := a.sender(nil).Send(context.Background(), sample)
		var pe *push.Error
		if !errors.As(err, &pe) || pe.Provider != "apns" || pe.Status != c.status || pe.Code != c.reason || pe.Kind != c.kind || pe.RetryAfter != c.wait {
			t.Errorf("%d %s: %#v", c.status, c.reason, err)
		}
	}
}

func TestErrorsNeverCarrySecrets(t *testing.T) {
	a := newAPNsServer(t)
	a.reply = func(w http.ResponseWriter, _ int) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"reason":"` + deviceToken + ` leaked"}`))
	}
	err := a.sender(nil).Send(context.Background(), sample)
	if err == nil || strings.Contains(err.Error(), deviceToken) || !strings.Contains(err.Error(), "500") {
		t.Fatalf("%v", err)
	}
	s := New("K", "T", "topic", a.key, "https://127.0.0.1:1", "https://127.0.0.1:1", nil, nil)
	err = s.Send(context.Background(), sample)
	if err == nil || strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), deviceToken) {
		t.Fatalf("%v", err)
	}
}

func TestCollapseIDFitsSixtyFourBytes(t *testing.T) {
	short := "inst_abcdefghij:" + strings.Repeat("k", 40)
	if CollapseID(short) != short {
		t.Fatal("a short key was changed")
	}
	long := strings.Repeat("x", 65)
	id := CollapseID(long)
	if len(id) > 64 || id != CollapseID(long) || id == CollapseID(long+"y") {
		t.Fatalf("%q", id)
	}
	a := newAPNsServer(t)
	m := sample
	m.CollapseKey = long
	if err := a.sender(nil).Send(context.Background(), m); err != nil || a.last().Header.Get("apns-collapse-id") != id {
		t.Fatalf("%v %q", err, a.last().Header.Get("apns-collapse-id"))
	}
}

func TestRefusesAPayloadOverTheLimit(t *testing.T) {
	a := newAPNsServer(t)
	m := sample
	// The relay's largest ciphertext with the longest name still fits.
	m.Data = map[string]string{"v": "1", "pushId": "inst_abcdefghij", "serverName": strings.Repeat("é", 40), "messageId": "m_" + strings.Repeat("a", 22),
		"ct": base64.StdEncoding.EncodeToString(make([]byte, 2048))}
	m.AlertTitle = m.Data["serverName"]
	if err := a.sender(nil).Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	m.Data = map[string]string{"ct": strings.Repeat("a", 4096)}
	if err := a.sender(nil).Send(context.Background(), m); !errors.Is(err, push.ErrTooLarge) || a.hits != 1 {
		t.Fatalf("%v after %d hits", err, a.hits)
	}
}

func TestSendHasOneDeadline(t *testing.T) {
	a := newAPNsServer(t)
	a.reply = func(w http.ResponseWriter, _ int) { time.Sleep(2 * time.Second) }
	s := a.sender(nil)
	s.sendLimit = 200 * time.Millisecond
	start := time.Now()
	if err := s.Send(context.Background(), sample); err == nil {
		t.Fatal("a hanging APNs let the send through")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("send took %s with a 200 ms limit", took)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	s, err := Load(write("ok.p8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "K", "T", "topic")
	if err != nil || s.prodBase != ProductionBase || s.sandboxBase != SandboxBase {
		t.Fatalf("%v", err)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rder, _ := x509.MarshalPKCS8PrivateKey(rk)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	pder, _ := x509.MarshalPKCS8PrivateKey(p384)
	for name, content := range map[string][]byte{
		"not pem": []byte("hunter2-secret"),
		"garbage": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("super-secret-material")}),
		"rsa":     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rder}),
		"p384":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pder}),
	} {
		_, err := Load(write(name+".p8", content), "K", "T", "topic")
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		for _, secret := range []string{"hunter2-secret", "super-secret-material", dir} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: error leaks %q: %v", name, secret, err)
			}
		}
	}
	if _, err := Load(filepath.Join(dir, "missing.p8"), "K", "T", "topic"); err == nil || strings.Contains(err.Error(), dir) {
		t.Errorf("missing file: %v", err)
	}
}
