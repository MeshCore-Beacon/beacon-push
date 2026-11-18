// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fcm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fcmServer struct {
	t         *testing.T
	key       *rsa.PrivateKey
	srv       *httptest.Server
	mu        sync.Mutex
	tokenHits int
	sendHits  int
	lastSend  map[string]any
	lastAuth  string
	lastPath  string
	sendReply func(w http.ResponseWriter, hit int)
	expiresIn int

	tokenDelay  atomic.Int64 // nanoseconds the token endpoint waits before answering
	tokenStatus atomic.Int64 // non-zero: the token endpoint answers this status
}

func newFCMServer(t *testing.T) *fcmServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fcmServer{t: t, key: key, expiresIn: 3600}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_ = r.ParseForm() // read the body so a client that gives up cancels r.Context
			select {
			case <-time.After(time.Duration(f.tokenDelay.Load())):
			case <-r.Context().Done():
				return
			}
			if st := f.tokenStatus.Load(); st != 0 {
				f.mu.Lock()
				f.tokenHits++
				f.mu.Unlock()
				w.WriteHeader(int(st))
				return
			}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.URL.Path == "/token":
			f.tokenHits++
			_ = r.ParseForm()
			f.checkAssertion(r.PostForm.Get("assertion"), r.PostForm.Get("grant_type"))
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-" + string(rune('0'+f.tokenHits)), "expires_in": f.expiresIn})
		case strings.HasSuffix(r.URL.Path, "/messages:send"):
			f.sendHits++
			f.lastAuth, f.lastPath = r.Header.Get("Authorization"), r.URL.Path
			body, _ := io.ReadAll(r.Body)
			f.lastSend = map[string]any{}
			_ = json.Unmarshal(body, &f.lastSend)
			if f.sendReply != nil {
				f.sendReply(w, f.sendHits)
				return
			}
			_, _ = w.Write([]byte(`{"name":"projects/p/messages/1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fcmServer) checkAssertion(jwt, grant string) {
	f.t.Helper()
	if grant != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		f.t.Errorf("grant type %q", grant)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		f.t.Errorf("assertion %q", jwt)
		return
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&f.key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		f.t.Errorf("assertion signature: %v", err)
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	_ = json.Unmarshal(claims, &c)
	if !strings.Contains(string(hdr), "RS256") || c["iss"] != "svc@project.iam" || c["scope"] != "https://www.googleapis.com/auth/firebase.messaging" ||
		c["aud"] != f.srv.URL+"/token" || c["exp"].(float64)-c["iat"].(float64) != 3600 {
		f.t.Errorf("claims %s header %s", claims, hdr)
	}
}

func (f *fcmServer) fcm(now func() time.Time) *FCM {
	return New("my-project", "svc@project.iam", f.srv.URL+"/token", f.srv.URL, f.key, f.srv.Client(), now)
}

var sampleMsg = Message{Token: "device-token-abc", Data: map[string]string{"v": "1", "ct": "c2VjcmV0"}, CollapseKey: "inst_a:42", TTL: time.Hour,
	AlertTitle: "Ottawa Mesh", AlertBody: "New alert"}

func TestFCMSendsTheV1Message(t *testing.T) {
	f := newFCMServer(t)
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	if err := f.fcm(func() time.Time { return clock }).Send(context.Background(), sampleMsg); err != nil {
		t.Fatal(err)
	}
	m := f.lastSend["message"].(map[string]any)
	data := m["data"].(map[string]any)
	if f.lastPath != "/v1/projects/my-project/messages:send" || f.lastAuth != "Bearer access-1" || m["token"] != "device-token-abc" ||
		len(data) != 2 || data["ct"] != "c2VjcmV0" || m["notification"] != nil {
		t.Fatalf("%s %s %+v", f.lastPath, f.lastAuth, f.lastSend)
	}
	android := m["android"].(map[string]any)
	if android["priority"] != "high" || android["ttl"] != "3600s" || android["collapse_key"] != "inst_a:42" {
		t.Fatalf("android %+v", android)
	}
	apns := m["apns"].(map[string]any)
	headers := apns["headers"].(map[string]any)
	aps := apns["payload"].(map[string]any)["aps"].(map[string]any)
	alert := aps["alert"].(map[string]any)
	if headers["apns-collapse-id"] != "inst_a:42" || headers["apns-priority"] != "10" || headers["apns-expiration"] != "1794920400" ||
		aps["mutable-content"] != float64(1) || alert["title"] != "Ottawa Mesh" || alert["body"] != "New alert" {
		t.Fatalf("apns %+v", apns)
	}
}

func TestFCMOmitsAnEmptyCollapseKey(t *testing.T) {
	f := newFCMServer(t)
	msg := sampleMsg
	msg.CollapseKey = ""
	if err := f.fcm(nil).Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	m := f.lastSend["message"].(map[string]any)
	if _, ok := m["android"].(map[string]any)["collapse_key"]; ok {
		t.Fatal("android collapse_key sent")
	}
	if _, ok := m["apns"].(map[string]any)["headers"].(map[string]any)["apns-collapse-id"]; ok {
		t.Fatal("apns-collapse-id sent")
	}
}

func TestFCMCachesTheAccessTokenUntilNearExpiry(t *testing.T) {
	f := newFCMServer(t)
	clock := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	c := f.fcm(func() time.Time { return clock })
	for i := 0; i < 3; i++ {
		if err := c.Send(context.Background(), sampleMsg); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokenHits != 1 || f.sendHits != 3 {
		t.Fatalf("token hits %d send hits %d", f.tokenHits, f.sendHits)
	}
	clock = clock.Add(59 * time.Minute) // inside the two minute refresh margin of a one hour token
	if err := c.Send(context.Background(), sampleMsg); err != nil {
		t.Fatal(err)
	}
	if f.tokenHits != 2 || f.lastAuth != "Bearer access-2" {
		t.Fatalf("not refreshed: hits %d auth %s", f.tokenHits, f.lastAuth)
	}
}

func TestFCMUnregisteredToken(t *testing.T) {
	f := newFCMServer(t)
	f.sendReply = func(w http.ResponseWriter, _ int) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"x","errorCode":"UNREGISTERED"}]}}`))
	}
	if err := f.fcm(nil).Send(context.Background(), sampleMsg); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("%v", err)
	}
	f.sendReply = func(w http.ResponseWriter, _ int) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"errorCode":"UNREGISTERED"}]}}`))
	}
	if err := f.fcm(nil).Send(context.Background(), sampleMsg); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("400 unregistered: %v", err)
	}
	f.sendReply = func(w http.ResponseWriter, _ int) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"bad payload"}}`))
	}
	if err := f.fcm(nil).Send(context.Background(), sampleMsg); !errors.Is(err, ErrInvalidArgument) || errors.Is(err, ErrUnregistered) {
		t.Fatalf("a plain 400 must be an invalid message, not an unregistered token: %v", err)
	}
	f.sendReply = func(w http.ResponseWriter, _ int) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"errorCode":"INVALID_ARGUMENT"}]}}`))
	}
	if err := f.fcm(nil).Send(context.Background(), sampleMsg); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("400 INVALID_ARGUMENT detail: %v", err)
	}
}

func TestFCMKeepsTheBackoff(t *testing.T) {
	f := newFCMServer(t)
	for _, c := range []struct {
		status int
		header string
		body   string
		want   time.Duration
		code   string
	}{
		{503, "3600", `{"error":{"code":503,"status":"UNAVAILABLE","details":[{"errorCode":"UNAVAILABLE"}]}}`, time.Hour, "UNAVAILABLE"},
		{429, "7", `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"errorCode":"QUOTA_EXCEEDED"}]}}`, 7 * time.Second, "QUOTA_EXCEEDED"},
		{500, "", `{"error":{"code":500,"status":"INTERNAL"}}`, 0, "INTERNAL"},
		{503, "Wed, 18 Nov 2026 12:00:30 GMT", ``, 30 * time.Second, ""},
	} {
		f.sendReply = func(w http.ResponseWriter, _ int) {
			if c.header != "" {
				w.Header().Set("Retry-After", c.header)
			}
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}
		now := func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) }
		err := f.fcm(now).Send(context.Background(), sampleMsg)
		var fe *Error
		if !errors.As(err, &fe) || fe.Status != c.status || fe.RetryAfter != c.want || fe.Code != c.code {
			t.Errorf("%d %q: %#v", c.status, c.header, err)
		}
		if errors.Is(err, ErrInvalidArgument) || errors.Is(err, ErrUnregistered) {
			t.Errorf("%d: %v", c.status, err)
		}
	}
}

func TestFCMRetriesOnceAfterAStaleAccessToken(t *testing.T) {
	f := newFCMServer(t)
	f.sendReply = func(w http.ResponseWriter, hit int) {
		if hit == 1 {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}
	if err := f.fcm(nil).Send(context.Background(), sampleMsg); err != nil {
		t.Fatal(err)
	}
	if f.tokenHits != 2 || f.sendHits != 2 || f.lastAuth != "Bearer access-2" {
		t.Fatalf("token hits %d, send hits %d, auth %s", f.tokenHits, f.sendHits, f.lastAuth)
	}
	f.sendReply = func(w http.ResponseWriter, _ int) { w.WriteHeader(401) }
	if err := f.fcm(nil).Send(context.Background(), sampleMsg); err == nil {
		t.Fatal("a second 401 must fail")
	}
}

func TestFCMErrorsNeverCarrySecrets(t *testing.T) {
	f := newFCMServer(t)
	f.sendReply = func(w http.ResponseWriter, _ int) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error":"device-token-abc access-1 leaked"}`))
	}
	err := f.fcm(nil).Send(context.Background(), sampleMsg)
	if err == nil || strings.Contains(err.Error(), "device-token-abc") || strings.Contains(err.Error(), "access-1") || !strings.Contains(err.Error(), "500") {
		t.Fatalf("%v", err)
	}
	// An unreachable token endpoint says so without the URL, the assertion or the key.
	c := New("p", "svc@project.iam", "http://127.0.0.1:1/token", "http://127.0.0.1:1", f.key, nil, nil)
	err = c.Send(context.Background(), sampleMsg)
	if err == nil || strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "device-token-abc") {
		t.Fatalf("%v", err)
	}
}

func serviceAccountJSON(t *testing.T, key *rsa.PrivateKey, tokenURI string) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	b, _ := json.Marshal(map[string]string{"project_id": "my-project", "client_email": "svc@project.iam", "private_key": string(pemKey), "token_uri": tokenURI})
	return b
}

func TestLoad(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := Load(write("ok.json", serviceAccountJSON(t, key, "https://oauth2.example/token"))); err != nil {
		t.Fatal(err)
	}
	// No token_uri falls back to Google's.
	if f, err := Load(write("default.json", serviceAccountJSON(t, key, ""))); err != nil || f.tokenURL != "https://oauth2.googleapis.com/token" {
		t.Fatalf("%v", err)
	}
	for name, content := range map[string][]byte{
		"http token":   serviceAccountJSON(t, key, "http://oauth2.example/token"),
		"not json":     []byte("hunter2-secret"),
		"missing key":  []byte(`{"project_id":"p","client_email":"e"}`),
		"bad pem":      []byte(`{"project_id":"p","client_email":"e","private_key":"super-secret-material"}`),
		"empty object": []byte(`{}`),
	} {
		_, err := Load(write(name+".json", content))
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
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil || strings.Contains(err.Error(), dir) {
		t.Errorf("missing file: %v", err)
	}
}

func TestFCMSendHasOneDeadline(t *testing.T) {
	f := newFCMServer(t)
	f.tokenDelay.Store(int64(5 * time.Second))
	c := f.fcm(nil)
	c.sendLimit = 300 * time.Millisecond
	start := time.Now()
	if err := c.Send(context.Background(), sampleMsg); err == nil {
		t.Fatal("a hanging token endpoint let the send through")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("send took %s with a 300 ms limit", took)
	}
}

func TestFCMSharesAFailedTokenRefresh(t *testing.T) {
	f := newFCMServer(t)
	f.tokenDelay.Store(int64(300 * time.Millisecond))
	f.tokenStatus.Store(503)
	c := f.fcm(nil)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Send(context.Background(), sampleMsg); err == nil {
				t.Error("send passed without an access token")
			}
		}()
	}
	wg.Wait()
	f.mu.Lock()
	hits := f.tokenHits
	f.mu.Unlock()
	if took := time.Since(start); hits != 1 || took > 1500*time.Millisecond {
		t.Fatalf("%d token requests in %s; waiting senders must share one failure", hits, took)
	}
}
