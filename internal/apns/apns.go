// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package apns sends notifications to iOS devices through Apple's HTTP/2 provider API, signed with a token-based
// (.p8) key.
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MeshCore-Beacon/beacon-push/internal/push"
)

const (
	ProductionBase = "https://api.push.apple.com"
	SandboxBase    = "https://api.sandbox.push.apple.com"

	callLimit     = 10 * time.Second
	sendLimit     = 10 * time.Second // a whole Send: the token retry included
	tokenLifetime = 45 * time.Minute // Apple refuses tokens older than an hour and refreshes more often than every 20 minutes
	maxPayload    = 4096
	maxCollapseID = 64
	maxReply      = 4 << 10
)

// APNs signs a provider token with the team's key and reuses it for tokenLifetime. Nothing it holds (key, provider
// token, device tokens) is ever logged or put in an error.
type APNs struct {
	keyID, teamID, topic  string
	key                   *ecdsa.PrivateKey
	prodBase, sandboxBase string
	client                *http.Client
	now                   func() time.Time
	sendLimit             time.Duration

	mu     sync.Mutex
	token  string
	issued time.Time
}

// Load reads the .p8 key file. Errors never include the file's content.
func Load(path, keyID, teamID, topic string) (*APNs, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("apns key file cannot be read")
	}
	key, err := ParseKey(raw)
	if err != nil {
		return nil, err
	}
	return New(keyID, teamID, topic, key, ProductionBase, SandboxBase, nil, nil), nil
}

// ParseKey reads a PKCS #8 P-256 key, the format of Apple's .p8 files.
func ParseKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("apns key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("apns key cannot be parsed")
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("apns key is not a P-256 key")
	}
	return key, nil
}

// New builds the sender from its parts; tests point the bases at a local server.
func New(keyID, teamID, topic string, key *ecdsa.PrivateKey, prodBase, sandboxBase string, client *http.Client, now func() time.Time) *APNs {
	if client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone() // keeps HTTP/2, which APNs requires
		client = &http.Client{Transport: tr, Timeout: callLimit, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if now == nil {
		now = time.Now
	}
	return &APNs{keyID: keyID, teamID: teamID, topic: topic, key: key, prodBase: strings.TrimRight(prodBase, "/"),
		sandboxBase: strings.TrimRight(sandboxBase, "/"), client: client, now: now, sendLimit: sendLimit}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// providerToken is the cached ES256 JWT, signed anew once it is tokenLifetime old.
func (a *APNs) providerToken() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.token != "" && now.Sub(a.issued) < tokenLifetime && !now.Before(a.issued) {
		return a.token, nil
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": a.keyID})
	claims, _ := json.Marshal(map[string]any{"iss": a.teamID, "iat": now.Unix()})
	signing := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, sum[:])
	if err != nil {
		return "", errors.New("apns provider token could not be signed")
	}
	sig := make([]byte, 64) // JWS wants r and s as two fixed 32-byte halves, not ASN.1
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	a.token, a.issued = signing+"."+b64(sig), now
	return a.token, nil
}

// renew drops the token Apple refused, unless another send already replaced it.
func (a *APNs) renew(stale string) {
	a.mu.Lock()
	if a.token == stale {
		a.token = ""
	}
	a.mu.Unlock()
}

// CollapseID is the key as APNs takes it: as is up to 64 bytes, else a hash that always comes out the same.
func CollapseID(key string) string {
	if len(key) <= maxCollapseID {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return b64(sum[:])
}

// payload is a placeholder alert with mutable-content, so the Notification Service Extension runs and replaces it
// with the decrypted text, and the data as top-level keys, where the extension reads them.
func payload(m push.Message) []byte {
	p := make(map[string]any, len(m.Data)+1)
	for k, v := range m.Data {
		p[k] = v
	}
	p["aps"] = map[string]any{
		"alert":           map[string]string{"title": m.AlertTitle, "body": m.AlertBody},
		"mutable-content": 1,
	}
	b, _ := json.Marshal(p)
	return b
}

// Send posts one message to the APNs environment the device token belongs to. The errors are *push.Error values
// whose kinds the relay acts on, or a plain error when Apple could not be reached.
func (a *APNs) Send(ctx context.Context, m push.Message) error {
	var base string
	switch m.APNsEnv {
	case push.Production:
		base = a.prodBase
	case push.Sandbox:
		base = a.sandboxBase
	default:
		return push.ErrInvalid
	}
	body := payload(m)
	if len(body) > maxPayload {
		return push.ErrTooLarge
	}
	ctx, cancel := context.WithTimeout(ctx, a.sendLimit)
	defer cancel()
	for attempt := 0; ; attempt++ {
		tok, err := a.providerToken()
		if err != nil {
			return err
		}
		cctx, ccancel := context.WithTimeout(ctx, callLimit)
		req, err := http.NewRequestWithContext(cctx, http.MethodPost, base+"/3/device/"+url.PathEscape(m.Token), bytes.NewReader(body))
		if err != nil {
			ccancel()
			return errors.New("apns request failed")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "bearer "+tok)
		req.Header.Set("apns-topic", a.topic)
		req.Header.Set("apns-push-type", "alert")
		req.Header.Set("apns-priority", "10")
		exp := int64(0)
		if m.TTL > 0 {
			exp = a.now().Add(m.TTL).Unix()
		}
		req.Header.Set("apns-expiration", strconv.FormatInt(exp, 10))
		if m.CollapseKey != "" {
			req.Header.Set("apns-collapse-id", CollapseID(m.CollapseKey))
		}
		resp, err := a.client.Do(req)
		if err != nil {
			ccancel()
			return errors.New("apns unreachable")
		}
		reply, _ := io.ReadAll(io.LimitReader(resp.Body, maxReply))
		resp.Body.Close()
		ccancel()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		reason := reasonOf(reply)
		if resp.StatusCode == http.StatusForbidden && attempt == 0 && (reason == "ExpiredProviderToken" || reason == "InvalidProviderToken") {
			a.renew(tok) // sign a fresh token once
			continue
		}
		return &push.Error{Provider: push.APNs, Status: resp.StatusCode, Code: reason,
			RetryAfter: push.RetryAfter(resp.Header.Get("Retry-After"), a.now()), Kind: kindOf(resp.StatusCode, reason)}
	}
}

// kindOf maps Apple's answer to what the relay does about it.
func kindOf(status int, reason string) error {
	switch {
	case status == http.StatusGone, status == http.StatusBadRequest && (reason == "BadDeviceToken" || reason == "DeviceTokenNotForTopic"):
		return push.ErrUnregistered
	case status == http.StatusRequestEntityTooLarge:
		return push.ErrTooLarge
	case status == http.StatusBadRequest:
		return push.ErrInvalid
	case status == http.StatusForbidden, reason == "TooManyProviderTokenUpdates":
		return push.ErrAuth // the relay's key or token, not this device
	case status == http.StatusTooManyRequests:
		return push.ErrThrottled
	case status >= 500:
		return push.ErrUnavailable
	}
	return nil
}

// reasonOf reads Apple's {"reason": "..."} reply. Only short letter-only words, so nothing odd reaches a log line.
func reasonOf(reply []byte) string {
	var e struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(reply, &e) != nil || len(e.Reason) > 40 {
		return ""
	}
	for _, c := range e.Reason {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return ""
		}
	}
	return e.Reason
}
