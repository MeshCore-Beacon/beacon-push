// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fcm sends data messages through Firebase Cloud Messaging's HTTP v1 API, which delivers to Android and,
// through the APNs key uploaded to Firebase, to iOS.
package fcm

import (
	"bytes"
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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Message is one notification for one device. Data is delivered as is; the app decrypts what it carries. On iOS the
// alert text is a placeholder the app's Notification Service Extension replaces after decrypting.
type Message struct {
	Token       string
	Data        map[string]string
	CollapseKey string // at most 64 bytes; empty means none
	TTL         time.Duration
	AlertTitle  string // iOS placeholder
	AlertBody   string // iOS placeholder
}

// ErrUnregistered means the push service no longer knows the token: the handle should go.
var ErrUnregistered = errors.New("fcm: token unregistered")

// ErrInvalidArgument means FCM refused the message itself (400 INVALID_ARGUMENT): sending it again cannot work.
var ErrInvalidArgument = errors.New("fcm: message refused as invalid")

// Error is any other refusal from FCM. It keeps the status, the error code and the asked-for wait, never the token
// or the reply body.
type Error struct {
	Status     int
	Code       string        // FCM errorCode, else the Google status; may be empty
	RetryAfter time.Duration // 0 when FCM gave none
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("fcm answered %d %s", e.Status, e.Code)
	}
	return fmt.Sprintf("fcm answered %d", e.Status)
}

// Is lets errors.Is(err, ErrInvalidArgument) match a 400 INVALID_ARGUMENT.
func (e *Error) Is(target error) bool {
	return target == ErrInvalidArgument && e.Status == http.StatusBadRequest && e.Code == "INVALID_ARGUMENT"
}

// Sender sends one message.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Log is a Sender for dev mode: it logs that a message would go out, without the token or the data.
type Log struct{}

func (Log) Send(_ context.Context, m Message) error {
	slog.Info("push (dev mode, not sent)", "component", "fcm", "data_keys", len(m.Data), "collapse_key", m.CollapseKey)
	return nil
}

const (
	scope          = "https://www.googleapis.com/auth/firebase.messaging"
	sendBase       = "https://fcm.googleapis.com"
	callLimit      = 10 * time.Second
	sendLimit      = 10 * time.Second // a whole Send: token, 401 retry and waits included
	tokenRetryIn   = 5 * time.Second  // a failed token request is shared this long before the next try
	maxReply       = 64 << 10
	tokenLifetime  = time.Hour
	tokenRefreshIn = 2 * time.Minute // refresh this long before the access token expires
)

// FCM obtains an access token from a service-account key (a signed JWT exchanged at the key's token endpoint) and
// caches it until shortly before it expires. Nothing it holds (key, access token, device tokens) is ever logged or
// put in an error.
type FCM struct {
	projectID, clientEmail, tokenURL, sendBase string
	key                                        *rsa.PrivateKey
	client                                     *http.Client
	now                                        func() time.Time
	sendLimit                                  time.Duration

	refreshing chan struct{} // one token request at a time; a waiter gives up with its context

	mu        sync.Mutex
	access    string
	expiry    time.Time
	failErr   error
	failUntil time.Time
}

type serviceAccount struct {
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// Load reads a Google service-account JSON file. The error never includes the file's content.
func Load(path string) (*FCM, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("firebase credentials file cannot be read")
	}
	return Parse(raw)
}

// Parse builds the sender from service-account JSON.
func Parse(raw []byte) (*FCM, error) {
	var sa serviceAccount
	if json.Unmarshal(raw, &sa) != nil || sa.ProjectID == "" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("firebase credentials file is not a service-account key")
	}
	tokenURL := sa.TokenURI
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	if u, err := url.Parse(tokenURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("firebase credentials token_uri must be an https URL")
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("firebase credentials private key is not PEM")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("firebase credentials private key is not RSA")
		}
		key = rk
	} else if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else {
		return nil, errors.New("firebase credentials private key cannot be parsed")
	}
	return New(sa.ProjectID, sa.ClientEmail, tokenURL, sendBase, key, nil, nil), nil
}

// New builds the sender from its parts; tests point tokenURL and base at a local server.
func New(projectID, clientEmail, tokenURL, base string, key *rsa.PrivateKey, client *http.Client, now func() time.Time) *FCM {
	if client == nil {
		client = &http.Client{Timeout: callLimit, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if now == nil {
		now = time.Now
	}
	return &FCM{projectID: projectID, clientEmail: clientEmail, tokenURL: tokenURL, sendBase: strings.TrimRight(base, "/"), key: key,
		client: client, now: now, sendLimit: sendLimit, refreshing: make(chan struct{}, 1)}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (f *FCM) assertion() (string, error) {
	now := f.now()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iss": f.clientEmail, "scope": scope, "aud": f.tokenURL,
		"iat": now.Unix(), "exp": now.Add(tokenLifetime).Unix()})
	signing := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", errors.New("fcm token request could not be signed")
	}
	return signing + "." + b64(sig), nil
}

// cached is the usable access token, or the recent token failure every caller shares.
func (f *FCM) cached() (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if f.access != "" && now.Add(tokenRefreshIn).Before(f.expiry) {
		return f.access, true, nil
	}
	if f.failErr != nil && now.Before(f.failUntil) {
		return "", true, f.failErr
	}
	return "", false, nil
}

// accessToken returns the cached access token, getting a new one when it is near expiry.
func (f *FCM) accessToken(ctx context.Context) (string, error) {
	if tok, ok, err := f.cached(); ok {
		return tok, err
	}
	select {
	case f.refreshing <- struct{}{}:
	case <-ctx.Done():
		return "", errors.New("fcm token request timed out")
	}
	defer func() { <-f.refreshing }()
	// Whoever held the slot may have just refreshed, or failed.
	if tok, ok, err := f.cached(); ok {
		return tok, err
	}
	tok, expiresIn, err := f.requestToken(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		if !errors.Is(ctx.Err(), context.Canceled) {
			f.failErr, f.failUntil = err, f.now().Add(tokenRetryIn)
		}
		return "", err
	}
	f.access, f.expiry, f.failErr = tok, f.now().Add(expiresIn), nil
	return tok, nil
}

func (f *FCM) requestToken(ctx context.Context) (string, time.Duration, error) {
	jwt, err := f.assertion()
	if err != nil {
		return "", 0, err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {jwt}}
	ctx, cancel := context.WithTimeout(ctx, callLimit)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, errors.New("fcm token request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		return "", 0, errors.New("fcm token endpoint unreachable")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxReply))
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &out) != nil || out.AccessToken == "" {
		return "", 0, fmt.Errorf("fcm token endpoint answered %d", resp.StatusCode)
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

func (f *FCM) forgetToken() {
	f.mu.Lock()
	f.access = ""
	f.mu.Unlock()
}

// body is the v1 message: data-only and high priority on Android; on iOS a placeholder alert with mutable-content so
// the Notification Service Extension runs and replaces it with the decrypted text.
func (f *FCM) body(m Message) []byte {
	ttl := int64(m.TTL / time.Second)
	android := map[string]any{"priority": "high", "ttl": strconv.FormatInt(ttl, 10) + "s"}
	headers := map[string]string{"apns-priority": "10", "apns-push-type": "alert",
		"apns-expiration": strconv.FormatInt(f.now().Add(m.TTL).Unix(), 10)}
	if m.CollapseKey != "" {
		android["collapse_key"] = m.CollapseKey
		headers["apns-collapse-id"] = m.CollapseKey
	}
	b, _ := json.Marshal(map[string]any{"message": map[string]any{
		"token":   m.Token,
		"data":    m.Data,
		"android": android,
		"apns": map[string]any{
			"headers": headers,
			"payload": map[string]any{"aps": map[string]any{
				"alert":           map[string]string{"title": m.AlertTitle, "body": m.AlertBody},
				"mutable-content": 1,
			}},
		},
	}})
	return b
}

// Send posts one message. ErrUnregistered when Google says the device token is gone, ErrInvalidArgument when it refuses
// the message, otherwise an *Error for an FCM answer or a plain error when FCM could not be reached.
func (f *FCM) Send(ctx context.Context, m Message) error {
	ctx, cancel := context.WithTimeout(ctx, f.sendLimit)
	defer cancel()
	body := f.body(m)
	for attempt := 0; ; attempt++ {
		access, err := f.accessToken(ctx)
		if err != nil {
			return err
		}
		cctx, cancel := context.WithTimeout(ctx, callLimit)
		req, err := http.NewRequestWithContext(cctx, http.MethodPost, f.sendBase+"/v1/projects/"+url.PathEscape(f.projectID)+"/messages:send", bytes.NewReader(body))
		if err != nil {
			cancel()
			return errors.New("fcm request failed")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+access)
		resp, err := f.client.Do(req)
		if err != nil {
			cancel()
			return errors.New("fcm unreachable")
		}
		reply, _ := io.ReadAll(io.LimitReader(resp.Body, maxReply))
		resp.Body.Close()
		cancel()
		switch {
		case resp.StatusCode == http.StatusOK:
			return nil
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			f.forgetToken() // the cached access token went stale: get a new one once
			continue
		}
		code, status := errorCode(reply)
		if code == "UNREGISTERED" || (resp.StatusCode == http.StatusNotFound && (status == "NOT_FOUND" || status == "UNREGISTERED")) {
			return ErrUnregistered
		}
		if code == "" {
			code = status
		}
		return &Error{Status: resp.StatusCode, Code: code, RetryAfter: retryAfter(resp.Header.Get("Retry-After"), f.now())}
	}
}

// errorCode reads Google's error reply: the FCM errorCode from its details, and the Google status.
func errorCode(reply []byte) (code, status string) {
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(reply, &e) != nil {
		return "", ""
	}
	for _, d := range e.Error.Details {
		if d.ErrorCode != "" {
			code = d.ErrorCode
			break
		}
	}
	// Only short upper-case words, so nothing odd from the reply reaches a log line.
	clean := func(v string) string {
		if len(v) > 40 {
			return ""
		}
		for _, c := range v {
			if (c < 'A' || c > 'Z') && c != '_' {
				return ""
			}
		}
		return v
	}
	return clean(code), clean(e.Error.Status)
}

// retryAfter reads a Retry-After header in seconds or as an HTTP date; 0 when absent or unreadable.
func retryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n <= 0 {
			return 0
		}
		return time.Duration(min(n, 86400)) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}
