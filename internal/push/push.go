// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package push is what every push provider shares: the message, the sender and the errors the relay acts on.
package push

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// Platforms and the provider each one goes through.
const (
	IOS     = "ios"
	Android = "android"
	APNs    = "apns"
	FCM     = "fcm"
)

// APNs environments a device token belongs to.
const (
	Sandbox    = "sandbox"
	Production = "production"
)

// Provider is the push service that delivers to a platform.
func Provider(platform string) string {
	if platform == IOS {
		return APNs
	}
	return FCM
}

// Message is one notification for one device. Data is delivered as is; the app decrypts what it carries. On iOS the
// alert text is a placeholder the app's Notification Service Extension replaces after decrypting.
type Message struct {
	Platform    string // ios or android
	Token       string
	APNsEnv     string // sandbox or production, iOS only
	Data        map[string]string
	CollapseKey string // at most 64 bytes; empty means none
	TTL         time.Duration
	AlertTitle  string // iOS placeholder
	AlertBody   string // iOS placeholder
}

// Sender sends one message.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// What a provider's answer means for the relay. Match them with errors.Is; an *Error also carries the details.
var (
	ErrUnregistered = errors.New("push: token unregistered")     // the handle should go
	ErrInvalid      = errors.New("push: message refused")        // sending it again cannot work
	ErrTooLarge     = errors.New("push: message too large")      // over the provider's payload limit
	ErrThrottled    = errors.New("push: device throttled")       // too many messages for this device
	ErrUnavailable  = errors.New("push: provider unavailable")   // an outage: back off from the whole provider
	ErrAuth         = errors.New("push: provider refused relay") // the relay's own credentials failed
)

// Error is a provider's refusal. It keeps the status, the error code and the asked-for wait, never the token or the
// reply body.
type Error struct {
	Provider   string
	Status     int
	Code       string        // the provider's reason; may be empty
	RetryAfter time.Duration // 0 when the provider gave none
	Kind       error         // one of the sentinels above, or nil
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s answered %d %s", e.Provider, e.Status, e.Code)
	}
	return fmt.Sprintf("%s answered %d", e.Provider, e.Status)
}

// Is matches the error's kind.
func (e *Error) Is(target error) bool { return e.Kind != nil && target == e.Kind }

// Router sends iOS messages through IOS and Android ones through Android.
type Router struct {
	IOS, Android Sender
}

func (r Router) Send(ctx context.Context, m Message) error {
	switch m.Platform {
	case IOS:
		return r.IOS.Send(ctx, m)
	case Android:
		return r.Android.Send(ctx, m)
	}
	return ErrInvalid
}

// Log is a Sender for dev mode: it logs that a message would go out, without the token or the data.
type Log struct{}

func (Log) Send(_ context.Context, m Message) error {
	slog.Info("push (dev mode, not sent)", "component", Provider(m.Platform), "platform", m.Platform, "apns_env", m.APNsEnv,
		"data_keys", len(m.Data), "collapse_key", m.CollapseKey)
	return nil
}

// RetryAfter reads a Retry-After header in seconds or as an HTTP date; 0 when absent or unreadable.
func RetryAfter(v string, now time.Time) time.Duration {
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
