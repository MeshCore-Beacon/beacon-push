// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package push

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

type recorder struct{ got []Message }

func (r *recorder) Send(_ context.Context, m Message) error {
	r.got = append(r.got, m)
	return nil
}

func TestRouterSendsEachPlatformToItsProvider(t *testing.T) {
	ios, android := &recorder{}, &recorder{}
	r := Router{IOS: ios, Android: android}
	for _, p := range []string{IOS, Android, Android} {
		if err := r.Send(context.Background(), Message{Platform: p, Token: p}); err != nil {
			t.Fatal(err)
		}
	}
	if len(ios.got) != 1 || ios.got[0].Token != IOS || len(android.got) != 2 {
		t.Fatalf("ios %+v android %+v", ios.got, android.got)
	}
	if err := r.Send(context.Background(), Message{Platform: "web"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown platform: %v", err)
	}
	if Provider(IOS) != APNs || Provider(Android) != FCM {
		t.Fatal("provider names")
	}
}

func TestErrorMatchesItsKind(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &Error{Provider: APNs, Status: 429, Code: "TooManyRequests", Kind: ErrThrottled})
	var pe *Error
	if !errors.Is(err, ErrThrottled) || errors.Is(err, ErrUnavailable) || !errors.As(err, &pe) || pe.Status != 429 {
		t.Fatalf("%v", err)
	}
	if err.Error() != "wrapped: apns answered 429 TooManyRequests" {
		t.Fatalf("%q", err.Error())
	}
	if errors.Is(&Error{Provider: FCM, Status: 502}, ErrUnavailable) {
		t.Fatal("an error without a kind matched one")
	}
}
