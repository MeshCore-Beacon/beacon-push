// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func prod() map[string]string {
	return map[string]string{
		"PUSH_PUBLIC_URL":           "https://push.meshcorebeacon.ca/",
		"PUSH_FIREBASE_CREDENTIALS": "/run/secrets/firebase.json",
		"PUSH_APNS_KEY":             "/run/secrets/apns.p8",
		"PUSH_APNS_KEY_ID":          "ABC123DEFG",
		"PUSH_APNS_TEAM_ID":         "TEAM123456",
		"PUSH_APNS_TOPIC":           "meshcorebeacon.app",
		"PUSH_SMTP_HOST":            "mail.example.ca",
		"PUSH_SMTP_FROM":            "Beacon Push <noreply@meshcorebeacon.ca>",
	}
}

func TestLoadProduction(t *testing.T) {
	c, err := Load(env(prod()))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL.String() != "https://push.meshcorebeacon.ca" || c.ListenAddr != ":8080" || c.SMTPPort != 587 || !c.SMTPStartTLS ||
		c.DatabasePath != "/data/beacon-push.db" || c.DevMode || c.TrustProxy || c.APNsKey != "/run/secrets/apns.p8" ||
		c.APNsKeyID != "ABC123DEFG" || c.APNsTeamID != "TEAM123456" || c.APNsTopic != "meshcorebeacon.app" {
		t.Fatalf("%+v", c)
	}
}

func TestLoadRefusesIncompleteProduction(t *testing.T) {
	for key, want := range map[string]string{
		"PUSH_PUBLIC_URL":           "PUSH_PUBLIC_URL",
		"PUSH_FIREBASE_CREDENTIALS": "PUSH_FIREBASE_CREDENTIALS",
		"PUSH_APNS_KEY":             "PUSH_APNS_KEY",
		"PUSH_APNS_KEY_ID":          "PUSH_APNS_KEY_ID",
		"PUSH_APNS_TEAM_ID":         "PUSH_APNS_TEAM_ID",
		"PUSH_APNS_TOPIC":           "PUSH_APNS_TOPIC",
		"PUSH_SMTP_HOST":            "PUSH_SMTP_HOST",
		"PUSH_SMTP_FROM":            "PUSH_SMTP_FROM",
	} {
		m := prod()
		delete(m, key)
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("without %s: %v", key, err)
		}
	}
	for key, val := range map[string]string{
		"PUSH_PUBLIC_URL":   "http://push.meshcorebeacon.ca",
		"PUSH_SMTP_PORT":    "70000",
		"PUSH_DEV_MODE":     "maybe",
		"PUSH_ADMIN_EMAIL":  "not an address",
		"PUSH_APNS_KEY_ID":  "abc123defg",
		"PUSH_APNS_TEAM_ID": "TEAM12345",
		"PUSH_APNS_TOPIC":   "bad topic",
	} {
		m := prod()
		m[key] = val
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("%s=%s: %v", key, val, err)
		}
	}
	m := prod()
	m["PUSH_PUBLIC_URL"] = "https://push.meshcorebeacon.ca/sub"
	if _, err := Load(env(m)); err == nil {
		t.Error("a path in PUSH_PUBLIC_URL must be refused")
	}
}

func TestLoadDevMode(t *testing.T) {
	c, err := Load(env(map[string]string{"PUSH_DEV_MODE": "true", "PUSH_PUBLIC_URL": "http://localhost:8080"}))
	if err != nil || !c.DevMode || c.PublicURL.Scheme != "http" {
		t.Fatalf("%+v %v", c, err)
	}
}
