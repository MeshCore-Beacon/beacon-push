// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config reads the relay's settings from the environment. Every secret comes from the environment or a
// mounted file, never from source.
package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
)

// Config is the relay's settings.
type Config struct {
	ListenAddr string
	// PublicURL is where operators and apps reach the relay; every mailed link is built from it.
	PublicURL *url.URL
	// DatabasePath is the SQLite file.
	DatabasePath string
	// FirebaseCredentials is the path of the service-account key file, for Android. Empty only in dev mode.
	FirebaseCredentials string
	// APNsKey is the path of the .p8 token key, for iOS; APNsKeyID and APNsTeamID name it and APNsTopic is the app's
	// bundle ID. Empty only in dev mode.
	APNsKey, APNsKeyID, APNsTeamID, APNsTopic string
	SMTPHost                                  string
	SMTPPort                                  int
	SMTPUsername                              string
	SMTPPassword                              string
	SMTPFrom                                  string
	SMTPStartTLS                              bool
	// AdminEmail receives notices of new servers and automatic suspensions. Empty sends none.
	AdminEmail string
	// TrustProxy takes the client address from the last X-Forwarded-For entry, for running behind Caddy.
	TrustProxy bool
	// DevMode logs mail and pushes instead of sending them, and lets the domain check reach plain http and private
	// addresses. Never on in production.
	DevMode bool
}

// Load reads the configuration through getenv.
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		ListenAddr:          or(getenv("PUSH_LISTEN_ADDR"), ":8080"),
		DatabasePath:        or(getenv("PUSH_DATABASE_PATH"), "/data/beacon-push.db"),
		FirebaseCredentials: strings.TrimSpace(getenv("PUSH_FIREBASE_CREDENTIALS")),
		APNsKey:             strings.TrimSpace(getenv("PUSH_APNS_KEY")),
		APNsKeyID:           strings.TrimSpace(getenv("PUSH_APNS_KEY_ID")),
		APNsTeamID:          strings.TrimSpace(getenv("PUSH_APNS_TEAM_ID")),
		APNsTopic:           strings.TrimSpace(getenv("PUSH_APNS_TOPIC")),
		SMTPHost:            strings.TrimSpace(getenv("PUSH_SMTP_HOST")),
		SMTPUsername:        getenv("PUSH_SMTP_USERNAME"),
		SMTPPassword:        getenv("PUSH_SMTP_PASSWORD"),
		SMTPFrom:            strings.TrimSpace(getenv("PUSH_SMTP_FROM")),
		AdminEmail:          strings.TrimSpace(getenv("PUSH_ADMIN_EMAIL")),
	}
	var err error
	if c.DevMode, err = boolean(getenv, "PUSH_DEV_MODE", false); err != nil {
		return Config{}, err
	}
	if c.TrustProxy, err = boolean(getenv, "PUSH_TRUST_PROXY", false); err != nil {
		return Config{}, err
	}
	if c.SMTPStartTLS, err = boolean(getenv, "PUSH_SMTP_STARTTLS", true); err != nil {
		return Config{}, err
	}
	c.SMTPPort = 587
	if v := getenv("PUSH_SMTP_PORT"); v != "" {
		if c.SMTPPort, err = strconv.Atoi(v); err != nil || c.SMTPPort < 1 || c.SMTPPort > 65535 {
			return Config{}, errors.New("PUSH_SMTP_PORT must be between 1 and 65535")
		}
	}

	raw := strings.TrimRight(strings.TrimSpace(getenv("PUSH_PUBLIC_URL")), "/")
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return Config{}, errors.New("PUSH_PUBLIC_URL must be the relay's base URL, e.g. https://push.meshcorebeacon.ca")
	}
	if u.Scheme != "https" && !(c.DevMode && u.Scheme == "http") {
		return Config{}, errors.New("PUSH_PUBLIC_URL must be https")
	}
	u.Path = ""
	c.PublicURL = u

	if c.DevMode {
		return c, nil
	}
	if c.FirebaseCredentials == "" {
		return Config{}, errors.New("PUSH_FIREBASE_CREDENTIALS: required, the path of the Firebase service-account key file")
	}
	if c.APNsKey == "" {
		return Config{}, errors.New("PUSH_APNS_KEY: required, the path of the APNs .p8 key file")
	}
	if !appleID(c.APNsKeyID) {
		return Config{}, errors.New("PUSH_APNS_KEY_ID: required, the 10-character ID of the APNs key")
	}
	if !appleID(c.APNsTeamID) {
		return Config{}, errors.New("PUSH_APNS_TEAM_ID: required, the 10-character Apple team ID")
	}
	if c.APNsTopic == "" || strings.ContainsAny(c.APNsTopic, " /") {
		return Config{}, errors.New("PUSH_APNS_TOPIC: required, the app's bundle ID, e.g. meshcorebeacon.app")
	}
	if c.SMTPHost == "" {
		return Config{}, errors.New("PUSH_SMTP_HOST: required, registration works by mailed links")
	}
	if _, err := mail.ParseAddress(c.SMTPFrom); err != nil {
		return Config{}, errors.New("PUSH_SMTP_FROM: required, one address, e.g. \"Beacon Push <noreply@meshcorebeacon.ca>\"")
	}
	if c.AdminEmail != "" {
		if _, err := mail.ParseAddress(c.AdminEmail); err != nil {
			return Config{}, errors.New("PUSH_ADMIN_EMAIL: not a valid address")
		}
	}
	return c, nil
}

// appleID is the shape of Apple key and team IDs: 10 upper-case letters or digits.
func appleID(v string) bool {
	if len(v) != 10 {
		return false
	}
	for _, c := range v {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func or(v, def string) string {
	if v = strings.TrimSpace(v); v != "" {
		return v
	}
	return def
}

func boolean(getenv func(string) string, key string, def bool) (bool, error) {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", key)
	}
	return b, nil
}
