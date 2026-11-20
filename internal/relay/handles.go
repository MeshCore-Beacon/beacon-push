// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/MeshCore-Beacon/beacon-push/internal/push"
	"github.com/MeshCore-Beacon/beacon-push/internal/store"
)

// HandleRequest registers a device with one server.
type HandleRequest struct {
	PushID          string `json:"pushId"`
	Platform        string `json:"platform" enums:"ios,android"`
	Token           string `json:"token"`                                                // APNs device token on iOS, FCM token on Android
	APNSEnvironment string `json:"apnsEnvironment,omitempty" enums:"sandbox,production"` // iOS only, required there
}

// HandleResponse is the device's handle for that server and the secret that lets the app change or delete it.
type HandleResponse struct {
	Handle       string `json:"handle"`
	HandleSecret string `json:"handleSecret"`
}

// HandleUpdate is the app proving it owns a handle, with the current token (and APNs environment on iOS) on a refresh.
type HandleUpdate struct {
	HandleSecret    string `json:"handleSecret"`
	Token           string `json:"token,omitempty"`
	APNSEnvironment string `json:"apnsEnvironment,omitempty" enums:"sandbox,production"`
}

// validToken takes the characters FCM registration tokens are made of, so a mangled token is refused up front.
func validToken(t string) bool {
	if t == "" || len(t) > 4096 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-', c == ':':
		default:
			return false
		}
	}
	return true
}

// validAPNsToken takes an APNs device token: hex, a whole number of bytes, 32 to 100 of them.
func validAPNsToken(t string) bool {
	if len(t) < 64 || len(t) > 200 || len(t)%2 != 0 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// checkDevice validates a token and APNs environment for the platform, answering 400 when they do not fit. It
// returns the token as stored.
func checkDevice(w http.ResponseWriter, platform, token, env string) (string, bool) {
	if platform == push.IOS {
		if env != push.Sandbox && env != push.Production {
			writeError(w, http.StatusBadRequest, "bad_apns_environment", "apnsEnvironment must be sandbox or production on iOS.")
			return "", false
		}
		if !validAPNsToken(token) {
			writeError(w, http.StatusBadRequest, "bad_token", "token is missing or not an APNs device token.")
			return "", false
		}
		return strings.ToLower(token), true
	}
	if env != "" {
		writeError(w, http.StatusBadRequest, "bad_apns_environment", "apnsEnvironment is only for iOS.")
		return "", false
	}
	if !validToken(token) {
		writeError(w, http.StatusBadRequest, "bad_token", "token is missing or malformed.")
		return "", false
	}
	return token, true
}

func (s *Server) createHandle(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	if ok, wait := s.hour.Allow("handle-create:"+s.clientIP(r), HandleCreatesPerHour, now); !ok {
		rateLimited(w, wait)
		return
	}
	var req HandleRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Platform != push.IOS && req.Platform != push.Android {
		writeError(w, http.StatusBadRequest, "bad_platform", "platform must be ios or android.")
		return
	}
	token, ok := checkDevice(w, req.Platform, req.Token, req.APNSEnvironment)
	if !ok {
		return
	}
	inst, err := s.store.Instance(r.Context(), req.PushID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "unknown_server", "This server is not registered with the push relay.")
		return
	}
	if err != nil {
		s.internal(w, "instance lookup failed", err)
		return
	}
	if inst.Status != store.StatusActive {
		writeError(w, http.StatusForbidden, "server_unavailable", "This server cannot send push notifications right now.")
		return
	}
	secret := randomString(32)
	handle, err := s.store.UpsertHandle(r.Context(), "h_"+randomString(16), inst.ID, req.Platform, token, req.APNSEnvironment, hash(secret), now)
	if err != nil {
		s.internal(w, "handle not stored", err)
		return
	}
	s.reviewDeviceCount(r, inst)
	writeJSON(w, http.StatusOK, HandleResponse{Handle: handle, HandleSecret: secret})
}

// reviewDeviceCount tells the admin, once, when an email-tier server passes the device count worth a look.
func (s *Server) reviewDeviceCount(r *http.Request, inst store.Instance) {
	if TierFor(inst).Name != "email" {
		return
	}
	if _, done := s.reviewed.Load(inst.ID); done {
		return
	}
	n, err := s.store.CountHandles(r.Context(), inst.ID)
	if err != nil || n < HandleReviewThreshold {
		return
	}
	if _, done := s.reviewed.LoadOrStore(inst.ID, struct{}{}); done {
		return
	}
	go s.notifyAdmin(r.Context(), "Push server worth a review: "+inst.ID,
		fmt.Sprintf("Server %s (%s, %s) is on the email tier and now has %d devices. Nothing was refused.\n"+
			"Check it with: beacon-push admin show %s\n", inst.ID, inst.Name, inst.Email, n, inst.ID))
}

// ownedHandle loads the handle in the path and checks the secret. Unknown handles and wrong secrets get the same
// answer.
func (s *Server) ownedHandle(w http.ResponseWriter, r *http.Request, secret string) (store.Handle, bool) {
	h, err := s.store.Handle(r.Context(), chi.URLParam(r, "handle"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, "handle lookup failed", err)
		return store.Handle{}, false
	}
	if err != nil || h.RevokedAt != 0 || secret == "" || subtle.ConstantTimeCompare(hash(secret), h.SecretHash) != 1 {
		writeError(w, http.StatusNotFound, "unknown_handle", "No such handle, or the handle secret is wrong.")
		return store.Handle{}, false
	}
	return h, true
}

func (s *Server) refreshHandle(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	if ok, wait := s.hour.Allow("handle-update:"+s.clientIP(r), HandleUpdatesPerHour, now); !ok {
		rateLimited(w, wait)
		return
	}
	var req HandleUpdate
	if !decode(w, r, &req) {
		return
	}
	h, ok := s.ownedHandle(w, r, req.HandleSecret)
	if !ok {
		return
	}
	// The handle's platform decides what a valid token is, so ownership is checked first.
	token, ok := checkDevice(w, h.Platform, req.Token, req.APNSEnvironment)
	if !ok {
		return
	}
	if err := s.store.RefreshHandleToken(r.Context(), h.Handle, h.InstanceID, token, req.APNSEnvironment, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown_handle", "No such handle, or the handle secret is wrong.")
			return
		}
		s.internal(w, "handle not refreshed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteHandle(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	if ok, wait := s.hour.Allow("handle-update:"+s.clientIP(r), HandleUpdatesPerHour, now); !ok {
		rateLimited(w, wait)
		return
	}
	var req HandleUpdate
	if !decode(w, r, &req) {
		return
	}
	h, ok := s.ownedHandle(w, r, req.HandleSecret)
	if !ok {
		return
	}
	if err := s.store.RevokeHandle(r.Context(), h.Handle, now); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, "handle not revoked", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
