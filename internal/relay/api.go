// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/MeshCore-Beacon/beacon-push/internal/fcm"
	"github.com/MeshCore-Beacon/beacon-push/internal/store"
)

// HelloResponse is what a server learns about itself at startup and every hour.
type HelloResponse struct {
	PushID         string `json:"pushId"`
	Name           string `json:"name"`
	Status         string `json:"status" enums:"active,suspended"`
	Tier           string `json:"tier" enums:"email,verified,custom"`
	Limits         Limits `json:"limits"`
	URL            string `json:"url,omitempty"`
	DomainVerified bool   `json:"domainVerified"`
	TermsOutdated  bool   `json:"termsOutdated"`
	Devices        int    `json:"devices"`
}

// Limits are the send quotas that apply to a server.
type Limits struct {
	PerMinute       int `json:"perMinute"`
	PerDay          int `json:"perDay"`
	PerDevicePerDay int `json:"perDevicePerDay"`
}

func (s *Server) hello(w http.ResponseWriter, r *http.Request, inst store.Instance) {
	now := s.now()
	if inst.URL != "" && inst.Status == store.StatusActive && now.Sub(time.UnixMilli(inst.DomainCheckedAt)) >= DomainRecheck {
		go s.checkDomainOnce(context.WithoutCancel(r.Context()), inst)
	}
	devices, err := s.store.CountHandles(r.Context(), inst.ID)
	if err != nil {
		s.log.Error("handle count failed", "component", "relay", "push_id", inst.ID, "err", err)
	}
	t := TierFor(inst)
	writeJSON(w, http.StatusOK, HelloResponse{PushID: inst.ID, Name: inst.Name, Status: inst.Status, Tier: t.Name,
		Limits: Limits{PerMinute: t.PerMinute, PerDay: t.PerDay, PerDevicePerDay: HandlePerDay}, URL: inst.URL,
		DomainVerified: inst.DomainVerifiedAt != 0, TermsOutdated: inst.TermsVersion < TermsVersion, Devices: devices})
}

func (s *Server) verifyDomain(w http.ResponseWriter, r *http.Request, inst store.Instance) {
	if inst.URL == "" {
		writeError(w, http.StatusConflict, "no_url", "This server was registered without a public URL.")
		return
	}
	if ok, wait := s.hour.Allow("domain:"+inst.ID, DomainChecksPerHour, s.now()); !ok {
		rateLimited(w, wait)
		return
	}
	if err := s.checkDomain(r.Context(), inst); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"domainVerified": false, "reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domainVerified": true})
}

// SendRequest is a batch of notifications from one server.
type SendRequest struct {
	Messages []SendItem `json:"messages"`
}

// SendItem is one encrypted notification for one device handle.
type SendItem struct {
	Handle      string `json:"handle"`
	Ciphertext  string `json:"ciphertext"`            // standard base64
	CollapseKey string `json:"collapseKey,omitempty"` // at most 40 of A-Z a-z 0-9 _ - . :
	TTLSeconds  int    `json:"ttlSeconds,omitempty"`  // default one day, at most 28 days
}

// SendResult answers one item, in request order.
type SendResult struct {
	MessageID string `json:"messageId,omitempty"`
	Status    string `json:"status" enums:"ok,rate_limited,invalid_handle,too_large,invalid,failed"`
}

// Send statuses.
const (
	StatusOK            = "ok"
	StatusRateLimited   = "rate_limited"
	StatusInvalidHandle = "invalid_handle" // delete this device
	StatusTooLarge      = "too_large"
	StatusInvalid       = "invalid"
	StatusFailed        = "failed" // retry later
)

func validCollapseKey(k string) bool {
	if len(k) > MaxCollapseKey {
		return false
	}
	for _, c := range k {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}

func dayStart(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func (s *Server) send(w http.ResponseWriter, r *http.Request, inst store.Instance) {
	if inst.Status != store.StatusActive {
		writeError(w, http.StatusForbidden, "suspended", "This server is suspended from the push relay. Contact abuse@meshcorebeacon.ca.")
		return
	}
	var req SendRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Messages) == 0 || len(req.Messages) > MaxBatch {
		writeError(w, http.StatusBadRequest, "bad_request", "Send between 1 and 100 messages.")
		return
	}
	ctx := r.Context()
	// One batch per server at a time, so concurrent requests cannot each pass the daily check on the same count.
	unlock := s.lockInstance(inst.ID)
	defer unlock()
	now := s.now()
	tier := TierFor(inst)
	sentToday, err := s.store.SentToday(ctx, inst.ID, now)
	if err != nil {
		s.internal(w, "usage read failed", err)
		return
	}
	globalToday, err := s.store.GlobalSentToday(ctx, now)
	if err != nil {
		s.internal(w, "usage read failed", err)
		return
	}

	results := make([]SendResult, len(req.Messages))
	var wait time.Duration
	limited := func(i int, d time.Duration) {
		results[i].Status = StatusRateLimited
		if d > wait {
			wait = d
		}
		if err := s.store.BumpUsage(ctx, inst.ID, now, store.UsageRateLimited); err != nil {
			s.log.Warn("usage not counted", "component", "relay", "push_id", inst.ID, "err", err)
		}
	}
	untilTomorrow := dayStart(now).Add(24 * time.Hour).Sub(now)

	for i, item := range req.Messages {
		ct, err := base64.StdEncoding.DecodeString(item.Ciphertext)
		switch {
		case err != nil || len(ct) == 0 || !validCollapseKey(item.CollapseKey) || item.TTLSeconds < 0 ||
			int64(item.TTLSeconds) > int64(MaxTTL/time.Second): // compare seconds, a Duration product can overflow
			results[i].Status = StatusInvalid
			continue
		case len(ct) > MaxCiphertext:
			results[i].Status = StatusTooLarge
			continue
		}

		h, err := s.store.Handle(ctx, item.Handle)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internal(w, "handle lookup failed", err)
			return
		}
		missing := errors.Is(err, store.ErrNotFound)
		// Only another server's live handle proves harvesting. A missing one may simply have been purged, and a
		// guessed one reaches nobody.
		stolen := !missing && h.InstanceID != inst.ID && h.RevokedAt == 0
		if s.harvest.add(inst.ID, stolen, now) {
			s.suspendForHarvesting(ctx, inst)
			writeError(w, http.StatusForbidden, "suspended", "This server is suspended from the push relay. Contact abuse@meshcorebeacon.ca.")
			return
		}
		if missing || stolen || h.RevokedAt != 0 {
			results[i].Status = StatusInvalidHandle
			if err := s.store.BumpUsage(ctx, inst.ID, now, store.UsageInvalidHandle); err != nil {
				s.log.Warn("usage not counted", "component", "relay", "push_id", inst.ID, "err", err)
			}
			continue
		}

		if globalToday >= GlobalPerDay {
			s.log.Warn("global daily push limit reached", "component", "relay", "limit", GlobalPerDay)
			limited(i, untilTomorrow)
			continue
		}
		if sentToday >= tier.PerDay {
			limited(i, untilTomorrow)
			continue
		}
		if ok, d := s.minute.Allow("inst:"+inst.ID, tier.PerMinute, now); !ok {
			limited(i, d)
			continue
		}
		if ok, d := s.minute.Allow("handle:"+h.Handle, HandlePerMinute, now); !ok {
			limited(i, d)
			continue
		}
		toHandle, err := s.store.HandleSentSince(ctx, h.Handle, dayStart(now))
		if err != nil {
			s.internal(w, "handle usage read failed", err)
			return
		}
		if toHandle >= HandlePerDay {
			limited(i, untilTomorrow)
			continue
		}

		msgID := "m_" + randomString(16)
		ttl := DefaultTTL
		if item.TTLSeconds > 0 {
			ttl = time.Duration(item.TTLSeconds) * time.Second
		}
		collapse := ""
		if item.CollapseKey != "" {
			collapse = inst.ID + ":" + item.CollapseKey
		}
		err = s.push.Send(ctx, fcm.Message{
			Token: h.FCMToken,
			Data: map[string]string{"v": "1", "pushId": inst.ID, "serverName": inst.Name, "messageId": msgID,
				"ct": base64.StdEncoding.EncodeToString(ct)},
			CollapseKey: collapse, TTL: ttl, AlertTitle: inst.Name, AlertBody: "New alert",
		})
		switch {
		case err == nil:
			sum := sha256.Sum256(ct)
			if err := s.store.RecordSend(ctx, store.Send{MessageID: msgID, InstanceID: inst.ID, Handle: h.Handle, Status: StatusOK,
				At: now, Size: len(ct), CiphertextSHA256: sum[:]}); err != nil {
				s.log.Error("send not recorded", "component", "relay", "push_id", inst.ID, "err", err)
			}
			sentToday++
			globalToday++
			results[i] = SendResult{MessageID: msgID, Status: StatusOK}
		case errors.Is(err, fcm.ErrUnregistered):
			if err := s.store.RevokeHandle(ctx, h.Handle, now); err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.Warn("handle not revoked", "component", "relay", "push_id", inst.ID, "err", err)
			}
			_ = s.store.BumpUsage(ctx, inst.ID, now, store.UsageInvalidHandle)
			results[i].Status = StatusInvalidHandle
		default:
			s.log.Warn("push not delivered", "component", "relay", "push_id", inst.ID, "err", err)
			results[i].Status = StatusFailed
		}
	}
	if wait > 0 {
		w.Header().Set("Retry-After", retryAfter(wait))
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) suspendForHarvesting(ctx context.Context, inst store.Instance) {
	if err := s.store.SetStatus(ctx, inst.ID, store.StatusSuspended, nil, s.now()); err != nil {
		s.log.Error("automatic suspension failed", "component", "relay", "push_id", inst.ID, "err", err)
		return
	}
	s.log.Warn("server suspended automatically: too many unknown device handles", "component", "relay", "push_id", inst.ID)
	go s.notifyAdmin(ctx, "Push server suspended automatically: "+inst.ID,
		"Server "+inst.ID+" ("+inst.Name+", "+inst.Email+") addressed too many device handles that are not its own in an hour,\n"+
			"which looks like harvested handles. It is suspended until you run:\n\n  beacon-push admin unsuspend "+inst.ID+"\n")
}

func (s *Server) internal(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "component", "relay", "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
}
