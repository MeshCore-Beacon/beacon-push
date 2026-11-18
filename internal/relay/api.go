// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
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

// SendRequest is a batch from one server.
type SendRequest struct {
	Messages []SendItem `json:"messages"`
}

// SendItem is one encrypted notification for one device handle.
type SendItem struct {
	Handle      string `json:"handle"`
	Ciphertext  string `json:"ciphertext"`            // standard base64
	CollapseKey string `json:"collapseKey,omitempty"` // at most 40 of A-Z a-z 0-9 _ - . :
	TTLSeconds  int    `json:"ttlSeconds,omitempty"`  // default one day, at most 28 days
	ID          string `json:"id,omitempty"`          // idempotency key, at most 64 of A-Z a-z 0-9 _ - . :
}

// SendResult answers one item, in request order.
type SendResult struct {
	MessageID         string `json:"messageId,omitempty"`
	Status            string `json:"status" enums:"ok,rate_limited,invalid_handle,too_large,invalid,failed"`
	RetryAfterSeconds int    `json:"retryAfterSeconds,omitempty"` // on rate_limited, and failed after an FCM outage
}

// Send statuses.
const (
	StatusOK            = "ok"
	StatusRateLimited   = "rate_limited"   // not sent; retry after the wait, not an attempt
	StatusInvalidHandle = "invalid_handle" // delete this device
	StatusTooLarge      = "too_large"
	StatusInvalid       = "invalid"
	StatusFailed        = "failed" // retry later
)

// validKey is the alphabet of collapse keys and ids.
func validKey(k string, max int) bool {
	if len(k) > max {
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

func writeSuspended(w http.ResponseWriter, status string) {
	if status == store.StatusBanned {
		writeError(w, http.StatusForbidden, "banned", "This server is banned from the push relay.")
		return
	}
	writeError(w, http.StatusForbidden, "suspended", "This server is suspended from the push relay. Contact abuse@meshcorebeacon.ca.")
}

// sendJob is an item that passed the checks and is ready to go to FCM.
type sendJob struct {
	i      int
	item   SendItem
	ct     []byte
	handle store.Handle
}

// batch is what every item of one send shares.
type batch struct {
	inst     store.Instance
	now      time.Time
	deadline time.Time       // wall clock: items not started by then are deferred
	db       context.Context // outlives the request, so a reply already sent is still recorded
	stop     atomic.Bool     // the store failed: start nothing more
}

func (s *Server) send(w http.ResponseWriter, r *http.Request, inst store.Instance) {
	if inst.Status != store.StatusActive {
		writeSuspended(w, inst.Status)
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
	// One batch per server at a time, so its harvesting count and limits see every earlier batch.
	unlock, err := s.lockInstance(ctx, inst.ID)
	if err != nil {
		return
	}
	defer unlock()
	// A batch that waited may be behind a suspension, ban or quota change.
	inst, err = s.store.Instance(ctx, inst.ID)
	if err != nil {
		s.internal(w, "instance reload failed", err)
		return
	}
	if inst.Status != store.StatusActive {
		writeSuspended(w, inst.Status)
		return
	}
	b := &batch{inst: inst, now: s.now(), deadline: time.Now().Add(s.batchDeadline), db: context.WithoutCancel(ctx)}

	results := make([]SendResult, len(req.Messages))
	var jobs []sendJob
	for i, item := range req.Messages {
		ct, err := base64.StdEncoding.DecodeString(item.Ciphertext)
		switch {
		case err != nil || len(ct) == 0 || !validKey(item.CollapseKey, MaxCollapseKey) || !validKey(item.ID, MaxClientID) ||
			item.TTLSeconds < 0 || int64(item.TTLSeconds) > int64(MaxTTL/time.Second): // compare seconds, a Duration product can overflow
			results[i].Status = StatusInvalid
			continue
		case len(ct) > MaxCiphertext:
			results[i].Status = StatusTooLarge
			continue
		}
		// A repeat of a sent id gets its first answer, whatever has changed since: nothing is sent or counted.
		if item.ID != "" {
			st, msgID, _, err := s.store.SentByClientID(ctx, inst.ID, item.ID)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.internal(w, "send lookup failed", err)
				return
			}
			if err == nil && st == store.SendOK {
				results[i] = SendResult{MessageID: msgID, Status: StatusOK}
				continue
			}
		}

		h, err := s.store.Handle(ctx, item.Handle)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internal(w, "handle lookup failed", err)
			return
		}
		// Only live handles count towards harvesting: a missing one may have been purged and reaches nobody, so it
		// can neither prove harvesting nor dilute it.
		live := err == nil && h.RevokedAt == 0
		foreign := live && h.InstanceID != inst.ID
		if live && s.harvest.add(inst.ID, foreign, b.now) {
			s.suspendForHarvesting(b.db, inst)
			writeSuspended(w, store.StatusSuspended)
			return
		}
		if !live || foreign {
			results[i].Status = StatusInvalidHandle
			s.bump(b, store.UsageInvalidHandle)
			continue
		}
		jobs = append(jobs, sendJob{i: i, item: item, ct: ct, handle: h})
	}

	next := make(chan sendJob)
	var wg sync.WaitGroup
	for range min(s.sendWorkers, len(jobs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range next {
				results[j.i] = s.sendOne(ctx, b, j)
			}
		}()
	}
	for _, j := range jobs {
		next <- j
	}
	close(next)
	wg.Wait()

	wait := 0
	for _, res := range results {
		wait = max(wait, res.RetryAfterSeconds)
	}
	if wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) bump(b *batch, field string) {
	if err := s.store.BumpUsage(b.db, b.inst.ID, b.now, field); err != nil {
		s.log.Warn("usage not counted", "component", "relay", "push_id", b.inst.ID, "err", err)
	}
}

func (s *Server) limited(b *batch, d time.Duration) SendResult {
	s.bump(b, store.UsageRateLimited)
	return SendResult{Status: StatusRateLimited, RetryAfterSeconds: seconds(d)}
}

// seconds rounds a wait up to whole seconds, at least one.
func seconds(d time.Duration) int {
	return max(int((d+time.Second-1)/time.Second), 1)
}

// storeFailed stops the batch: without durable accounting nothing more may go out.
func (s *Server) storeFailed(b *batch, what string, err error) SendResult {
	s.log.Error(what, "component", "relay", "push_id", b.inst.ID, "err", err)
	b.stop.Store(true)
	return SendResult{Status: StatusFailed}
}

// sendOne reserves quota for one item, hands it to FCM and records the answer.
func (s *Server) sendOne(ctx context.Context, b *batch, j sendJob) SendResult {
	inst, h := b.inst, j.handle
	if b.stop.Load() {
		return SendResult{Status: StatusFailed}
	}
	if time.Now().After(b.deadline) || ctx.Err() != nil {
		return s.limited(b, DeferredRetry)
	}
	if d := s.pausedFor(s.now()); d > 0 {
		return s.limited(b, d)
	}
	if d := s.cooledFor(h.Handle, s.now()); d > 0 {
		return s.limited(b, d)
	}
	if j.item.ID != "" {
		// A cheap look first, so a repeat in flight spends no rate limit. Reserve decides for real.
		st, _, at, err := s.store.SentByClientID(b.db, inst.ID, j.item.ID)
		switch {
		case err == nil && st == store.SendPending && b.now.Sub(at) < store.PendingTimeout:
			return s.limited(b, InFlightRetry)
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return s.storeFailed(b, "send lookup failed", err)
		}
	}
	// The current row, so a quota changed mid-batch applies to what has not gone out yet.
	cur, err := s.store.Instance(b.db, inst.ID)
	if err != nil {
		return s.storeFailed(b, "instance reload failed", err)
	}
	if cur.Status != store.StatusActive {
		b.stop.Store(true)
		return SendResult{Status: StatusFailed}
	}
	if ok, d := s.minute.Allow("inst:"+inst.ID, TierFor(cur).PerMinute, b.now); !ok {
		return s.limited(b, d)
	}
	if ok, d := s.minute.Allow("handle:"+h.Handle, HandlePerMinute, b.now); !ok {
		return s.limited(b, d)
	}

	sum := sha256.Sum256(j.ct)
	outcome, msgID, err := s.store.Reserve(b.db, store.Reservation{MessageID: "m_" + randomString(16), InstanceID: inst.ID,
		Handle: h.Handle, ClientID: j.item.ID, At: b.now, Size: len(j.ct), CiphertextSHA256: sum[:],
		DayLimit: func(i store.Instance) int { return TierFor(i).PerDay }, GlobalPerDay: GlobalPerDay, HandlePerDay: HandlePerDay})
	if err != nil {
		return s.storeFailed(b, "send not reserved", err)
	}
	untilTomorrow := dayStart(b.now).Add(24 * time.Hour).Sub(b.now)
	switch outcome {
	case store.AlreadySent:
		return SendResult{MessageID: msgID, Status: StatusOK}
	case store.InFlight:
		return s.limited(b, InFlightRetry)
	case store.OverGlobalDay:
		s.log.Warn("global daily push limit reached", "component", "relay", "limit", GlobalPerDay)
		return s.limited(b, untilTomorrow)
	case store.OverInstanceDay, store.OverHandleDay:
		return s.limited(b, untilTomorrow)
	case store.NotActive:
		b.stop.Store(true)
		return SendResult{Status: StatusFailed}
	}

	ttl := DefaultTTL
	if j.item.TTLSeconds > 0 {
		ttl = time.Duration(j.item.TTLSeconds) * time.Second
	}
	collapse := ""
	if j.item.CollapseKey != "" {
		collapse = inst.ID + ":" + j.item.CollapseKey
	}
	// Not cancelled with the request, which would leave the outcome unknown, but bounded as a whole.
	sctx, scancel := context.WithTimeout(b.db, s.sendLimit)
	err = s.push.Send(sctx, fcm.Message{
		Token: h.FCMToken,
		Data: map[string]string{"v": "1", "pushId": inst.ID, "serverName": inst.Name, "messageId": msgID,
			"ct": base64.StdEncoding.EncodeToString(j.ct)},
		CollapseKey: collapse, TTL: ttl, AlertTitle: inst.Name, AlertBody: "New alert",
	})
	scancel()
	if ferr := s.finishSend(b, msgID, err == nil); ferr != nil {
		s.log.Error("send outcome not recorded", "component", "relay", "push_id", inst.ID, "err", ferr)
		if err == nil {
			// Unrecorded, an ok could not be repeated for this id, so the sender must not count on it.
			b.stop.Store(true)
			return SendResult{Status: StatusFailed}
		}
	}
	var fe *fcm.Error
	switch {
	case err == nil:
		s.fcmRecovered()
		return SendResult{MessageID: msgID, Status: StatusOK}
	case errors.Is(err, fcm.ErrUnregistered):
		uctx, ucancel := context.WithTimeout(b.db, finishSendTimeout)
		defer ucancel()
		return s.unregistered(uctx, b, h)
	case errors.Is(err, fcm.ErrInvalidArgument):
		return SendResult{Status: StatusInvalid}
	case errors.As(err, &fe) && fe.Status == http.StatusTooManyRequests:
		d := fe.RetryAfter
		if d <= 0 {
			d = FCMThrottleRetry
		}
		d = min(d, FCMPauseMax)
		s.coolHandle(h.Handle, s.now().Add(d), s.now())
		return s.limited(b, d)
	case errors.As(err, &fe) && (fe.Status == http.StatusInternalServerError || fe.Status == http.StatusServiceUnavailable):
		d := s.pauseFCM(s.now(), fe.RetryAfter)
		s.log.Warn("fcm unavailable, relay paused", "component", "relay", "status", fe.Status, "pause", d.String())
		return SendResult{Status: StatusFailed, RetryAfterSeconds: seconds(d)}
	}
	s.log.Warn("push not delivered", "component", "relay", "push_id", inst.ID, "err", err)
	return SendResult{Status: StatusFailed}
}

// finishSend records FCM's answer on a context of its own, trying a few times before giving up.
func (s *Server) finishSend(b *batch, msgID string, ok bool) error {
	ctx, cancel := context.WithTimeout(b.db, finishSendTimeout)
	defer cancel()
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		if err = s.store.FinishSend(ctx, msgID, ok, s.now()); err == nil || errors.Is(err, store.ErrNotFound) {
			return err
		}
		select {
		case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
		case <-ctx.Done():
			return err
		}
	}
	return err
}

// unregistered revokes a handle FCM no longer knows, unless the app moved it to a new token meanwhile.
func (s *Server) unregistered(ctx context.Context, b *batch, h store.Handle) SendResult {
	err := s.store.RevokeHandleToken(ctx, h.Handle, h.FCMToken, s.now())
	if errors.Is(err, store.ErrNotFound) {
		cur, cerr := s.store.Handle(ctx, h.Handle)
		switch {
		case errors.Is(cerr, store.ErrNotFound), cerr == nil && cur.RevokedAt != 0 && cur.FCMToken == h.FCMToken:
			err = nil // already gone for this token
		case cerr == nil:
			return SendResult{Status: StatusFailed} // a fresh token: retry reaches it
		default:
			err = cerr
		}
	}
	if err != nil {
		s.log.Warn("handle not revoked", "component", "relay", "push_id", b.inst.ID, "err", err)
		return SendResult{Status: StatusFailed}
	}
	s.bump(b, store.UsageInvalidHandle)
	return SendResult{Status: StatusInvalidHandle}
}

func (s *Server) suspendForHarvesting(ctx context.Context, inst store.Instance) {
	done, err := s.store.SuspendIfActive(ctx, inst.ID)
	if err != nil {
		s.log.Error("automatic suspension failed", "component", "relay", "push_id", inst.ID, "err", err)
		return
	}
	if !done {
		return // banned or suspended meanwhile
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
