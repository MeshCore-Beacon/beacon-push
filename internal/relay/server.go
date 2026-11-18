// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package relay is the push relay: the registration pages operators use, the API beacon-server calls to send
// notifications, and the API the Beacon app calls to get a device handle.
package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MeshCore-Beacon/beacon-push/internal/config"
	"github.com/MeshCore-Beacon/beacon-push/internal/limit"
	"github.com/MeshCore-Beacon/beacon-push/internal/mail"
	"github.com/MeshCore-Beacon/beacon-push/internal/push"
	"github.com/MeshCore-Beacon/beacon-push/internal/store"
)

// Limits. Starting numbers; tune with real traffic.
const (
	EmailTierPerMinute    = 30
	EmailTierPerDay       = 500
	VerifiedTierPerMinute = 300
	VerifiedTierPerDay    = 10_000
	HandlePerMinute       = 10
	HandlePerDay          = 200
	GlobalPerDay          = 100_000

	MaxServersPerEmail    = 2
	RegisterPerHourPerIP  = 3
	LinkMailsPerHour      = 5 // per email address
	VerifyPerHourPerIP    = 20
	HandleCreatesPerHour  = 20 // per IP
	HandleUpdatesPerHour  = 60 // per IP
	DomainChecksPerHour   = 10 // per server, on request
	HandleReviewThreshold = 1000

	MaxBody           = 512 << 10 // 100 maximum-size items with room for JSON
	MaxBatch          = 100
	MaxCiphertext     = 2048
	MaxCollapseKey    = 40
	MaxClientID       = 64
	MaxTTL            = 28 * 24 * time.Hour
	DefaultTTL        = 24 * time.Hour
	LinkLifetime      = 24 * time.Hour
	DomainRecheck     = 24 * time.Hour
	TermsVersion      = 1
	harvestMinSends   = 100 // live handles in an hour before the ratio applies
	harvestBadPercent = 20
	harvestForeignMax = 50 // another server's live handles in an hour, whatever the ratio
)

// Send timing. A batch answers within about BatchDeadline plus one provider call (10 s).
const (
	SendWorkers        = 8
	BatchDeadline      = 10 * time.Second
	SendLimit          = 10 * time.Second // one item's whole provider send, token refresh included
	DeferredRetry      = 5 * time.Second  // an item not started before the deadline
	InFlightRetry      = 30 * time.Second // an id whose earlier send has no answer yet
	OutagePauseDefault = time.Minute      // after a provider outage without Retry-After; doubles while outages repeat
	OutagePauseMax     = time.Hour        // cap on the computed backoff
	ProviderWaitMax    = 24 * time.Hour   // sanity cap on a Retry-After a provider sends
	ThrottleRetry      = time.Minute      // after a device throttle without Retry-After
	finishSendTimeout  = 5 * time.Second
)

// Options builds a Server. Now, ChallengeClient and Logger are optional.
type Options struct {
	Config          config.Config
	Store           *store.Store
	Push            push.Sender
	Mail            mail.Sender
	Now             func() time.Time
	ChallengeClient *http.Client
	Logger          *slog.Logger
}

// Server is the relay.
type Server struct {
	cfg       config.Config
	store     *store.Store
	push      push.Sender
	mail      mail.Sender
	now       func() time.Time
	challenge *http.Client
	log       *slog.Logger

	minute, hour  *limit.Window
	harvest       harvestCounter
	checking      sync.Map // server ID -> struct{}, a domain check in flight
	sending       sync.Map // server ID -> chan struct{}, a one-slot lock held for one send batch
	reviewed      sync.Map // server ID -> struct{}, the device-count review notice was sent
	sendWorkers   int
	batchDeadline time.Duration
	sendLimit     time.Duration

	pauseMu sync.Mutex
	pauses  map[string]*outage // provider -> its outage backoff

	coolMu sync.Mutex
	cool   map[string]time.Time // handle -> its provider throttled it until then
}

// outage is one provider's backoff: every send through it waits until pausedUntil.
type outage struct {
	pausedUntil time.Time
	streak      int // outages since the last successful send
}

// New builds the relay.
func New(o Options) *Server {
	s := &Server{cfg: o.Config, store: o.Store, push: o.Push, mail: o.Mail, now: o.Now, challenge: o.ChallengeClient, log: o.Logger,
		minute: limit.New(time.Minute), hour: limit.New(time.Hour), harvest: harvestCounter{m: map[string]*harvestSlot{}},
		sendWorkers: SendWorkers, batchDeadline: BatchDeadline, sendLimit: SendLimit, cool: map[string]time.Time{}, pauses: map[string]*outage{}}
	if s.now == nil {
		s.now = time.Now
	}
	if s.challenge == nil {
		s.challenge = challengeClient(o.Config.DevMode)
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	return s
}

// Handler is the relay's HTTP surface.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(securityHeaders)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	r.Get("/", s.page("index"))
	r.Get("/terms", s.page("terms"))
	r.Get("/privacy", s.page("privacy"))
	r.Get("/register", s.registerForm)
	r.Post("/register", s.register)
	r.Get("/verify", s.page("verify"))
	r.Post("/verify", s.verify)
	r.Handle("/static/*", staticFiles())

	r.Route("/v1", func(r chi.Router) {
		r.Post("/hello", s.withInstance(s.hello))
		r.Post("/verify-domain", s.withInstance(s.verifyDomain))
		r.Post("/send", s.withInstance(s.send))
		r.Post("/handles", s.createHandle)
		r.Put("/handles/{handle}", s.refreshHandle)
		r.Delete("/handles/{handle}", s.deleteHandle)
	})
	return r
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

// lockInstance serialises send batches per server and returns the unlock. The wait ends with ctx.
func (s *Server) lockInstance(ctx context.Context, id string) (func(), error) {
	v, _ := s.sending.LoadOrStore(id, make(chan struct{}, 1))
	slot := v.(chan struct{})
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Server) outageOf(provider string) *outage {
	o := s.pauses[provider]
	if o == nil {
		o = &outage{}
		s.pauses[provider] = o
	}
	return o
}

// pausedFor is how long sends through the provider still wait after it asked the relay to back off.
func (s *Server) pausedFor(provider string, now time.Time) time.Duration {
	s.pauseMu.Lock()
	defer s.pauseMu.Unlock()
	return s.outageOf(provider).pausedUntil.Sub(now)
}

// pauseProvider stops every send through the provider for its Retry-After (at most a day), or a default that doubles
// with each new outage, at most an hour. It returns how long the pause now lasts.
func (s *Server) pauseProvider(provider string, now time.Time, d time.Duration) time.Duration {
	s.pauseMu.Lock()
	defer s.pauseMu.Unlock()
	o := s.outageOf(provider)
	// Sends already in flight when the pause began are the same outage, not a new one.
	if !now.Before(o.pausedUntil) {
		o.streak++
	}
	if d > 0 {
		d = min(d, ProviderWaitMax)
	} else {
		d = min(OutagePauseDefault<<min(max(o.streak-1, 0), 6), OutagePauseMax)
	}
	if until := now.Add(d); until.After(o.pausedUntil) {
		o.pausedUntil = until
	}
	return o.pausedUntil.Sub(now)
}

// providerRecovered resets the provider's backoff after a successful send, unless a pause is still on: a send that
// was in flight when it went down says nothing about the outage being over.
func (s *Server) providerRecovered(provider string, now time.Time) {
	s.pauseMu.Lock()
	if o := s.outageOf(provider); !now.Before(o.pausedUntil) {
		o.streak = 0
	}
	s.pauseMu.Unlock()
}

// coolHandle keeps sends away from a handle its provider throttled, keeping the later expiry, which it returns.
func (s *Server) coolHandle(handle string, until, now time.Time) time.Time {
	s.coolMu.Lock()
	defer s.coolMu.Unlock()
	if len(s.cool) > 10_000 {
		for h, t := range s.cool {
			if !t.After(now) {
				delete(s.cool, h)
			}
		}
	}
	if cur := s.cool[handle]; cur.After(until) {
		until = cur
	}
	s.cool[handle] = until
	return until
}

// cooledFor is how long a throttled handle still waits.
func (s *Server) cooledFor(handle string, now time.Time) time.Duration {
	s.coolMu.Lock()
	defer s.coolMu.Unlock()
	until, ok := s.cool[handle]
	if ok && !until.After(now) {
		delete(s.cool, handle)
	}
	return until.Sub(now)
}

// clientIP is the caller's address: behind Caddy the last X-Forwarded-For entry across every header line, which is
// the one Caddy wrote. Entries a client sent itself come before it.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if values := r.Header.Values("X-Forwarded-For"); len(values) > 0 {
			parts := strings.Split(strings.Join(values, ","), ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ── Identifiers and secrets ─────────────────────────────────────────────────────────────────────

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newInstanceID() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789" // no l, o, 0, 1
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "inst_" + string(b)
}

func hash(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// EmailHash is how a banned email is remembered: never the address itself.
func EmailHash(email string) []byte { return hash("email:" + strings.ToLower(email)) }

// ── JSON helpers ────────────────────────────────────────────────────────────────────────────────

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	var e apiError
	e.Error.Code, e.Error.Message = code, msg
	writeJSON(w, status, e)
}

func rateLimited(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", retryAfter(wait))
	writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests. Try again later.")
}

func retryAfter(d time.Duration) string {
	secs := int((d + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}

// decode reads a JSON body of at most MaxBody bytes.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "The request body is too large.")
		} else {
			writeError(w, http.StatusBadRequest, "bad_request", "The request body is not valid JSON.")
		}
		return false
	}
	return true
}

// ── Instance authentication ─────────────────────────────────────────────────────────────────────

type instanceHandler func(w http.ResponseWriter, r *http.Request, inst store.Instance)

// withInstance authenticates "Authorization: Bearer <push id>.<push secret>". Banned servers are refused outright;
// suspended ones reach the handler, which decides.
func (s *Server) withInstance(next instanceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		id, secret, found := strings.Cut(token, ".")
		if !ok || !found || id == "" || secret == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Send Authorization: Bearer <push id>.<push secret>.")
			return
		}
		inst, err := s.store.Instance(r.Context(), id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.Error("instance lookup failed", "component", "relay", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
			return
		}
		// Compare even for an unknown ID so the answer takes the same time.
		stored := inst.SecretHash
		if stored == nil {
			stored = make([]byte, sha256.Size)
		}
		if subtle.ConstantTimeCompare(hash(secret), stored) != 1 || errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Unknown push ID or wrong push secret.")
			return
		}
		if inst.Status == store.StatusBanned {
			writeError(w, http.StatusForbidden, "banned", "This server is banned from the push relay.")
			return
		}
		next(w, r, inst)
	}
}

// Tier is a server's limits and the name of where they come from.
type Tier struct {
	Name              string `json:"tier"`
	PerMinute, PerDay int
}

// TierFor is the limits that apply to a server: an admin override, a verified domain, or the email tier.
func TierFor(inst store.Instance) Tier {
	t := Tier{Name: "email", PerMinute: EmailTierPerMinute, PerDay: EmailTierPerDay}
	if inst.DomainVerifiedAt != 0 {
		t = Tier{Name: "verified", PerMinute: VerifiedTierPerMinute, PerDay: VerifiedTierPerDay}
	}
	if inst.QuotaPerMinute > 0 || inst.QuotaPerDay > 0 {
		t.Name = "custom"
		if inst.QuotaPerMinute > 0 {
			t.PerMinute = inst.QuotaPerMinute
		}
		if inst.QuotaPerDay > 0 {
			t.PerDay = inst.QuotaPerDay
		}
	}
	return t
}

// notifyAdmin mails the admin address, when one is set. Failures are logged, never returned.
func (s *Server) notifyAdmin(ctx context.Context, subject, text string) {
	if s.cfg.AdminEmail == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := s.mail.Send(ctx, mail.Message{To: s.cfg.AdminEmail, Subject: subject, Text: text}); err != nil {
		s.log.Warn("admin notice not sent", "component", "relay", "subject", subject, "err", err)
	}
}

// ── Harvesting detection ────────────────────────────────────────────────────────────────────────

// harvestCounter counts, per server and hour, the live handles it addressed and how many belong to another server:
// a server trying handles it harvested elsewhere. Missing and revoked handles prove nothing either way.
type harvestCounter struct {
	mu sync.Mutex
	m  map[string]*harvestSlot
}

type harvestSlot struct {
	start         time.Time
	live, foreign int
	suspended     bool
}

// add counts one live handle and reports whether the server just crossed the line.
func (h *harvestCounter) add(id string, foreign bool, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.m[id]
	if s == nil || now.Sub(s.start) >= time.Hour {
		s = &harvestSlot{start: now}
		h.m[id] = s
	}
	s.live++
	if foreign {
		s.foreign++
	}
	if !s.suspended && (s.foreign >= harvestForeignMax || (s.live >= harvestMinSends && s.foreign*100 > s.live*harvestBadPercent)) {
		s.suspended = true
		return true
	}
	return false
}
