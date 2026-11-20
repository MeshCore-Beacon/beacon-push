// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/MeshCore-Beacon/beacon-push/internal/store"
)

// The manage pages let an operator who lost a Push secret, or wants a slot back, act on their servers through an
// emailed link. The link opens a short session; each action uses it up and the list page hands out a fresh one.

const (
	purposeManage        = "manage"
	purposeManageSession = "manage-session"
)

// managedServer is one row on the manage list.
type managedServer struct {
	PushID, Name, URL, Status, Tier string
	// Usage, already formatted with thousands separators.
	Devices, SentToday, PerMinute, PerDay  string
	WeekSent, WeekRateLimited, WeekInvalid string
	// For the meter.
	TodayN, PerDayN int
	NearLimit       bool
}

// usageWindow is how many days, today included, the usage line on the manage list covers.
const usageWindow = 7

// managed builds a list row with the server's usage. Today's count is the one the daily quota checks.
func (s *Server) managed(ctx context.Context, i store.Instance) (managedServer, error) {
	now := s.now()
	devices, err := s.store.CountHandles(ctx, i.ID)
	if err != nil {
		return managedServer{}, err
	}
	today, err := s.store.SentToday(ctx, i.ID, now)
	if err != nil {
		return managedServer{}, err
	}
	days, err := s.store.UsageFor(ctx, i.ID, usageWindow)
	if err != nil {
		return managedServer{}, err
	}
	from := store.Day(now.AddDate(0, 0, 1-usageWindow))
	var sent, limited, invalid int
	for _, d := range days {
		if d.Day >= from {
			sent, limited, invalid = sent+d.Sent, limited+d.RateLimited, invalid+d.InvalidHandles
		}
	}
	t := TierFor(i)
	return managedServer{PushID: i.ID, Name: i.Name, URL: i.URL, Status: i.Status, Tier: t.Name,
		Devices: thousands(devices), SentToday: thousands(today), PerMinute: thousands(t.PerMinute), PerDay: thousands(t.PerDay),
		WeekSent: thousands(sent), WeekRateLimited: thousands(limited), WeekInvalid: thousands(invalid),
		TodayN: today, PerDayN: t.PerDay, NearLimit: today*5 >= t.PerDay*4}, nil
}

const somethingWrong = "Something went wrong. Try again later."

func (s *Server) manage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		s.render(w, http.StatusBadRequest, "manage", pageData{Error: "The form could not be read."})
		return
	}
	raw := r.PostForm.Get("email")
	if r.PostForm.Get("website") != "" {
		s.render(w, http.StatusOK, "manage-sent", pageData{Email: raw})
		return
	}
	email, ok := cleanEmail(raw)
	if !ok {
		s.render(w, http.StatusBadRequest, "manage", pageData{Error: "Enter one email address, like you@example.org.", Form: registerForm{Email: raw}})
		return
	}
	now := s.now()
	if ok, _ := s.hour.Allow("manage:"+s.clientIP(r), ManagePerHourPerIP, now); !ok {
		s.render(w, http.StatusTooManyRequests, "manage", pageData{Error: "Too many requests from your address. Try again in an hour.", Form: registerForm{Email: raw}})
		return
	}

	// From here on the page always says the same thing, so it cannot tell anyone which addresses hold servers.
	sent := func() { s.render(w, http.StatusOK, "manage-sent", pageData{Email: email}) }
	if ok, _ := s.hour.Allow("link:"+email, LinkMailsPerHour, now); !ok {
		sent()
		return
	}
	ctx := r.Context()
	list, err := s.manageable(ctx, email)
	if err != nil {
		s.log.Error("manage lookup failed", "component", "web", "err", err)
		s.render(w, http.StatusInternalServerError, "manage", pageData{Error: somethingWrong, Form: registerForm{Email: raw}})
		return
	}
	if len(list) == 0 {
		sent()
		return
	}
	token := randomString(32)
	if err := s.store.CreateEmailToken(ctx, hash(token), purposeManage, email, "{}", now.Add(ManageLinkLifetime)); err != nil {
		s.log.Error("link not stored", "component", "web", "err", err)
		s.render(w, http.StatusInternalServerError, "manage", pageData{Error: somethingWrong, Form: registerForm{Email: raw}})
		return
	}
	link := s.cfg.PublicURL.String() + "/manage/open#token=" + token
	s.sendMail(ctx, email, "Manage your Beacon push servers",
		"Someone, hopefully you, asked to manage the Beacon push servers registered with this address.\n\n"+
			"Open this link within an hour to get a new Push secret or remove a server:\n\n"+link+"\n\n"+
			"If this wasn't you, ignore this email and nothing changes.\n")
	sent()
}

// manageable lists the servers an email may act on: none while the email is banned, never a banned server.
func (s *Server) manageable(ctx context.Context, email string) ([]store.Instance, error) {
	banned, err := s.store.EmailBanned(ctx, EmailHash(email))
	if err != nil || banned {
		return nil, err
	}
	all, err := s.store.InstancesByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	var out []store.Instance
	for _, i := range all {
		if i.Status != store.StatusBanned {
			out = append(out, i)
		}
	}
	return out, nil
}

func (s *Server) manageOpen(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		s.render(w, http.StatusBadRequest, "manage-open", pageData{Error: "The form could not be read."})
		return
	}
	now := s.now()
	if ok, _ := s.hour.Allow("verify:"+s.clientIP(r), VerifyPerHourPerIP, now); !ok {
		s.render(w, http.StatusTooManyRequests, "manage-open", pageData{Error: "Too many attempts from your address. Try again in an hour."})
		return
	}
	token := strings.TrimSpace(r.PostForm.Get("token"))
	if token == "" {
		token = strings.TrimSpace(strings.TrimPrefix(r.PostForm.Get("token_manual"), "token="))
	}
	email, _, err := s.store.ConsumeEmailToken(r.Context(), hash(token), purposeManage, now)
	if errors.Is(err, store.ErrNotFound) {
		s.render(w, http.StatusBadRequest, "manage-open", pageData{Error: "This link has expired or was already used. Ask for a new one."})
		return
	}
	if err != nil {
		s.log.Error("link not consumed", "component", "web", "err", err)
		s.render(w, http.StatusInternalServerError, "manage-open", pageData{Error: somethingWrong})
		return
	}
	s.renderList(w, r, email, "")
}

// renderList shows the email's servers with a fresh session for the next action.
func (s *Server) renderList(w http.ResponseWriter, r *http.Request, email, notice string) {
	ctx := r.Context()
	list, err := s.manageable(ctx, email)
	if err != nil {
		s.log.Error("manage lookup failed", "component", "web", "err", err)
		s.render(w, http.StatusInternalServerError, "manage-list", pageData{Error: somethingWrong})
		return
	}
	data := pageData{Notice: notice, Email: email}
	if len(list) > 0 {
		session := randomString(32)
		if err := s.store.CreateEmailToken(ctx, hash(session), purposeManageSession, email, "{}", s.now().Add(ManageSessionLifetime)); err != nil {
			s.log.Error("session not stored", "component", "web", "err", err)
			s.render(w, http.StatusInternalServerError, "manage-list", pageData{Error: somethingWrong})
			return
		}
		data.Session = session
	}
	for _, i := range list {
		row, err := s.managed(ctx, i)
		if err != nil {
			s.log.Error("usage lookup failed", "component", "web", "push_id", i.ID, "err", err)
			s.render(w, http.StatusInternalServerError, "manage-list", pageData{Error: somethingWrong})
			return
		}
		data.Servers = append(data.Servers, row)
	}
	s.render(w, http.StatusOK, "manage-list", data)
}

// manageTarget uses up the session in the form and returns the server it names, locked against sends. It renders
// the error itself and returns ok false when the session or server is not good.
func (s *Server) manageTarget(w http.ResponseWriter, r *http.Request) (inst store.Instance, unlock func(), ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		s.render(w, http.StatusBadRequest, "manage-list", pageData{Error: "The form could not be read."})
		return inst, nil, false
	}
	ctx := r.Context()
	email, _, err := s.store.ConsumeEmailToken(ctx, hash(r.PostForm.Get("session")), purposeManageSession, s.now())
	if errors.Is(err, store.ErrNotFound) {
		s.render(w, http.StatusBadRequest, "manage-list", pageData{Error: "This page has expired or was already used. Ask for a new link."})
		return inst, nil, false
	}
	if err != nil {
		s.log.Error("session not consumed", "component", "web", "err", err)
		s.render(w, http.StatusInternalServerError, "manage-list", pageData{Error: somethingWrong})
		return inst, nil, false
	}
	refuse := func() {
		s.render(w, http.StatusForbidden, "manage-list", pageData{Error: "This server cannot be managed from here."})
	}
	banned, err := s.store.EmailBanned(ctx, EmailHash(email))
	if err != nil || banned {
		refuse()
		return inst, nil, false
	}
	// Check the server before locking, so the lock map only ever holds real push IDs.
	inst, err = s.store.Instance(ctx, r.PostForm.Get("push_id"))
	if err != nil || inst.Email != email || inst.Status == store.StatusBanned {
		refuse()
		return inst, nil, false
	}
	unlock, err = s.lockInstance(ctx, inst.ID)
	if err != nil {
		s.render(w, http.StatusServiceUnavailable, "manage-list", pageData{Error: somethingWrong})
		return inst, nil, false
	}
	return inst, unlock, true
}

func (s *Server) manageSecret(w http.ResponseWriter, r *http.Request) {
	inst, unlock, ok := s.manageTarget(w, r)
	if !ok {
		return
	}
	defer unlock()
	ctx := r.Context()
	secret := randomString(32)
	if err := s.store.SetSecret(ctx, inst.ID, hash(secret)); err != nil {
		s.log.Error("secret not changed", "component", "web", "push_id", inst.ID, "err", err)
		s.render(w, http.StatusInternalServerError, "manage-list", pageData{Error: somethingWrong})
		return
	}
	s.log.Info("push secret changed", "component", "web", "push_id", inst.ID)
	s.sendMail(ctx, inst.Email, "Your Beacon Push secret was changed",
		"The Push secret for the Beacon server \""+inst.Name+"\" ("+inst.ID+") was changed from the manage page.\n"+
			"The old secret no longer works.\n\n"+
			"If this wasn't you, write to abuse@meshcorebeacon.ca.\n")
	go s.notifyAdmin(ctx, "Push secret changed: "+inst.Name, "Push ID: "+inst.ID+"\nEmail: "+inst.Email+"\n")
	s.render(w, http.StatusOK, "verified", pageData{Reset: true,
		Result: &registered{PushID: inst.ID, Secret: secret, Name: inst.Name, URL: inst.URL}})
}

func (s *Server) manageRemove(w http.ResponseWriter, r *http.Request) {
	inst, unlock, ok := s.manageTarget(w, r)
	if !ok {
		return
	}
	defer unlock()
	ctx := r.Context()
	if r.PostForm.Get("confirm") != "on" {
		s.renderList(w, r, inst.Email, "Tick the box to confirm removing "+inst.Name+".")
		return
	}
	if err := s.store.DeleteInstance(ctx, inst.ID); err != nil {
		s.log.Error("server not removed", "component", "web", "push_id", inst.ID, "err", err)
		s.render(w, http.StatusInternalServerError, "manage-list", pageData{Error: somethingWrong})
		return
	}
	s.log.Info("server removed", "component", "web", "push_id", inst.ID)
	s.sendMail(ctx, inst.Email, "Your Beacon push server was removed",
		"The Beacon server \""+inst.Name+"\" ("+inst.ID+") was removed from the push relay from the manage page.\n"+
			"Its devices no longer get notifications through it.\n\n"+
			"If this wasn't you, write to abuse@meshcorebeacon.ca.\n")
	go s.notifyAdmin(ctx, "Push server removed: "+inst.Name, "Push ID: "+inst.ID+"\nEmail: "+inst.Email+"\n")
	s.renderList(w, r, inst.Email, inst.Name+" was removed.")
}
