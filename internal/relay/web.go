// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/MeshCore-Beacon/beacon-push/internal/disposable"
	mailer "github.com/MeshCore-Beacon/beacon-push/internal/mail"
	"github.com/MeshCore-Beacon/beacon-push/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

var pages = template.Must(template.ParseFS(templateFS, "templates/*.html"))

func staticFiles() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}

// pageData is what every page template gets.
type pageData struct {
	Error  string
	Form   registerForm
	Result *registered
	Email  string
}

type registerForm struct {
	Name, Email, URL string
}

type registered struct {
	PushID, Secret, Name, URL, Server string
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name+".html", data); err != nil {
		s.log.Error("page not rendered", "component", "web", "page", name, "err", err)
	}
}

func (s *Server) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { s.render(w, http.StatusOK, name, pageData{}) }
}

func (s *Server) registerForm(w http.ResponseWriter, _ *http.Request) {
	s.render(w, http.StatusOK, "register", pageData{})
}

// cleanName is the display name shown on notifications: 1 to 40 printable characters, spaces collapsed. Format
// characters (bidi overrides, zero-width joiners and the like) are refused, so one name cannot be made to look like
// another.
func cleanName(raw string) (string, bool) {
	name := strings.Join(strings.FieldsFunc(raw, unicode.IsSpace), " ")
	if name == "" || utf8.RuneCountInString(name) > 40 {
		return "", false
	}
	for _, r := range name {
		if !unicode.IsPrint(r) || r == '<' || r == '>' {
			return "", false
		}
	}
	return name, true
}

// cleanEmail accepts one bare address and returns it lower-cased.
func cleanEmail(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	a, err := mail.ParseAddress(raw)
	if err != nil || a.Address != raw || len(raw) > 254 || !strings.Contains(raw, "@") {
		return "", false
	}
	return strings.ToLower(raw), true
}

// cleanURL accepts an https base URL (http in dev mode) with no credentials, query or fragment, without a trailing
// slash. Empty is allowed: the URL is optional.
func (s *Server) cleanURL(raw string) (string, bool) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return "", true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(raw) > 200 {
		return "", false
	}
	if u.Scheme != "https" && !(s.cfg.DevMode && u.Scheme == "http") {
		return "", false
	}
	return u.String(), true
}

type linkPayload struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	IP   string `json:"ip"`
}

const purposeRegister = "register"

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		s.render(w, http.StatusBadRequest, "register", pageData{Error: "The form could not be read."})
		return
	}
	form := registerForm{Name: r.PostForm.Get("name"), Email: r.PostForm.Get("email"), URL: r.PostForm.Get("url")}
	fail := func(msg string) { s.render(w, http.StatusBadRequest, "register", pageData{Error: msg, Form: form}) }

	// Bots fill the hidden field; tell them it worked and do nothing.
	if r.PostForm.Get("website") != "" {
		s.render(w, http.StatusOK, "sent", pageData{Email: form.Email})
		return
	}
	name, ok := cleanName(form.Name)
	if !ok {
		fail("Give the server a name of 1 to 40 characters, without < or >.")
		return
	}
	email, ok := cleanEmail(form.Email)
	if !ok {
		fail("Enter one email address, like you@example.org.")
		return
	}
	if disposable.Blocked(email[strings.LastIndexByte(email, '@')+1:]) {
		fail("Use a permanent email address. We need to be able to reach you about this server.")
		return
	}
	serverURL, ok := s.cleanURL(form.URL)
	if !ok {
		fail("The public URL must be an https address like https://beacon.example.org, or left empty.")
		return
	}
	if r.PostForm.Get("terms") != "on" {
		fail("You need to accept the terms to register.")
		return
	}
	// Only complete forms count against the address, so a typo does not lock anyone out.
	now := s.now()
	ip := s.clientIP(r)
	if ok, _ := s.hour.Allow("register:"+ip, RegisterPerHourPerIP, now); !ok {
		s.render(w, http.StatusTooManyRequests, "register", pageData{Error: "Too many registrations from your address. Try again in an hour.", Form: form})
		return
	}

	// From here on the page always says the same thing, so it cannot tell anyone which addresses hold servers.
	sent := func() { s.render(w, http.StatusOK, "sent", pageData{Email: email}) }
	if ok, _ := s.hour.Allow("link:"+email, LinkMailsPerHour, now); !ok {
		sent()
		return
	}
	ctx := r.Context()
	banned, err := s.store.EmailBanned(ctx, EmailHash(email))
	if err != nil {
		s.log.Error("ban check failed", "component", "web", "err", err)
		s.render(w, http.StatusInternalServerError, "register", pageData{Error: "Something went wrong. Try again later.", Form: form})
		return
	}
	if banned {
		sent()
		return
	}
	n, err := s.store.CountInstancesByEmail(ctx, email)
	if err != nil {
		s.log.Error("server count failed", "component", "web", "err", err)
		s.render(w, http.StatusInternalServerError, "register", pageData{Error: "Something went wrong. Try again later.", Form: form})
		return
	}
	if n >= MaxServersPerEmail {
		s.sendMail(ctx, email, "Your Beacon push registration",
			"Someone asked to register the Beacon server \""+name+"\" for push notifications with this address.\n\n"+
				"This address already has the most servers allowed (2), so nothing was registered.\n"+
				"If you need more, write to abuse@meshcorebeacon.ca.\n")
		sent()
		return
	}
	token := randomString(32)
	payload, _ := json.Marshal(linkPayload{Name: name, URL: serverURL, IP: ip})
	if err := s.store.CreateEmailToken(ctx, hash(token), purposeRegister, email, string(payload), now.Add(LinkLifetime)); err != nil {
		s.log.Error("link not stored", "component", "web", "err", err)
		s.render(w, http.StatusInternalServerError, "register", pageData{Error: "Something went wrong. Try again later.", Form: form})
		return
	}
	link := s.cfg.PublicURL.String() + "/verify#token=" + token
	s.sendMail(ctx, email, "Confirm your Beacon push server",
		"Someone, hopefully you, asked to register the Beacon server \""+name+"\" for push notifications.\n\n"+
			"Open this link within 24 hours to get its Push ID and Push secret:\n\n"+link+"\n\n"+
			"If this wasn't you, ignore this email and nothing happens.\n")
	sent()
}

func (s *Server) sendMail(ctx context.Context, to, subject, text string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.mail.Send(ctx, mailer.Message{To: to, Subject: subject, Text: text}); err != nil {
		domain := to[strings.LastIndexByte(to, '@')+1:]
		s.log.Warn("mail not sent", "component", "web", "subject", subject, "recipient_domain", domain, "err", err)
	}
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		s.render(w, http.StatusBadRequest, "verify", pageData{Error: "The form could not be read."})
		return
	}
	now := s.now()
	if ok, _ := s.hour.Allow("verify:"+s.clientIP(r), VerifyPerHourPerIP, now); !ok {
		s.render(w, http.StatusTooManyRequests, "verify", pageData{Error: "Too many attempts from your address. Try again in an hour."})
		return
	}
	token := strings.TrimSpace(r.PostForm.Get("token"))
	if token == "" {
		token = strings.TrimSpace(strings.TrimPrefix(r.PostForm.Get("token_manual"), "token="))
	}
	ctx := r.Context()
	email, raw, err := s.store.ConsumeEmailToken(ctx, hash(token), purposeRegister, now)
	if errors.Is(err, store.ErrNotFound) {
		s.render(w, http.StatusBadRequest, "verify", pageData{Error: "This link has expired or was already used. Register again to get a new one."})
		return
	}
	if err != nil {
		s.log.Error("link not consumed", "component", "web", "err", err)
		s.render(w, http.StatusInternalServerError, "verify", pageData{Error: "Something went wrong. Try again later."})
		return
	}
	var p linkPayload
	_ = json.Unmarshal([]byte(raw), &p)
	if banned, err := s.store.EmailBanned(ctx, EmailHash(email)); err != nil || banned {
		s.render(w, http.StatusForbidden, "verify", pageData{Error: "This server cannot be registered."})
		return
	}
	secret := randomString(32)
	inst := store.Instance{Name: p.Name, Email: email, URL: p.URL, SecretHash: hash(secret), TermsVersion: TermsVersion,
		TermsAcceptedAt: store.Ms(now), CreatedAt: store.Ms(now), CreatedIP: p.IP}
	for attempt := 0; ; attempt++ {
		inst.ID = newInstanceID()
		err = s.store.CreateInstance(ctx, inst, MaxServersPerEmail)
		if err == nil || errors.Is(err, store.ErrLimit) || attempt == 3 {
			break
		}
	}
	if errors.Is(err, store.ErrLimit) {
		s.render(w, http.StatusConflict, "verify", pageData{Error: "This email address already has the most servers allowed (2)."})
		return
	}
	if err != nil {
		s.log.Error("server not created", "component", "web", "err", err)
		s.render(w, http.StatusInternalServerError, "verify", pageData{Error: "Something went wrong. Register again to get a new link."})
		return
	}
	s.log.Info("server registered", "component", "web", "push_id", inst.ID, "has_url", inst.URL != "")
	go s.notifyAdmin(ctx, "New push server: "+inst.Name,
		"Push ID: "+inst.ID+"\nName: "+inst.Name+"\nEmail: "+inst.Email+"\nURL: "+orNone(inst.URL)+"\nIP: "+inst.CreatedIP+"\n")
	s.render(w, http.StatusOK, "verified", pageData{Result: &registered{PushID: inst.ID, Secret: secret, Name: inst.Name, URL: inst.URL,
		Server: s.cfg.PublicURL.String()}})
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
