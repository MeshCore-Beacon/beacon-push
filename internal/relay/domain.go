// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/MeshCore-Beacon/beacon-push/internal/store"
)

// ChallengePath is where beacon-server answers the domain check.
const ChallengePath = "/.well-known/beacon-push"

// ChallengeMAC is the answer a server gives: hex HMAC-SHA256 keyed with SHA-256 of its push secret, over
// "beacon-push-challenge:<push id>:<challenge>". The relay only stores that hash, so it is the key both sides hold.
func ChallengeMAC(secretHash []byte, pushID, challenge string) string {
	m := hmac.New(sha256.New, secretHash)
	m.Write([]byte("beacon-push-challenge:" + pushID + ":" + challenge))
	return hex.EncodeToString(m.Sum(nil))
}

var errBlockedAddress = errors.New("address not allowed")

// blockedPrefixes are ranges the domain check must never reach, beyond what netip already classes as private,
// loopback or link-local: the relay runs next to other services.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use translation, RFC 8215
	netip.MustParsePrefix("2002::/16"),      // 6to4 can wrap a private IPv4
	netip.MustParsePrefix("2001::/32"),      // Teredo
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
	netip.MustParsePrefix("3fff::/20"),      // documentation, RFC 9637
	netip.MustParsePrefix("100::/64"),       // discard-only
}

func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// challengeClient reaches only public addresses over https, follows no redirects and gives up quickly. Dev mode
// lifts the address rule so a local beacon-server can be checked.
func challengeClient(dev bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if !dev {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !publicAddr(ap.Addr()) {
				return errBlockedAddress
			}
			return nil
		}
	}
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// checkDomainOnce runs a check unless one for the server is already under way.
func (s *Server) checkDomainOnce(ctx context.Context, inst store.Instance) {
	if _, busy := s.checking.LoadOrStore(inst.ID, struct{}{}); busy {
		return
	}
	defer s.checking.Delete(inst.ID)
	if err := s.checkDomain(ctx, inst); err != nil {
		s.log.Info("domain check failed", "component", "relay", "push_id", inst.ID, "reason", err.Error())
	}
}

// checkDomain asks the server's URL to prove it holds the push secret and records the outcome. The error is safe to
// show the operator.
func (s *Server) checkDomain(ctx context.Context, inst store.Instance) error {
	err := s.challengeURL(ctx, inst)
	passed := err == nil
	if rerr := s.store.SetDomainCheck(ctx, inst.ID, passed, s.now()); rerr != nil {
		s.log.Error("domain check not recorded", "component", "relay", "push_id", inst.ID, "err", rerr)
	}
	if !passed && inst.DomainVerifiedAt != 0 {
		s.log.Warn("domain check failed after passing before", "component", "relay", "push_id", inst.ID, "reason", err.Error())
		s.notifyAdmin(ctx, "Push server lost its domain verification: "+inst.ID,
			"Server "+inst.ID+" ("+inst.Name+", "+inst.Email+") at "+inst.URL+" no longer passes the domain check: "+err.Error()+
				".\nIt is back on the email tier until it passes again.\n")
	}
	return err
}

func (s *Server) challengeURL(ctx context.Context, inst store.Instance) error {
	base, err := url.Parse(inst.URL)
	if err != nil || (base.Scheme != "https" && !s.cfg.DevMode) {
		return errors.New("the registered URL is not https")
	}
	challenge := randomString(18)
	u := *base
	u.Path = base.Path + ChallengePath
	u.RawQuery = url.Values{"challenge": {challenge}}.Encode()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return errors.New("the registered URL cannot be requested")
	}
	req.Header.Set("User-Agent", "beacon-push/1 (domain check)")
	req.Header.Set("Accept", "application/json")
	resp, err := s.challenge.Do(req)
	if err != nil {
		if errors.Is(err, errBlockedAddress) {
			return errors.New("the registered URL does not resolve to a public address")
		}
		return errors.New("the server could not be reached")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", ChallengePath, resp.StatusCode)
	}
	var answer struct {
		PushID string `json:"pushId"`
		MAC    string `json:"mac"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&answer); err != nil {
		return fmt.Errorf("%s did not answer with JSON", ChallengePath)
	}
	got, _ := hex.DecodeString(answer.MAC)
	want, _ := hex.DecodeString(ChallengeMAC(inst.SecretHash, inst.ID, challenge))
	if answer.PushID != inst.ID || !hmac.Equal(got, want) {
		return errors.New("the answer does not match this push ID and secret")
	}
	return nil
}
