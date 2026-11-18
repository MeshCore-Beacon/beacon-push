// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command beacon-push is the MeshCore Beacon push relay.
//
//	beacon-push                 serve
//	beacon-push admin ...       manage registered servers (see beacon-push admin help)
//	beacon-push healthcheck     exit 0 when the local relay answers /healthz
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MeshCore-Beacon/beacon-push/internal/apns"
	"github.com/MeshCore-Beacon/beacon-push/internal/config"
	"github.com/MeshCore-Beacon/beacon-push/internal/fcm"
	"github.com/MeshCore-Beacon/beacon-push/internal/mail"
	"github.com/MeshCore-Beacon/beacon-push/internal/push"
	"github.com/MeshCore-Beacon/beacon-push/internal/relay"
	"github.com/MeshCore-Beacon/beacon-push/internal/store"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	args := os.Args[1:]
	var err error
	switch {
	case len(args) == 0:
		err = serve()
	case args[0] == "admin":
		err = admin(args[1:], os.Stdout)
	case args[0] == "healthcheck":
		err = healthcheck()
	case args[0] == "version":
		fmt.Println(version)
	default:
		err = fmt.Errorf("unknown command %q: run with no arguments to serve, or use admin, healthcheck or version", args[0])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "beacon-push:", err)
		os.Exit(1)
	}
}

func serve() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	var sender push.Sender = push.Log{}
	var mailer mail.Sender = mail.Log{}
	if cfg.DevMode {
		slog.Warn("dev mode: mail and pushes are logged, not sent, and the domain check may reach private addresses", "component", "startup")
	} else {
		f, err := fcm.Load(cfg.FirebaseCredentials)
		if err != nil {
			return err
		}
		a, err := apns.Load(cfg.APNsKey, cfg.APNsKeyID, cfg.APNsTeamID, cfg.APNsTopic)
		if err != nil {
			return err
		}
		sender = push.Router{IOS: a, Android: f}
		mailer = mail.NewSMTP(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, cfg.SMTPStartTLS)
	}

	srv := relay.New(relay.Options{Config: cfg, Store: st, Push: sender, Mail: mailer})
	go srv.RunMaintenance(ctx)

	hs := &http.Server{Addr: cfg.ListenAddr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	slog.Info("beacon-push listening", "component", "startup", "version", version, "addr", cfg.ListenAddr,
		"public_url", cfg.PublicURL.String(), "admin_notices", cfg.AdminEmail != "")

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return hs.Shutdown(shutdown)
}

func healthcheck() error {
	addr := os.Getenv("PUSH_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("PUSH_LISTEN_ADDR %q: %w", addr, err)
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz answered %d", resp.StatusCode)
	}
	return nil
}
