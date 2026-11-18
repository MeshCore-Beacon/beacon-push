// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/MeshCore-Beacon/beacon-push/internal/relay"
	"github.com/MeshCore-Beacon/beacon-push/internal/store"
)

const adminUsage = `usage: beacon-push admin <command>

  list                                   every registered server
  show <push id>                         one server, its devices and its last 14 days
  suspend <push id>                      stop it sending until unsuspended
  unsuspend <push id>                    let it send again
  ban <push id>                          stop it for good and refuse its email
  set-quota <push id> <per min> <per day>   override its limits; 0 0 restores its tier
  backup <file>                          write a consistent copy of the database to a new file

The database is PUSH_DATABASE_PATH (default /data/beacon-push.db).`

func admin(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(out, adminUsage)
		return nil
	}
	path := os.Getenv("PUSH_DATABASE_PATH")
	if path == "" {
		path = "/data/beacon-push.db"
	}
	ctx := context.Background()
	st, err := store.Open(ctx, path)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()
	return runAdmin(ctx, st, args, out, time.Now())
}

func runAdmin(ctx context.Context, st *store.Store, args []string, out io.Writer, now time.Time) error {
	need := func(n int) error {
		if len(args) != n+1 {
			return errors.New(adminUsage)
		}
		return nil
	}
	switch args[0] {
	case "list":
		list, err := st.Instances(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "PUSH ID\tSTATUS\tTIER\tNAME\tEMAIL\tURL\tCREATED")
		for _, i := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", i.ID, i.Status, relay.TierFor(i).Name, i.Name, i.Email, dash(i.URL),
				time.UnixMilli(i.CreatedAt).UTC().Format("2006-01-02"))
		}
		return tw.Flush()
	case "show":
		if err := need(1); err != nil {
			return err
		}
		i, err := lookup(ctx, st, args[1])
		if err != nil {
			return err
		}
		devices, err := st.CountHandles(ctx, i.ID)
		if err != nil {
			return err
		}
		usage, err := st.UsageFor(ctx, i.ID, 14)
		if err != nil {
			return err
		}
		t := relay.TierFor(i)
		fmt.Fprintf(out, "Push ID:   %s\nName:      %s\nEmail:     %s\nURL:       %s\nStatus:    %s\nTier:      %s (%d/min, %d/day)\n",
			i.ID, i.Name, i.Email, dash(i.URL), i.Status, t.Name, t.PerMinute, t.PerDay)
		fmt.Fprintf(out, "Domain:    %s\nDevices:   %d\nCreated:   %s from %s\nTerms:     version %d\n",
			domainState(i), devices, stamp(i.CreatedAt), dash(i.CreatedIP), i.TermsVersion)
		if len(usage) > 0 {
			fmt.Fprintln(out, "\nDAY         SENT  RATE LIMITED  INVALID HANDLES")
			for _, u := range usage {
				fmt.Fprintf(out, "%s  %5d  %12d  %15d\n", u.Day, u.Sent, u.RateLimited, u.InvalidHandles)
			}
		}
		return nil
	case "suspend", "unsuspend", "ban":
		if err := need(1); err != nil {
			return err
		}
		i, err := lookup(ctx, st, args[1])
		if err != nil {
			return err
		}
		status := map[string]string{"suspend": store.StatusSuspended, "unsuspend": store.StatusActive, "ban": store.StatusBanned}[args[0]]
		if i.Status == store.StatusBanned && status != store.StatusBanned {
			return fmt.Errorf("%s is banned; bans are not lifted from here", i.ID)
		}
		var eh []byte
		if status == store.StatusBanned {
			eh = relay.EmailHash(i.Email)
		}
		if err := st.SetStatus(ctx, i.ID, status, eh, now); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s is now %s\n", i.ID, status)
		return nil
	case "backup":
		if err := need(1); err != nil {
			return err
		}
		if err := st.Backup(ctx, args[1]); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		fmt.Fprintf(out, "wrote %s\n", args[1])
		return nil
	case "set-quota":
		if err := need(3); err != nil {
			return err
		}
		perMin, err1 := strconv.Atoi(args[2])
		perDay, err2 := strconv.Atoi(args[3])
		if err1 != nil || err2 != nil || perMin < 0 || perDay < 0 {
			return errors.New("set-quota takes two whole numbers, 0 or more")
		}
		if err := st.SetQuota(ctx, args[1], perMin, perDay); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("no server %s", args[1])
			}
			return err
		}
		i, err := lookup(ctx, st, args[1])
		if err != nil {
			return err
		}
		t := relay.TierFor(i)
		fmt.Fprintf(out, "%s: %s tier, %d/min, %d/day\n", i.ID, t.Name, t.PerMinute, t.PerDay)
		return nil
	}
	return fmt.Errorf("unknown admin command %q\n\n%s", args[0], adminUsage)
}

func lookup(ctx context.Context, st *store.Store, id string) (store.Instance, error) {
	i, err := st.Instance(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return i, fmt.Errorf("no server %s", id)
	}
	return i, err
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func stamp(ms int64) string {
	if ms == 0 {
		return "never"
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02 15:04 UTC")
}

func domainState(i store.Instance) string {
	switch {
	case i.URL == "":
		return "no URL"
	case i.DomainVerifiedAt != 0:
		return "verified since " + stamp(i.DomainVerifiedAt) + ", checked " + stamp(i.DomainCheckedAt)
	case i.DomainCheckedAt != 0:
		return "not verified, checked " + stamp(i.DomainCheckedAt)
	}
	return "not checked yet"
}
