// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package relay

import (
	"context"
	"time"
)

// MaintenanceEvery is how often retention cleanup and due domain checks run.
const MaintenanceEvery = time.Hour

// RunMaintenance cleans up expired data and re-checks domains once now and then every hour, until ctx ends.
func (s *Server) RunMaintenance(ctx context.Context) {
	t := time.NewTicker(MaintenanceEvery)
	defer t.Stop()
	for {
		s.Maintain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Maintain runs one round: retention cleanup, then the domain checks that are due.
func (s *Server) Maintain(ctx context.Context) {
	now := s.now()
	if err := s.store.Cleanup(ctx, now); err != nil {
		s.log.Error("cleanup failed", "component", "maintenance", "err", err)
	}
	due, err := s.store.DueForDomainCheck(ctx, now.Add(-DomainRecheck))
	if err != nil {
		s.log.Error("domain check list failed", "component", "maintenance", "err", err)
		return
	}
	for _, inst := range due {
		if ctx.Err() != nil {
			return
		}
		s.checkDomainOnce(ctx, inst)
	}
}
