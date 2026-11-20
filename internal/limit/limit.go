// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package limit counts requests per key in fixed time windows, in memory. A restart forgets the counts, which is
// fine for short windows; daily quotas are counted in the database instead.
package limit

import (
	"sync"
	"time"
)

// Window allows at most a number of events per key in each window.
type Window struct {
	every time.Duration

	mu    sync.Mutex
	slots map[string]*slot
	sweep time.Time
}

type slot struct {
	start time.Time
	n     int
}

// New returns a limiter with windows of the given length.
func New(every time.Duration) *Window {
	return &Window{every: every, slots: map[string]*slot{}}
}

// Allow counts one event for key and reports whether it fits under max. When it does not, it also returns how long
// until the window resets. max <= 0 refuses everything.
func (w *Window) Allow(key string, max int, now time.Time) (bool, time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now.Sub(w.sweep) > w.every {
		for k, s := range w.slots {
			if now.Sub(s.start) >= w.every {
				delete(w.slots, k)
			}
		}
		w.sweep = now
	}
	s := w.slots[key]
	if s == nil || now.Sub(s.start) >= w.every {
		s = &slot{start: now}
		w.slots[key] = s
	}
	if s.n >= max {
		return false, s.start.Add(w.every).Sub(now)
	}
	s.n++
	return true, 0
}

// Count returns how many events key has in its current window, without counting one.
func (w *Window) Count(key string, now time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.slots[key]
	if s == nil || now.Sub(s.start) >= w.every {
		return 0
	}
	return s.n
}
