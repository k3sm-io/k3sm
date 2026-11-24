/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package socket

import (
	"sync"
	"time"
)

// uidRate admits at most n requests per uid in any window of length per,
// on the injected clock: a sliding window, so a burst at a window's edge
// cannot double the rate.
type uidRate struct {
	n   int
	per time.Duration
	now func() time.Time

	mu     sync.Mutex
	recent map[uint32][]time.Time // each uid's admitted requests inside the window, oldest first
}

// pruneAt is how many uids the limiter holds before it drops those with no
// request inside the window.
const pruneAt = 256

func newUIDRate(n int, per time.Duration, now func() time.Time) *uidRate {
	return &uidRate{n: n, per: per, now: now, recent: map[uint32][]time.Time{}}
}

// allow reports whether uid may make a request now, and counts it if so.
func (r *uidRate) allow(uid uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if len(r.recent) >= pruneAt {
		for u, ts := range r.recent {
			if len(r.live(ts, now)) == 0 {
				delete(r.recent, u)
			}
		}
	}
	ts := r.live(r.recent[uid], now)
	if len(ts) >= r.n {
		r.recent[uid] = ts
		return false
	}
	r.recent[uid] = append(ts, now)
	return true
}

// live is ts without the requests that left the window ending at now.
func (r *uidRate) live(ts []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(now.Add(-r.per)) {
		i++
	}
	return ts[i:]
}
