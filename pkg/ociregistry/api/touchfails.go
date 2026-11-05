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

package api

import (
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
)

// maxTouchFails is the most objects whose HEAD touch is suppressed at once.
const maxTouchFails = 4096

// touchKey is an object in a repository.
type touchKey struct {
	repo   string
	digest digest.Digest
}

// touchFails remembers the objects whose HEAD touch failed, each until the
// end of its suppression window, so a degraded store is not asked again on
// every HEAD. It holds at most max entries; adding past that evicts the entry
// whose window ends first. mu guards until.
type touchFails struct {
	mu    sync.Mutex
	max   int
	until map[touchKey]time.Time
}

func newTouchFails(max int) *touchFails {
	return &touchFails{max: max, until: make(map[touchKey]time.Time)}
}

// suppressed reports whether k's window is still open at now, and forgets k
// once it has closed.
func (t *touchFails) suppressed(k touchKey, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	end, ok := t.until[k]
	if !ok {
		return false
	}
	if now.Before(end) {
		return true
	}
	delete(t.until, k)
	return false
}

// add opens k's window until end, evicting the entry whose window ends first
// when the map is full.
func (t *touchFails) add(k touchKey, end time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.until[k]; !ok && len(t.until) >= t.max {
		var oldest touchKey
		first := true
		for kk, e := range t.until {
			if first || e.Before(t.until[oldest]) {
				oldest, first = kk, false
			}
		}
		delete(t.until, oldest)
	}
	t.until[k] = end
}
