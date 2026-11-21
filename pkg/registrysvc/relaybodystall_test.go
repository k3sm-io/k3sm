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

package registrysvc

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestRelayStalledUploadBodyFreesItsSlot is the gate for an upload whose body
// stalls part way while the handler is reading it: the read times out, and the
// server's drain of the unread rest must time out too, so the connection
// closes and its per-source slot is freed. It runs in a synctest bubble over
// in-memory connections, so the window passes on the bubble's clock.
func TestRelayStalledUploadBodyFreesItsSlot(t *testing.T) {
	relayBubble(t, func(t *testing.T) {
		const peerA = "100.64.1.2"
		gotBytes := make(chan struct{}, 1)
		registry := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusOK)
				return
			}
			buf := make([]byte, 64)
			for {
				n, err := r.Body.Read(buf)
				if n > 0 {
					select {
					case gotBytes <- struct{}{}:
					default:
					}
				}
				if err != nil {
					break
				}
			}
			w.WriteHeader(http.StatusAccepted)
		})
		f := newRelayLimitFixtureWith(t, stallLimits(), registry)
		f.tokens.statuses[tokTeam] = saStatus("team", "builder")
		c := f.dial(t, peerA)
		// The part sent is larger than the proxy's write buffer, so some of it
		// reaches the registry before the stall. The rest is under the 256 KiB
		// net/http drains after a handler rather than closing outright, so the
		// connection is closed only if that drain is bounded.
		if _, err := fmt.Fprintf(c, "POST /v2/team/app/blobs/uploads/ HTTP/1.1\r\nHost: registry.test\r\nAuthorization: %s\r\nContent-Length: %d\r\n\r\n", basic(tokTeam), 64<<10+100); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(make([]byte, 64<<10)); err != nil {
			t.Fatal(err)
		}
		bound := time.NewTimer(stallWindow)
		select {
		case <-gotBytes:
			bound.Stop()
		case <-bound.C:
			t.Fatal("the registry never read the first bytes of the upload body: the test would not exercise a body read")
		}
		// Send no more of the body and never close; read whatever comes back.
		drainPeer(c)
		f.assertSlotHeld(t, peerA)
		f.awaitSlot(t, peerA, 3*stallWindow)
	})
}
