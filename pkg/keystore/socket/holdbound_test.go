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
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// U89 and U108 end to end: uid A's scope holds tens of thousands of files
// (an entry padded as many versions would leave it) and A rotates in a
// loop at its mutation rate limit, while uid B removes its entries; each
// of B's rm answers ok within a lock wait far below the 2 s default.
// Before the usage figure, each of A's rotations walked A's whole scope
// under the exclusive lock, longer than that wait, and B's rm answered
// busy.
func TestLockHoldBoundPerUID(t *testing.T) {
	const (
		padFiles = 60000
		lockWait = 100 * time.Millisecond
		removals = 6
	)
	r := newStartedBridge(t, bridgeConfig(0, lockWait))
	for _, name := range []string{"token", "bulk"} {
		if _, err := r.b.Put(t.Context(), Peer{UID: uidA, PID: 1}, entryOf(uidA, name), keystore.KindOpaque, []byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	bulk := filepath.Join(r.data, "server", "keystore", ".user", strconv.FormatUint(uint64(uidA), 10), "entries", "bulk")
	for i := range padFiles {
		if err := os.WriteFile(filepath.Join(bulk, "pad-"+strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Connected once the scope is planted, which can outlast an idle
	// connection on a loaded host.
	a, b := r.connect(t, uidA), r.connect(t, uidB)
	for i := range removals {
		b.must(t, "put", entryOf(uidB, "e"+strconv.Itoa(i)), []byte("v"))
	}
	var (
		stop    atomic.Bool
		wg      sync.WaitGroup
		rotated atomic.Int64
		sent    = make(chan struct{}, 1)
	)
	rotate, err := json.Marshal(map[string]string{"op": "rotate", "entry": entryOf(uidA, "token")})
	if err != nil {
		t.Fatal(err)
	}
	wg.Go(func() {
		pace := time.Second / MutationsPerSecond
		for !stop.Load() {
			a.s.send(t, TypeRequest, string(rotate), []byte("next"))
			select {
			case sent <- struct{}{}:
			default:
			}
			if f, _ := a.s.recvFrame(t); f.Type == TypeReply {
				rotated.Add(1)
			}
			time.Sleep(pace)
		}
	})
	for i := range removals {
		// B's rm lands just behind one of A's rotations, so it waits for
		// that rotation's whole hold.
		select {
		case <-sent: // an earlier rotation's
		default:
		}
		<-sent
		time.Sleep(5 * time.Millisecond)
		began := time.Now()
		code, _ := b.do(t, "rm", entryOf(uidB, "e"+strconv.Itoa(i)), nil)
		if code != "" {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("uid B's rm %d while uid A rotates: code %q after %s, want ok within %s", i, code, time.Since(began), lockWait)
		}
	}
	stop.Store(true)
	wg.Wait()
	if rotated.Load() == 0 {
		t.Fatal("uid A's rotations never ran")
	}
}
