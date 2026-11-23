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

package keystore

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// A burial whose second tombstone fails after the first landed has revoked
// the entry: rm reports errCommitted, never "nothing removed", its audit
// line is a revocation, and a retry buries the rest and completes.
func TestRmPartialBurialIsCommitted(t *testing.T) {
	ctx := context.Background()
	s, _, u := newDeliveryScope(t)
	fl, _ := userLogs(s)
	fl.mu.Lock()
	for _, g := range []byte{0x31, 0x32} {
		fl.lines = append(fl.lines, memFloorLine{scope: "user/1001", name: "gone", gen: guid(g), seq: 1})
	}
	fl.buryLimit = fl.buried + 1
	fl.mu.Unlock()
	err := u.Delete(ctx, "user/1001/gone")
	if !errors.Is(err, errCommitted) || strings.Contains(err.Error(), "nothing removed") {
		t.Fatalf("rm whose second tombstone failed: %v, want errCommitted, never nothing removed", err)
	}
	if l := lastAudit(t, s); !l.revoke {
		t.Fatalf("rm committed part way: audit line %+v, want revoke", l)
	}
	fl.mu.Lock()
	fl.buryLimit = 0
	fl.mu.Unlock()
	if err := u.Delete(ctx, "user/1001/gone"); err != nil {
		t.Fatalf("rm retried after a partial burial: %v, want it to complete", err)
	}
	if l := lastAudit(t, s); !l.revoke {
		t.Fatalf("the retried rm: audit line %+v, want revoke", l)
	}
	if live, err := fl.liveGens("user/1001", "gone"); err != nil || len(live) != 0 {
		t.Fatalf("live generations after the retry: %d, %v, want none", len(live), err)
	}
	if err := u.Delete(ctx, "user/1001/gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rm after the burial completed: %v, want ErrNotFound", err)
	}
}

// A burial is reserved whole before its first tombstone: with key headroom
// for only one of two tombstones that each add a key, or free space for only
// one line beyond the revocation slack, or for the tombstones but not the
// audit line that follows them, it is refused with nothing written.
func TestRmBurialReservedBeforeFirstTombstone(t *testing.T) {
	gens := [][generationSize]byte{guid(0x41), guid(0x42)}
	for _, tc := range []struct {
		name  string
		setup func(l *appendLog)
		want  error
	}{
		{"key headroom", func(l *appendLog) { l.maxKeys, l.maxHeadroom = l.state.keys, 1 }, ErrLogFull},
		{"free space", func(l *appendLog) {
			line, err := tombLine("user/1001", "gone", gens[0])
			if err != nil {
				t.Fatal(err)
			}
			l.freeSpace = func(int) (uint64, error) { return revokeFreeSlack + uint64(len(line)), nil }
		}, errLogNoSpace},
		{"audit line space", func(l *appendLog) {
			var n uint64
			for _, g := range gens {
				line, err := tombLine("user/1001", "gone", g)
				if err != nil {
					t.Fatal(err)
				}
				n += uint64(len(line))
			}
			l.freeSpace = func(int) (uint64, error) { return revokeFreeSlack + n, nil }
		}, errLogNoSpace},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, u := fileLogScope(t)
			l := syncedFloor(t, s)
			l.mu.Lock()
			tc.setup(l)
			l.mu.Unlock()
			before := readLog(t, s, userFloorLogName)
			b := &userBurial{name: "gone"}
			for _, g := range gens {
				b.add("the generation file", g)
			}
			err := b.bury(u)
			if !errors.Is(err, tc.want) || errors.Is(err, errCommitted) {
				t.Fatalf("a burial without room for its whole: %v, want %v before any write", err, tc.want)
			}
			if after := readLog(t, s, userFloorLogName); !bytes.Equal(before, after) {
				t.Fatalf("the refused burial wrote %q", after[len(before):])
			}
		})
	}
}
