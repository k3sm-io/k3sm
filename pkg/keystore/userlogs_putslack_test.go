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
	"testing"
)

// A put admitted by its preflight commits, and a volume filler that takes
// the free space between the preflight and the post-commit append cannot
// cost it its floor line: that line, the integrity record of a committed
// change, is held only to the revocation slack.
func TestPutFloorLineSurvivesVolumeFiller(t *testing.T) {
	s, _, u := fileLogScope(t)
	l := s.userFloor.(*fileFloorLog).log
	calls := 0
	l.freeSpace = func(int) (uint64, error) {
		calls++
		if calls == 1 {
			return 64 << 20, nil // the preflight: room for everything
		}
		return revokeFreeSlack + maxLogLine, nil // filled since
	}
	if _, err := u.Put(context.Background(), "user/1001/other", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("put with the volume filled after its preflight: %v, want it committed with its floor line", err)
	}
	if calls < 2 {
		t.Fatalf("the free-space seam ran %d times, want the preflight and the append", calls)
	}
	if !bytes.Contains(readLog(t, s, userFloorLogName), []byte("user/1001 other ")) {
		t.Fatalf("the put's floor line did not land:\n%s", readLog(t, s, userFloorLogName))
	}
}

// The put's preflight reserves room for the value it writes, not only its
// floor lines: with the margin and the lines free but not the value, the
// put is refused before its first write.
func TestPutPreflightReservesValueRoom(t *testing.T) {
	s, server, u := fileLogScope(t)
	value := make([]byte, 64<<10)
	s.userFloor.(*fileFloorLog).log.freeSpace = func(int) (uint64, error) { return logFreeMargin + maxLogLine, nil }
	snap := treeSnapshot(t, server)
	_, err := u.Put(context.Background(), "user/1001/other", KindOpaque, value)
	if !errors.Is(err, errLogNoSpace) || errors.Is(err, errCommitted) {
		t.Fatalf("put with no room for its value: %v, want errLogNoSpace before any write", err)
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, server))
}
