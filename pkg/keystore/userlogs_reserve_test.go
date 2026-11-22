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
	"os"
	"syscall"
	"testing"
)

// An append reserves its line's blocks on the log's descriptor before it
// writes, so a disk filler racing the free-space preflight cannot leave a
// torn floor or audit tail: a refused reservation is errLogNoSpace, and the
// log stays byte-identical.
func TestLogAppendReservesBlocks(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	fl, al := s.userFloor.(*fileFloorLog).log, s.auditSink.(*fileAuditLog).log
	var asked []int64
	refuse := func(_ *os.File, n int64) error { asked = append(asked, n); return syscall.ENOSPC }
	fl.reserve, al.reserve = refuse, refuse
	floor, audit := readLog(t, s, userFloorLogName), readLog(t, s, auditLogName)
	if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); !errors.Is(err, errLogNoSpace) {
		t.Fatalf("put with its reservation refused: %v, want errLogNoSpace", err)
	}
	if len(asked) == 0 {
		t.Fatal("no reservation was asked for")
	}
	for _, n := range asked {
		if n <= 0 || n%logBlock != 0 {
			t.Fatalf("reservation of %d bytes, want whole %d-byte blocks", n, logBlock)
		}
	}
	if !bytes.Equal(floor, readLog(t, s, userFloorLogName)) || !bytes.Equal(audit, readLog(t, s, auditLogName)) {
		t.Fatal("a line was written after its reservation was refused")
	}
	// A revocation is refused the same way, with nothing written.
	if err := u.Delete(ctx, "user/1001/token"); !errors.Is(err, errLogNoSpace) || errors.Is(err, errCommitted) {
		t.Fatalf("rm with its reservation refused: %v, want errLogNoSpace before any commit", err)
	}
	if !bytes.Equal(floor, readLog(t, s, userFloorLogName)) || !bytes.Equal(audit, readLog(t, s, auditLogName)) {
		t.Fatal("a tombstone was written after its reservation was refused")
	}
	// The real reservation succeeds on the test volume.
	fl.reserve, al.reserve = nil, nil
	if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("put with the real reservation: %v", err)
	}
}

func TestReserveLogBlocksRounds(t *testing.T) {
	for _, c := range []struct{ n, want int64 }{{1, logBlock}, {logBlock, logBlock}, {logBlock + 1, 2 * logBlock}, {maxLogLine, logBlock}} {
		if got := reserveSize(c.n); got != c.want {
			t.Errorf("reserveSize(%d) = %d, want %d", c.n, got, c.want)
		}
	}
}
