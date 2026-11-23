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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkPutRefusedFirst asserts a put of name was refused with want before
// it changed anything: not as after a commit, the keystore tree unchanged.
func checkPutRefusedFirst(t *testing.T, u *UserScope, server, name string, want error) {
	t.Helper()
	snap := treeSnapshot(t, server)
	_, err := u.Put(context.Background(), name, KindOpaque, []byte("v"))
	if !errors.Is(err, want) || errors.Is(err, errCommitted) {
		t.Fatalf("put %s: %v, want %v before any write", name, err, want)
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, server))
}

// A put whose floor line the floor's free-space margin would refuse is
// refused before its first write, not committed without its floor line.
func TestPutRefusedFirstBelowFloorMargin(t *testing.T) {
	s, server, u := fileLogScope(t)
	s.userFloor.(*fileFloorLog).log.freeSpace = func(int) (uint64, error) { return logFreeMargin, nil }
	checkPutRefusedFirst(t, u, server, "user/1001/other", errLogNoSpace)
}

// A put with the floor one key short of the room its lines need is refused
// before its first write.
func TestPutRefusedFirstAtKeyBound(t *testing.T) {
	s, server, u := fileLogScope(t)
	l := s.userFloor.(*fileFloorLog).log
	if err := s.userFloor.check(); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	l.maxKeys = l.state.keys + 1
	l.mu.Unlock()
	checkPutRefusedFirst(t, u, server, "user/1001/other", ErrLogFull)
}

// A put that mints its scope appends two floor lines. With the floor just
// below its hard cap the first would start below it and the second past
// it, where a grant's line is refused: the put is refused before its first
// write, the scope not minted.
func TestPutRefusedFirstAtCapStraddle(t *testing.T) {
	s, server, _ := fileLogScope(t)
	for i := range 20 {
		line, err := floorLine("user/1001", fmt.Sprintf("pad-%d", i), guid(0xA1), 1)
		if err != nil {
			t.Fatal(err)
		}
		appendLogBytes(t, s, userFloorLogName, line)
	}
	if err := os.Truncate(filepath.Join(s.dataRoot, logsDirName, auditDirName, auditLogName), 0); err != nil {
		t.Fatal(err)
	}
	size := int64(len(readLog(t, s, userFloorLogName)))
	s.logSoftCap, s.logHardCap = size+1, size+1
	u2 := userScope(t, s, 1002)
	checkPutRefusedFirst(t, u2, server, "user/1002/token", ErrLogFull)
}

// A deliver whose floor line the floor would refuse after its commit is
// refused before it seals anything: the delivery record is unchanged.
func TestDeliverRefusedFirstBelowFloorMargin(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	snap := treeSnapshot(t, server)
	s.userFloor.(*fileFloorLog).log.freeSpace = func(int) (uint64, error) { return logFreeMargin, nil }
	err := u.addDelivery(ctx, testDelivery(2))
	if !errors.Is(err, errLogNoSpace) || errors.Is(err, errCommitted) {
		t.Fatalf("deliver below the floor's free-space margin: %v, want errLogNoSpace before any write", err)
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, server))
}

// A put that mints its scope judges the room for both its floor lines once,
// before the mint's ok audit line, and never again after it: here the
// volume fills once the mint's floor line lands, which a second check
// would refuse after the ok line. The put commits, and the audit log holds
// its one ok line and no refusal.
func TestPutMintJudgesFloorRoomOnce(t *testing.T) {
	s, _, _ := fileLogScope(t)
	floorPath := filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName)
	before := int64(len(readLog(t, s, userFloorLogName)))
	s.userFloor.(*fileFloorLog).log.freeSpace = func(int) (uint64, error) {
		fi, err := os.Stat(floorPath)
		if err != nil || fi.Size() > before {
			return logFreeMargin, nil
		}
		return 1 << 30, nil
	}
	u2 := userScope(t, s, 1002)
	audit := len(readLog(t, s, auditLogName))
	if _, err := u2.Put(context.Background(), "user/1002/token", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("a minting put with room judged before its ok line: %v", err)
	}
	added := string(readLog(t, s, auditLogName)[audit:])
	if len(nonEmptyLines([]byte(added))) != 1 || !strings.Contains(added, "ok") {
		t.Fatalf("the put's audit lines %q, want its one ok line", added)
	}
}
