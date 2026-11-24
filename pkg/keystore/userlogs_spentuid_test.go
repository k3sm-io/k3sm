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
	"time"
)

// reopenStore is a fresh FileStore over s's directories, data root and
// caps, with the file-backed logs and the test flag source: what a server
// restart makes. Its user scope is not started.
func reopenStore(t *testing.T, s *FileStore) *FileStore {
	t.Helper()
	s2 := New(Config{
		Dir: s.dir, MasterDir: s.masterDir, DataRoot: s.dataRoot,
		UID: s.uid, GID: s.gid, FloorUID: s.floorUID, FloorGID: s.floorGID,
		LogUIDShare: s.logUIDShare,
	})
	// The caps as s holds them, a test's lowered ones included, set the
	// way that test set them: on the store, beside the hard cap its Config
	// named, which the effective share is judged against.
	s2.logSoftCap, s2.logHardCap, s2.logRevokeBudget = s.logSoftCap, s.logHardCap, s.logRevokeBudget
	s2.configHardCap = s.configHardCap
	s2.logAllowance = s.logAllowance
	s2.logFlags = flagged
	return s2
}

// A uid that spent its revocation budget to under one line is that uid's
// problem alone: a restart starts the user scope, another uid's rm and
// withdraw succeed, and the spent uid's next revocation is refused.
func TestSpentRevocationBudgetIsPerUID(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	b := userScope(t, s, 1002)
	userPut(t, b, "user/1002/token", "b's value")
	d := testDelivery(1)
	d.entry, d.requestedBy = "user/1002/token", "k3sm:local:1002"
	if err := b.addDelivery(ctx, d); err != nil {
		t.Fatal(err)
	}
	size := int64(len(readLog(t, s, auditLogName)))
	s.logSoftCap, s.logHardCap, s.logRevokeBudget = size, size, 4*maxLogLine
	line, err := marshalAuditLine(auditLine{op: "rm", scope: "user/1001", name: "token", result: "ok"}, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	// uid 1001's lines past the hard cap leave it under one line of budget.
	k := int(s.logRevokeBudget)/len(line) - 1
	if int64(k*len(line)+maxAppendLine) <= s.logRevokeBudget {
		k++
	}
	appendLogBytes(t, s, auditLogName, bytes.Repeat(line, k))

	s2 := reopenStore(t, s)
	damage, spent, err := s2.CheckLogBounds(ctx)
	if err != nil || damage != 0 || spent != 1 {
		t.Fatalf("CheckLogBounds with one uid's budget spent = %d, %d, %v; want 0, 1, nil", damage, spent, err)
	}
	if err := s2.startUserScopes(ctx); err != nil || !s2.userScopesStarted.Load() {
		t.Fatalf("restart with one uid's budget spent: %v", err)
	}
	b2, err := s2.UserScope(1002)
	if err != nil {
		t.Fatal(err)
	}
	if err := b2.Withdraw(ctx, d.uid); err != nil {
		t.Fatalf("another uid's withdraw: %v", err)
	}
	if err := b2.Delete(ctx, "user/1002/token"); err != nil {
		t.Fatalf("another uid's rm: %v", err)
	}
	a2, err := s2.UserScope(1001)
	if err != nil {
		t.Fatal(err)
	}
	if err := a2.Delete(ctx, "user/1001/token"); !errors.Is(err, ErrLogFull) {
		t.Fatalf("the spent uid's rm: %v, want ErrLogFull", err)
	}
}
