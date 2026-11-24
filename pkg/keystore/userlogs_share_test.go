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
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// testShare is the byte share the share tests configure: small enough to
// fill with a few dozen lines, over 1/16 of no cap they use.
const testShare = 8 << 10

// shareCounts is one reading of a log's per-uid charges.
type shareCounts struct{ share, margin, allowance map[uint32]int64 }

func (c shareCounts) equal(o shareCounts) bool {
	return maps.Equal(c.share, o.share) && maps.Equal(c.margin, o.margin) && maps.Equal(c.allowance, o.allowance)
}

// countsOf reads l through its own running state, as the next append would.
func countsOf(t *testing.T, l *appendLog) shareCounts {
	t.Helper()
	f, st, err := l.open(unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil {
		t.Fatal(err)
	}
	if state.bad != nil {
		t.Fatal(state.bad)
	}
	return shareCounts{maps.Clone(state.share), maps.Clone(state.pastCap), maps.Clone(state.allowance)}
}

func auditLogOf(s *FileStore) *appendLog { return s.auditSink.(*fileAuditLog).log }
func floorLogOf(s *FileStore) *appendLog { return s.userFloor.(*fileFloorLog).log }

// fillAudit appends audit lines of uid's, as a foreign writer would, until
// the reader charges uid's share in the audit log to under one append of
// room and, when margin, its socket margin too.
func fillAudit(t *testing.T, s *FileStore, uid uint32, via string, margin bool) {
	t.Helper()
	line, err := marshalAuditLine(auditLine{op: "rm", via: via, scope: userScopeOf(uid), name: "f", result: "ok"}, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	l := auditLogOf(s)
	for i := 0; ; i++ {
		c := countsOf(t, l)
		// Filled while no fill line fits: no line of the operations the
		// tests make, each longer, fits either.
		full := c.share[uid]+int64(len(line))+1 > s.uidShare()
		if margin {
			full = full && c.margin[uid]+maxAppendLine > s.logRevokeBudget
		}
		if full {
			return
		}
		if i > 10000 {
			t.Fatal("the audit share never filled")
		}
		appendLogBytes(t, s, auditLogName, append([]byte{'\n'}, line...))
	}
}

// fillFloorShare is fillAudit for the floor: lines of one key of uid's scope.
func fillFloorShare(t *testing.T, s *FileStore, uid uint32) {
	t.Helper()
	l := floorLogOf(s)
	for seq := uint64(1); ; seq++ {
		line, err := floorLine(userScopeOf(uid), "f", [generationSize]byte{}, seq)
		if err != nil {
			t.Fatal(err)
		}
		if c := countsOf(t, l); c.share[uid]+int64(len(line))+1 > s.uidShare() {
			return
		}
		if seq > 10000 {
			t.Fatal("the floor share never filled")
		}
		appendLogBytes(t, s, userFloorLogName, append([]byte{'\n'}, line...))
	}
}

func reconcilerLine(uid uint32) auditLine {
	return auditLine{op: "deliver-delete", via: auditViaReconciler, scope: userScopeOf(uid), name: "token", namespace: "apps", result: "ok", revoke: true}
}

// shareStore is fileLogScope with uid 1002's scope too and the test share.
func shareStore(t *testing.T) (*FileStore, *UserScope, *UserScope) {
	t.Helper()
	s, _, a := fileLogScope(t)
	b := userScope(t, s, 1002)
	userPut(t, b, "user/1002/token", "b's value")
	s.logUIDShare = testShare
	return s, a, b
}

// The share is a fixed byte count per uid per log: a uid past it has its
// grants refused with ErrLogFull, naming its own share, before any line is
// written, while another uid's succeed.
func TestShareLimitRefusesOnlyThatUID(t *testing.T) {
	ctx := context.Background()
	s, a, b := shareStore(t)
	fillAudit(t, s, 1001, "", false)
	auditBefore, floorBefore := readLog(t, s, auditLogName), readLog(t, s, userFloorLogName)
	_, err := a.Put(ctx, "user/1001/more", KindOpaque, []byte("v"))
	if !errors.Is(err, ErrLogFull) || !strings.Contains(err.Error(), "share") {
		t.Fatalf("a put past the caller's share = %v, want ErrLogFull naming its share", err)
	}
	if got := readLog(t, s, auditLogName); len(got) != len(auditBefore) {
		t.Fatalf("a refused put wrote %d audit bytes", len(got)-len(auditBefore))
	}
	if got := readLog(t, s, userFloorLogName); len(got) != len(floorBefore) {
		t.Fatalf("a refused put wrote %d floor bytes", len(got)-len(floorBefore))
	}
	userPut(t, b, "user/1002/more", "b's other value")
	if c := countsOf(t, auditLogOf(s)); c.share[1001] > s.uidShare() || c.share[1002] > s.uidShare() {
		t.Fatalf("a share charged past its limit: %v", c.share)
	}
}

// The floor's share is held the same way: a uid whose floor share is
// spent has its grants refused before their first write.
func TestShareLimitInTheFloor(t *testing.T) {
	ctx := context.Background()
	s, a, b := shareStore(t)
	fillFloorShare(t, s, 1001)
	if _, err := a.Put(ctx, "user/1001/more", KindOpaque, []byte("v")); !errors.Is(err, ErrLogFull) {
		t.Fatalf("a put past the caller's floor share = %v, want ErrLogFull", err)
	}
	userPut(t, b, "user/1002/more", "b's other value")
}

// The running count of every uid's share and budgets equals a fresh
// recount of the file after every step, and each append the writer judged
// is charged by the reader exactly as the writer planned it: one rule.
func TestShareRunningCountIsTheRecount(t *testing.T) {
	ctx := context.Background()
	s, a, b := shareStore(t)
	check := func(step string) {
		t.Helper()
		for _, l := range []struct {
			running *appendLog
			fresh   func() *appendLog
		}{
			{auditLogOf(s), func() *appendLog { return newFileAuditLog(s).log }},
			{floorLogOf(s), func() *appendLog { return newFileFloorLog(s).log }},
		} {
			if got, want := countsOf(t, l.running), countsOf(t, l.fresh()); !got.equal(want) {
				t.Fatalf("%s: %s running count %+v, recount %+v", step, l.running.name, got, want)
			}
		}
	}
	planned := func(step string, uid uint32, line auditLine, torn bool) {
		t.Helper()
		l := auditLogOf(s)
		b, err := marshalAuditLine(line, s.now())
		if err != nil {
			t.Fatal(err)
		}
		before := countsOf(t, l)
		f, st, err := l.open(unix.O_RDONLY)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		l.mu.Lock()
		margin, allowance, perr := l.planCharge(&l.state, st.Size, uid, [][]byte{b}, true)
		l.mu.Unlock()
		if perr != nil {
			t.Fatalf("%s: plan: %v", step, perr)
		}
		if err := l.appendLine(uid, b, true, true); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		after := countsOf(t, l)
		if dm, da := after.margin[uid]-before.margin[uid], after.allowance[uid]-before.allowance[uid]; dm != margin || da != allowance {
			t.Fatalf("%s: writer planned margin %d allowance %d, reader charged %d %d", step, margin, allowance, dm, da)
		}
		// The writer plans each append's leading newline; the reader charges
		// it unless it closed a foreign torn tail, so the plan is never under
		// the charge and at most that one byte over it.
		ds := after.share[uid] - before.share[uid]
		if got := ds + margin + allowance; got != int64(len(b))+1 && !(torn && got == int64(len(b))) {
			t.Fatalf("%s: %d bytes charged for a %d-byte append", step, got, len(b)+1)
		}
		check(step)
	}
	check("start")
	userPut(t, a, "user/1001/second", "v")
	check("put")
	userPut(t, b, "user/1002/second", "v")
	check("another uid's put")
	if err := a.Delete(ctx, "user/1001/second"); err != nil {
		t.Fatal(err)
	}
	check("rm")
	appendLogBytes(t, s, auditLogName, []byte("not json\n\n"))
	appendLogBytes(t, s, auditLogName, []byte(`{"v":1,"op":"put","scope":"user/1001","name":"x","namespace":"","result":"ok"}`+"\n"))
	check("foreign lines")
	planned("a reconciler line in the share", 1001, reconcilerLine(1001), false)
	appendLogBytes(t, s, auditLogName, []byte(`{"v":1,"op":"put","scope":"user/10`))
	planned("an append closing a torn tail", 1001, reconcilerLine(1001), true)
	fillAudit(t, s, 1001, "", false)
	check("share filled")
	planned("a socket revocation past the share", 1001, auditLine{op: "rm", scope: userScopeOf(1001), name: "token", result: "ok", revoke: true}, false)
	planned("a reconciler revocation past the share", 1001, reconcilerLine(1001), false)
	if err := a.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm past the share: %v", err)
	}
	check("rm past the share")
	s.logSoftCap, s.logHardCap = int64(len(readLog(t, s, auditLogName))), int64(len(readLog(t, s, auditLogName)))
	s.logUIDShare = 0
	planned("a revocation past the hard cap", 1002, auditLine{op: "rm", scope: userScopeOf(1002), name: "token", result: "ok", revoke: true}, false)
}

// U67: past its share a revocation bypasses the share and draws on the
// uid's socket margin, in both logs; the share stays at its limit.
func TestRevocationBypassesShareUsesReserve(t *testing.T) {
	ctx := context.Background()
	s, a, _ := shareStore(t)
	fillAudit(t, s, 1001, "", false)
	fillFloorShare(t, s, 1001)
	auditShare, floorShare := countsOf(t, auditLogOf(s)).share[1001], countsOf(t, floorLogOf(s)).share[1001]
	if err := a.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm past the share: %v", err)
	}
	for _, l := range []struct {
		log   *appendLog
		share int64
	}{{auditLogOf(s), auditShare}, {floorLogOf(s), floorShare}} {
		c := countsOf(t, l.log)
		if c.margin[1001] == 0 || c.share[1001] != l.share || c.allowance[1001] != 0 {
			t.Fatalf("%s after rm past the share: share %d (was %d), margin %d, allowance %d; want the margin charged alone", l.log.name, c.share[1001], l.share, c.margin[1001], c.allowance[1001])
		}
	}
}

// U67: an rm that names nothing changes nothing, so it is charged like any
// line and refused past the share; it never draws on the margin.
func TestNoOpRevocationChargedToShare(t *testing.T) {
	ctx := context.Background()
	s, a, b := shareStore(t)
	if err := b.Delete(ctx, "user/1002/absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a no-op rm within the share = %v, want ErrNotFound", err)
	}
	fillAudit(t, s, 1001, "", false)
	if err := a.Delete(ctx, "user/1001/absent"); !errors.Is(err, ErrLogFull) {
		t.Fatalf("a no-op rm past the share = %v, want ErrLogFull", err)
	}
	for _, l := range []*appendLog{auditLogOf(s), floorLogOf(s)} {
		if c := countsOf(t, l); c.margin[1001] != 0 || c.margin[1002] != 0 {
			t.Fatalf("%s: a no-op rm drew on a margin: %v", l.name, c.margin)
		}
	}
}

// U67: a uid that spent its socket margin keeps its reconciler allowance
// whole: its next socket revocation is refused, the reconciler's
// revocation for it is written, on the allowance alone.
func TestReserveKeepsReconcilerPart(t *testing.T) {
	ctx := context.Background()
	s, a, _ := shareStore(t)
	s.logRevokeBudget = minLogRevokeBudget
	fillAudit(t, s, 1001, "", true)
	if err := a.Delete(ctx, "user/1001/token"); !errors.Is(err, ErrLogFull) || !strings.Contains(err.Error(), "revocation budget") {
		t.Fatalf("rm with the margin spent = %v, want ErrLogFull naming the revocation budget", err)
	}
	before := countsOf(t, auditLogOf(s))
	if err := s.auditSink.append(reconcilerLine(1001)); err != nil {
		t.Fatalf("a reconciler revocation with the margin spent: %v", err)
	}
	after := countsOf(t, auditLogOf(s))
	if after.allowance[1001] <= before.allowance[1001] || after.margin[1001] != before.margin[1001] || after.share[1001] != before.share[1001] {
		t.Fatalf("the reconciler revocation charged share %d→%d margin %d→%d allowance %d→%d; want the allowance alone", before.share[1001], after.share[1001], before.margin[1001], after.margin[1001], before.allowance[1001], after.allowance[1001])
	}
}

// U67: the reconciler allowance has its own limit and spending it leaves
// the socket margin whole, so the uid's own rm still succeeds.
func TestSocketMarginSeparateFromReconcilerAllowance(t *testing.T) {
	ctx := context.Background()
	s, a, _ := shareStore(t)
	s.logAllowance = 4 * maxAppendLine
	fillAudit(t, s, 1001, "", false)
	var err error
	for i := 0; err == nil; i++ {
		if i > 100 {
			t.Fatal("the reconciler allowance never ran out")
		}
		err = s.auditSink.append(reconcilerLine(1001))
	}
	if !errors.Is(err, ErrLogFull) || !strings.Contains(err.Error(), "reconciler allowance") {
		t.Fatalf("a reconciler revocation past the allowance = %v, want ErrLogFull naming the allowance", err)
	}
	c := countsOf(t, auditLogOf(s))
	if c.margin[1001] != 0 || c.allowance[1001] > s.logAllowance {
		t.Fatalf("reconciler lines charged margin %d, allowance %d of %d", c.margin[1001], c.allowance[1001], s.logAllowance)
	}
	if err := a.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm with the allowance spent: %v", err)
	}
	if after := countsOf(t, auditLogOf(s)); after.allowance[1001] != c.allowance[1001] || after.margin[1001] == 0 {
		t.Fatalf("the rm charged allowance %d→%d margin %d; want the margin alone", c.allowance[1001], after.allowance[1001], after.margin[1001])
	}
}

// U67: one uid that spent its share and both budgets refuses none of
// another uid's revocations, socket or reconciler.
func TestRevocationAllowanceIsPerUID(t *testing.T) {
	ctx := context.Background()
	s, a, b := shareStore(t)
	s.logRevokeBudget, s.logAllowance = minLogRevokeBudget, 4*maxAppendLine
	fillAudit(t, s, 1001, "", true)
	for i := 0; s.auditSink.append(reconcilerLine(1001)) == nil; i++ {
		if i > 100 {
			t.Fatal("uid 1001's reconciler allowance never ran out")
		}
	}
	if err := a.Delete(ctx, "user/1001/token"); !errors.Is(err, ErrLogFull) {
		t.Fatalf("uid 1001's rm with both budgets spent = %v, want ErrLogFull", err)
	}
	fillAudit(t, s, 1002, "", false)
	if err := s.auditSink.append(reconcilerLine(1002)); err != nil {
		t.Fatalf("uid 1002's reconciler revocation: %v", err)
	}
	if err := b.Delete(ctx, "user/1002/token"); err != nil {
		t.Fatalf("uid 1002's rm: %v", err)
	}
}

// The shares are counted from the log: once root's maintenance swaps in a
// new audit log, every count starts again from it.
func TestShareResetAfterAuditRotate(t *testing.T) {
	ctx := context.Background()
	s, a, _ := shareStore(t)
	fillAudit(t, s, 1001, "", false)
	if _, err := a.Put(ctx, "user/1001/more", KindOpaque, []byte("v")); !errors.Is(err, ErrLogFull) {
		t.Fatalf("a put past the share = %v, want ErrLogFull", err)
	}
	p := filepath.Join(s.dataRoot, logsDirName, logDirOf(auditLogName), auditLogName)
	if err := os.WriteFile(p+".new", nil, logMode); err != nil {
		t.Fatal(err)
	}
	giveToService(t, p+".new")
	if err := os.Rename(p+".new", p); err != nil {
		t.Fatal(err)
	}
	if c := countsOf(t, auditLogOf(s)); len(c.share)+len(c.margin)+len(c.allowance) != 0 {
		t.Fatalf("counts after the swap: %+v, want none", c)
	}
	userPut(t, a, "user/1001/more", "v")
}

// The reader's size bound holds both per-uid budgets of maxRevokeUIDs uids
// past the hard cap, and the audit log's the pre-frame part besides.
func TestLogReadBoundHoldsBothBudgets(t *testing.T) {
	s, _ := newServerLogsStore(t)
	want := int64(256<<20 + 1024*(704<<10+256<<10) + 1<<20)
	if got := s.logReadBound(); got != want {
		t.Fatalf("logReadBound at the defaults = %d, want %d", got, want)
	}
	if got := s.readBoundOf(auditLogName); got != want+PreFrameBudget {
		t.Fatalf("the audit log's bound = %d, want %d", got, want+PreFrameBudget)
	}
	if got := s.readBoundOf(userFloorLogName); got != want {
		t.Fatalf("the floor's bound = %d, want %d", got, want)
	}
}

// The share is at most 1/16 of the hard cap: a configured share over it is
// refused, and the default is 16 MiB.
func TestShareConfigAtMostOneSixteenthOfHardCap(t *testing.T) {
	s, _ := newServerLogsStore(t)
	if got := s.uidShare(); got != 16<<20 {
		t.Fatalf("the default share = %d, want 16 MiB", got)
	}
	for _, tc := range []struct {
		hardCap, share int64
		ok             bool
		want           int64
	}{
		{256 << 20, 16 << 20, true, 16 << 20},
		{256 << 20, 16<<20 + 1, false, 0},
		{256 << 20, -1, false, 0},
		{64 << 20, 4 << 20, true, 4 << 20},
		{64 << 20, 8 << 20, false, 0},
	} {
		t.Run(fmt.Sprintf("cap%d-share%d", tc.hardCap, tc.share), func(t *testing.T) {
			s.logSoftCap, s.logHardCap, s.logUIDShare = tc.hardCap, tc.hardCap, tc.share
			err := s.checkConfig()
			if (err == nil) != tc.ok || (err != nil && !errors.Is(err, errInvalidConfig)) {
				t.Fatalf("checkConfig = %v, want ok %v", err, tc.ok)
			}
			if tc.ok && s.uidShare() != tc.want {
				t.Fatalf("uidShare = %d, want %d", s.uidShare(), tc.want)
			}
		})
	}
}
