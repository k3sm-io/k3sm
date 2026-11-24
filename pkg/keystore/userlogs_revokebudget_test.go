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
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

// A configuration under which a uid's lines past the hard cap exceed its
// revocation budget, which the writer never produces, means the caps were
// lowered: it is refused at store open, naming the remedy. Under one line of
// budget left is no refusal: it is counted, per uid.
func TestCheckLogBoundsRefusesSpentRevocationBudget(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	size := int64(len(readLog(t, s, auditLogName)))
	s.logSoftCap, s.logHardCap, s.logRevokeBudget = size, size, 4*maxLogLine
	line, err := marshalAuditLine(auditLine{op: "rm", scope: "user/1001", name: "token", result: "ok"}, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, auditLogName, bytes.Repeat(line, 3*maxLogLine/len(line)))
	if _, spent, err := s.CheckLogBounds(ctx); err != nil || spent != 0 {
		t.Fatalf("store open with the budget not yet spent: %d, %v", spent, err)
	}
	appendLogBytes(t, s, auditLogName, bytes.Repeat(line, maxLogLine/len(line)+2))
	_, _, err = s.CheckLogBounds(ctx)
	if !errors.Is(err, errInvalidConfig) || !errors.Is(err, errLogRevokeBudgetSpent) {
		t.Fatalf("store open with a uid over its revocation budget: %v, want errLogRevokeBudgetSpent", err)
	}
	if !strings.Contains(err.Error(), "sudo k3sm doctor") || !strings.Contains(err.Error(), "caps") {
		t.Fatalf("the refusal %q does not name the remedy", err)
	}
}

// The revocation budget holds at least one worst-case burial plus its audit
// line: maxBurialTombstones tombstones under the longest scope and name,
// and the longest rm audit line.
func TestCheckConfigRevocationBudgetFloor(t *testing.T) {
	tomb, rm, _, _ := worstRevocationLines(t)
	// Each append leads with a newline: the burial is one append, its
	// audit line another.
	floor := int64(maxBurialTombstones*tomb + 1 + rm + 1)
	if minLogRevokeBudget < floor || minLogRevokeBudget < 2*maxAppendLine {
		t.Fatalf("minLogRevokeBudget %d is under one worst-case burial plus its audit line, %d", int64(minLogRevokeBudget), floor)
	}
	s, _ := newTestStore(t)
	s.logRevokeBudget = minLogRevokeBudget - 1
	if err := s.checkConfig(); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("checkConfig with a budget under one burial: %v, want errInvalidConfig", err)
	}
	s.logRevokeBudget = minLogRevokeBudget
	if err := s.checkConfig(); err != nil {
		t.Fatalf("checkConfig with a budget of one burial: %v", err)
	}
}

// worstRevocationLines is the longest line of each revocation: an rm's
// tombstone and audit line under the longest scope and a 253-byte name,
// and a withdraw's floor line and audit line, at the longest result and a
// full RFC3339Nano timestamp, each audit line as the socket writes it, the
// socket margin's own lines: via socket and the caller with the longest
// uid and pid.
//
// A user rotate's lines (up to 535 bytes each: its audit line and its
// floor line) are revocations too and draw on the same socket margin; they
// are not counted here. That is an accepted residual, not a gap this
// margin closes: a uid that rotates without end spends its own margin and
// refuses only its own further socket revocations (docs/design/keystore.md
// § "Per-uid fairness", "The socket margin keeps a user able to revoke").
// The margin is not changed for them.
func worstRevocationLines(t *testing.T) (tomb, rmAudit, withdrawFloor, withdrawAudit int) {
	t.Helper()
	scope := userScopeOf(maxScopeUID)
	name := strings.Repeat("a", maxNameLen)
	tl, err := tombLine(scope, name, [generationSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	fl, err := floorLine(scope, deliveriesFloorName, [generationSize]byte{}, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 12, 31, 23, 59, 59, 999999999, time.UTC)
	for _, result := range revocationResults() {
		caller := &auditCaller{UID: maxScopeUID, PID: math.MaxInt32}
		al, err := marshalAuditLine(auditLine{op: "rm", via: auditViaSocket, caller: caller, scope: scope, name: name, result: result}, ts)
		if err != nil {
			t.Fatal(err)
		}
		rmAudit = max(rmAudit, len(al))
		wl, err := marshalAuditLine(auditLine{op: "withdraw", via: auditViaSocket, caller: caller, scope: scope, namespace: strings.Repeat("n", 63), delivery: "00000000-0000-0000-0000-000000000000", result: result}, ts)
		if err != nil {
			t.Fatal(err)
		}
		withdrawAudit = max(withdrawAudit, len(wl))
	}
	return len(tl), rmAudit, len(fl), withdrawAudit
}

// revocationResults are the results of auditResults an rm or withdraw line
// can carry with a name: not floor-degraded or quarantined, which refuse
// only grants and reads (rm and withdraw still run), not kind-mismatch,
// which no revocation checks, and not invalid-name, whose line names the
// placeholder rather than the name.
func revocationResults() []string {
	return slices.DeleteFunc(slices.Clone(auditResults), func(r string) bool {
		switch r {
		case "floor-degraded", "quarantined", "kind-mismatch", "invalid-name":
			return true
		}
		return false
	})
}

// The default budget holds one scope's full revocation: every entry rm'd
// under the longest scope and name, each a burial of maxBurialTombstones
// tombstones and an audit line, and maxDeliveries withdraws, each a floor
// line and an audit line; and logReadBound stays overflow-free at the
// caps' bounds with it.
func TestDefaultRevocationBudgetHoldsFullRevocation(t *testing.T) {
	tomb, rm, wFloor, wAudit := worstRevocationLines(t)
	need := int64(maxScopeEntries*(maxBurialTombstones*tomb+1+rm+1) + maxDeliveries*(wFloor+1+wAudit+1))
	if defaultLogRevocationBytes < need {
		t.Fatalf("defaultLogRevocationBytes %d is under one scope's full revocation, %d", int64(defaultLogRevocationBytes), need)
	}
	if defaultLogRevocationBytes > maxLogRevokeBudget || defaultLogRevocationBytes < minLogRevokeBudget {
		t.Fatalf("defaultLogRevocationBytes %d is outside its bounds", int64(defaultLogRevocationBytes))
	}
	s, _ := newTestStore(t)
	for _, budget := range []int64{defaultLogRevocationBytes, maxLogRevokeBudget} {
		s.logHardCap, s.logRevokeBudget = maxLogHardCap, budget
		if b := s.logReadBound(); b <= s.logHardCap || b < 0 {
			t.Fatalf("logReadBound() = %d at budget %d, overflowed", b, budget)
		}
	}
}
