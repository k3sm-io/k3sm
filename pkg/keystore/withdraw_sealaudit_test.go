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
	"fmt"
	"strings"
	"testing"
	"time"
)

// auditPad is audit lines of uid 1001's scope totalling exactly n bytes,
// n at least two of the shortest such line.
func auditPad(t *testing.T, n int) []byte {
	t.Helper()
	line := func(nameLen int) []byte {
		l, err := marshalAuditLine(auditLine{op: "put", scope: "user/1001", name: strings.Repeat("p", nameLen), result: "ok"}, time.Unix(1_800_000_000, 0))
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	base := len(line(1)) - 1 // a line's bytes but its name's
	var out []byte
	for n-len(out) >= 2*(base+maxNameLen) {
		out = append(out, line(maxNameLen)...)
	}
	rem := n - len(out)
	if rem < 2*(base+1) {
		t.Fatalf("an audit pad of %d bytes is too short to split", n)
	}
	first := rem / 2
	out = append(out, line(first-base)...)
	out = append(out, line(rem-first-base)...)
	if len(out) != n {
		t.Fatalf("audit pad: %d bytes, want %d", len(out), n)
	}
	return out
}

// A withdraw under a delivery-record taint seals every live delivery and
// audits each: at every revocation budget left on the audit log around
// the mass seal's need, (1 + live deliveries) whole appends, it is either
// refused before it seals anything, or every sealed delivery's audit line
// lands with the withdraw's own.
func TestWithdrawMassSealAuditsEveryDeliveryAtBudgetEdge(t *testing.T) {
	const deliveries = 10 // 10 is torn withdrawn; withdrawing 1 seals 2 to 9
	need := (1 + deliveries - 2) * maxAppendLine
	for _, left := range []int{maxAppendLine + 75, 1600, 2000, 2400, need - 1, need, need + 1} {
		t.Run(fmt.Sprintf("left %d", left), func(t *testing.T) {
			ctx := context.Background()
			s, _, u := fileLogScope(t)
			for n := 1; n <= deliveries; n++ {
				if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
					t.Fatal(err)
				}
			}
			fl := s.userFloor.(*fileFloorLog).log
			tornFloorWrite(fl)
			if err := u.withdrawDelivery(ctx, testDelivery(deliveries).uid); err != nil && !errors.Is(err, errCommitted) {
				t.Fatalf("withdraw whose floor line tears: %v", err)
			}
			fl.write = nil
			forgetDeliveriesSeen(s)
			s2 := reopenStore(t, s)
			if err := s2.startUserScopes(ctx); err != nil {
				t.Fatalf("start: %v", err)
			}
			// Both logs at the hard cap, the audit log brought there by
			// another uid's lines, then uid 1001's lines past it spending
			// its revocation budget down to left.
			floorSize, auditSize := len(readLog(t, s2, userFloorLogName)), len(readLog(t, s2, auditLogName))
			if floorSize > auditSize {
				var fill []byte
				for len(fill) < floorSize-auditSize {
					l, err := marshalAuditLine(auditLine{op: "put", scope: "user/1002", name: "fill", result: "ok"}, time.Unix(1_800_000_000, 0))
					if err != nil {
						t.Fatal(err)
					}
					fill = append(fill, l...)
				}
				appendLogBytes(t, s2, auditLogName, fill)
			}
			s2.logSoftCap = int64(len(readLog(t, s2, auditLogName)))
			s2.logHardCap = s2.logSoftCap
			s2.logRevokeBudget = int64(need + 4*maxAppendLine)
			appendLogBytes(t, s2, auditLogName, auditPad(t, int(s2.logRevokeBudget)-left))
			floorBefore, auditBefore := readLog(t, s2, userFloorLogName), readLog(t, s2, auditLogName)
			err := userScope(t, s2, 1001).Withdraw(ctx, testDelivery(1).uid)
			floorAfter, auditAfter := readLog(t, s2, userFloorLogName), readLog(t, s2, auditLogName)
			named := map[string]bool{}
			for _, l := range bytes.Split(auditAfter[len(auditBefore):], []byte{'\n'}) {
				if r, perr := parseAuditLine(l); perr == nil && r.Op == "withdraw" && r.Result == auditResultOK {
					named[r.DeliveryUID] = true
				}
			}
			if err != nil && !errors.Is(err, errCommitted) {
				if !errors.Is(err, ErrLogFull) || !bytes.Equal(floorAfter, floorBefore) || len(named) != 0 {
					t.Fatalf("a refused mass seal (%v) wrote: floor grew %d bytes, audited %v", err, len(floorAfter)-len(floorBefore), named)
				}
				if left >= need {
					t.Fatalf("a mass seal with its whole need left (%d of %d) was refused: %v", left, need, err)
				}
				return
			}
			for n := 1; n < deliveries; n++ {
				if !named[testDelivery(n).uid] {
					t.Fatalf("withdraw (%v) with %d of the audit budget left: the audit log names %d of %d deliveries, not delivery %d", err, left, len(named), deliveries-1, n)
				}
			}
		})
	}
}

// failingAudit fails the audit line of one delivery and records the rest.
type failingAudit struct {
	fail  string
	lines []auditLine
}

func (a *failingAudit) append(l auditLine) error {
	if l.delivery == a.fail {
		return errors.New("injected audit failure")
	}
	a.lines = append(a.lines, l)
	return nil
}

// The sealed deliveries' audit loop attempts every line: one that fails
// does not stop the rest, and the result counts how many it wrote.
func TestAuditSealedKeepsGoingPastFailure(t *testing.T) {
	_, _, u := fileLogScope(t)
	a := &failingAudit{fail: testDelivery(2).uid}
	u.s.auditSink = a
	sealed := []delivery{testDelivery(1), testDelivery(2), testDelivery(3)}
	err := u.auditSealed(sealed, nil)
	if !errors.Is(err, errCommitted) || !strings.Contains(err.Error(), "2 of 3 written") {
		t.Fatalf("auditSealed with one line failing: %v, want errCommitted counting 2 of 3 written", err)
	}
	if len(a.lines) != 2 || a.lines[0].delivery != testDelivery(1).uid || a.lines[1].delivery != testDelivery(3).uid {
		t.Fatalf("auditSealed wrote %+v, want deliveries 1 and 3", a.lines)
	}
}
