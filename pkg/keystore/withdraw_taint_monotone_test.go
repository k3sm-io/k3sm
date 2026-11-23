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
	"testing"
)

// A withdraw under a delivery-record taint reseals a record copy that
// could be older than the lost line: here the lost line withdrew delivery
// 3, and the copy put back still holds it live. The reseal counts every
// delivery as withdrawn, so the lost withdraw is never undone, and seals
// above both the record's and the floor's sequence.
func TestWithdrawUnderTaintNeverRevivesLostWithdraw(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	for _, n := range []int{1, 2, 3} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	older := readDeliveriesBytes(t, server)
	_, olderSeq := recordedDelivery(t, s, server, 3)
	fl := s.userFloor.(*fileFloorLog).log
	tornFloorWrite(fl)
	if err := u.withdrawDelivery(ctx, testDelivery(3).uid); err != nil && !Committed(err) {
		t.Fatalf("withdraw whose floor line tears: %v", err)
	}
	fl.write = nil
	putBackDeliveries(t, server, older)
	forgetDeliveriesSeen(s)
	s2 := reopenStore(t, s)
	if err := s2.startUserScopes(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	u2 := userScope(t, s2, 1001)
	if err := u2.Withdraw(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw under a delivery-record taint: %v", err)
	}
	for _, n := range []int{1, 2, 3} {
		d, seq := recordedDelivery(t, s2, server, n)
		if !d.withdrawn {
			t.Fatalf("delivery %d is live in the record resealed under the taint; the lost line could have withdrawn it", n)
		}
		if seq <= olderSeq {
			t.Fatalf("the resealed record's sequence %d is not above the copy's %d", seq, olderSeq)
		}
	}
}

// The mass seal under a delivery-record taint is audited: the audit log
// names every delivery it withdrew, the requested one and the others, each
// a revocation's line.
func TestWithdrawUnderTaintAuditsEverySealed(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	for _, n := range []int{1, 2, 3} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	fl := s.userFloor.(*fileFloorLog).log
	tornFloorWrite(fl)
	if err := u.withdrawDelivery(ctx, testDelivery(3).uid); err != nil && !Committed(err) {
		t.Fatalf("withdraw whose floor line tears: %v", err)
	}
	fl.write = nil
	forgetDeliveriesSeen(s)
	s2 := reopenStore(t, s)
	if err := s2.startUserScopes(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	before := len(readLog(t, s2, auditLogName))
	if err := userScope(t, s2, 1001).Withdraw(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw under a delivery-record taint: %v", err)
	}
	named := map[string]bool{}
	for _, l := range bytes.Split(readLog(t, s2, auditLogName)[before:], []byte{'\n'}) {
		r, err := parseAuditLine(l)
		if err != nil || r.Op != "withdraw" || r.Result != auditResultOK {
			continue
		}
		named[r.DeliveryUID] = true
	}
	for _, n := range []int{1, 2} {
		if !named[testDelivery(n).uid] {
			t.Fatalf("the audit log after the mass seal names %v, not delivery %d", named, n)
		}
	}
}
