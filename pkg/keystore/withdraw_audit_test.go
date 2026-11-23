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
	"testing"
)

// lastAudit returns the last audit line s's in-memory sink holds.
func lastAudit(t *testing.T, s *FileStore) auditLine {
	t.Helper()
	_, a := userLogs(s)
	lines := a.all()
	if len(lines) == 0 {
		t.Fatal("no audit line")
	}
	return lines[len(lines)-1]
}

// Withdraw's audit line is a revocation when it committed, its floor line
// failing (errCommitted) included, and not for a repeat that wrote no
// tombstone and no catch-up line.
func TestWithdrawAuditRevokeFlag(t *testing.T) {
	ctx := context.Background()
	s, _, u := newDeliveryScope(t)
	for _, n := range []int{1, 2} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatal(err)
	}
	if l := lastAudit(t, s); !l.revoke {
		t.Fatalf("a withdraw that revoked: audit line %+v, want revoke", l)
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatal(err)
	}
	if l := lastAudit(t, s); l.revoke {
		t.Fatalf("a no-op repeat withdraw: audit line %+v, want no revoke", l)
	}
	fl, _ := userLogs(s)
	fl.failAppend = true
	if err := u.withdrawDelivery(ctx, testDelivery(2).uid); !Committed(err) {
		t.Fatalf("withdraw with a failing floor append: %v, want Committed", err)
	}
	fl.failAppend = false
	if l := lastAudit(t, s); !l.revoke {
		t.Fatalf("a withdraw committed without its floor line: audit line %+v, want revoke", l)
	}
}
