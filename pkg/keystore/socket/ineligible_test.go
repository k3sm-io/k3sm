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

package socket

import (
	"testing"

	"k3sm.io/k3sm/pkg/keystore"
)

// A peer the store gives no user scope (here a system uid the listener
// would have refused, reaching the operations directly) is answered
// refused, not internal, and leaves a refused line with the closed-set
// reason ineligible-uid naming it as the caller, rate-limited like every
// refused line.
func TestIneligibleUIDRefusedWithLine(t *testing.T) {
	r := newOpsRig(t, nil)
	const sysUID = 100
	w := dialOps(t, r.ops, sysUID)
	for i := range RefusalLinesPerMinute + 3 {
		f := w.call(t, hdr(t, OpList, "", nil), nil)
		if code := codeOf(t, f); code != CodeRefused {
			t.Fatalf("list %d by an ineligible uid: code %q, want refused", i, code)
		}
	}
	lines, _ := readAudit(t, r.auditPath())
	var mine []auditEntry
	for _, l := range lines {
		if l.Caller.UID == sysUID {
			mine = append(mine, l)
		}
	}
	if len(mine) != RefusalLinesPerMinute {
		t.Fatalf("the ineligible uid has %d lines, want %d: the rest rate-limited", len(mine), RefusalLinesPerMinute)
	}
	for _, l := range mine {
		if l.Op != "refused" || l.Request != "list" || l.Result != keystore.RefusedIneligibleUID || l.Scope != "" || l.Via != "socket" {
			t.Fatalf("the ineligible uid's line is %+v, want a socket refused list line, ineligible-uid, no scope", l)
		}
	}
}
