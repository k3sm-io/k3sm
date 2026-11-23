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
	"bytes"
	"fmt"
	"testing"
	"testing/synctest"

	"k3sm.io/k3sm/pkg/keystore"
)

// preFrameLineFor is a pre-frame line for uid and reason, as the server
// writes it in a synctest bubble.
func preFrameLineFor(uid uint32, reason string) string {
	return fmt.Sprintf(`{"v":1,"ts":"2000-01-01T00:00:00Z","op":"refused","via":"socket","caller":{"uid":%d},"scope":"","name":"","namespace":"","result":%q,"charge":"reconciler","source":"pre-frame"}`, uid, reason)
}

// uidShareLines is uid's sandboxed lines, each led by a newline, filling
// keystore.PreFrameLoginUIDShare until no further one fits.
func uidShareLines(uid uint32) []byte {
	one := "\n" + preFrameLineFor(uid, ReasonSandboxed) + "\n"
	return bytes.Repeat([]byte(one), keystore.PreFrameLoginUIDShare/len(one))
}

// TestPreFrameBudgetLoginUIDCannotStarveIneligible checks the pre-frame
// part's split: a login uid past its sub-share is dropped while root and
// service-uid refusals still land; login uids together cannot pass the
// login part; and the recount from the log after a reopen gives the same
// answers.
func TestPreFrameBudgetLoginUIDCannotStarveIneligible(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newStoreRig(t)
		ctx := t.Context()
		if err := r.logs.Reopen(ctx); err != nil {
			t.Fatal(err)
		}
		// One login uid spends its sub-share through the append path.
		landed := 0
		for i := 0; ; i++ {
			if i > keystore.PreFrameLoginUIDShare {
				t.Fatal("a login uid's lines never ran out of room")
			}
			before := size(t, r.auditPath())
			err := r.logs.Refused(ctx, 501, ReasonSandboxed)
			if err != nil {
				if size(t, r.auditPath()) != before {
					t.Fatal("a refused append wrote bytes")
				}
				break
			}
			landed++
		}
		one := len(preFrameLineFor(501, ReasonSandboxed)) + 2
		if want := keystore.PreFrameLoginUIDShare / one; landed != want {
			t.Fatalf("uid 501 landed %d lines, want %d (its %d-byte sub-share)", landed, want, keystore.PreFrameLoginUIDShare)
		}
		if got := r.logs.PendingDropped(501); got != 1 {
			t.Fatalf("uid 501 dropped count = %d, want 1", got)
		}
		check := func(when string) {
			t.Helper()
			if err := r.logs.Refused(ctx, 501, ReasonCredUnreadable); err == nil {
				t.Fatalf("%s: uid 501 past its sub-share still landed a line", when)
			}
			if err := r.logs.Refused(ctx, 0, ReasonRoot); err != nil {
				t.Fatalf("%s: a root refusal was not written: %v", when, err)
			}
			if err := r.logs.Refused(ctx, serviceUID, ReasonServiceUID); err != nil {
				t.Fatalf("%s: a service-uid refusal was not written: %v", when, err)
			}
			if err := r.logs.Refused(ctx, NoUID, ReasonCredUnreadable); err != nil {
				t.Fatalf("%s: a no-uid refusal was not written: %v", when, err)
			}
		}
		check("first count")
		if err := r.logs.Reopen(ctx); err != nil {
			t.Fatal(err)
		}
		// Every byte appended is a pre-frame line's charge.
		if got, want := r.logs.PreFrameUsed(), size(t, r.auditPath()); got != want {
			t.Fatalf("recount after reopen = %d, want the log's %d bytes", got, want)
		}
		check("after reopen")

		// Many login uids, each at its sub-share in the log, together pass
		// the login part: the recount classes each line from its uid and
		// reason, and no login uid lands another line, while the reserved
		// part still takes root's.
		var seeded bytes.Buffer
		n := keystore.PreFrameLoginBudget/keystore.PreFrameLoginUIDShare + 4
		for u := range n {
			seeded.Write(uidShareLines(uint32(1000 + u)))
		}
		r.writeLog(t, r.auditPath(), seeded.Bytes())
		if err := r.logs.Reopen(ctx); err != nil {
			t.Fatal(err)
		}
		if got := r.logs.PreFrameUsed(); got != int64(seeded.Len()) || got <= keystore.PreFrameLoginBudget {
			t.Fatalf("recounted %d bytes, want the %d seeded, over the login part", got, seeded.Len())
		}
		for _, uid := range []uint32{1000, 5000, 70000} {
			if err := r.logs.Refused(ctx, uid, ReasonSandboxUnknown); err == nil {
				t.Fatalf("login uid %d landed a line past the login part", uid)
			}
		}
		if err := r.logs.Refused(ctx, 0, ReasonRoot); err != nil {
			t.Fatalf("a root refusal was not written past the login part: %v", err)
		}
		if err := r.logs.Refused(ctx, 42, ReasonSystemUID); err != nil {
			t.Fatalf("a system-uid refusal was not written past the login part: %v", err)
		}

		// Through the append path: fresh login uids fill what is left of
		// the login part and no more.
		seeded.Reset()
		for u := range keystore.PreFrameLoginBudget/keystore.PreFrameLoginUIDShare - 1 {
			seeded.Write(uidShareLines(uint32(1000 + u)))
		}
		r.writeLog(t, r.auditPath(), seeded.Bytes())
		if err := r.logs.Reopen(ctx); err != nil {
			t.Fatal(err)
		}
		start := r.logs.PreFrameUsed()
		for _, uid := range []uint32{3000, 3001, 3002} {
			for r.logs.Refused(ctx, uid, ReasonSandboxed) == nil {
			}
		}
		if got := r.logs.PreFrameUsed(); got > keystore.PreFrameLoginBudget {
			t.Fatalf("login lines took %d bytes (from %d), over the %d-byte login part", got, start, keystore.PreFrameLoginBudget)
		}
		if err := r.logs.Refused(ctx, 0, ReasonRoot); err != nil {
			t.Fatalf("a root refusal was not written: %v", err)
		}
	})
}
