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
	"os"
	"strconv"
	"testing"

	"k3sm.io/k3sm/pkg/keystore"
)

// padAuditPastCap appends root's lines, charged to no uid, until the audit
// log is at least size bytes.
func (r *bridgeRig) padAuditPastCap(t *testing.T, size int64) {
	t.Helper()
	f, err := os.OpenFile(r.auditPath(), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	line := []byte("\n" + `{"v":1,"ts":"2026-01-01T00:00:00Z","op":"put","via":"root","scope":"system","name":"pad","namespace":"","result":"ok"}`)
	for {
		st, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() >= size {
			return
		}
		if _, err := f.Write(line); err != nil {
			t.Fatal(err)
		}
	}
}

// Past the audit log's hard cap (U67, the socket's half), a put and a
// read are log-full while rm and rotate, the revocation class, still run
// on their uid's socket margin; one uid's spent margin refuses its own
// revocations only, never another uid's. The grant's refusal line cannot
// be written past the cap, which is the global append failure: until an
// append succeeds, the next put is refused before the store, and a
// revocation's append ends it.
func TestHardCapRefusesGrantsAndReadsNotRevocations(t *testing.T) {
	const hardCap = 16 * testShare
	r := newOpsRig(t, func(c *keystore.Config) {
		c.LogSoftCap, c.LogHardCap, c.LogUIDShare, c.LogRevocationBudget = hardCap, hardCap, hardCap/16, 6<<10
	})
	a, b := dialOps(t, r.ops, uidA), dialOps(t, r.ops, uidB)
	for i := range 3 {
		a.mustReply(t, hdr(t, OpPut, entryOf(uidA, "a"+strconv.Itoa(i)), nil), []byte("v"), nil)
		b.mustReply(t, hdr(t, OpPut, entryOf(uidB, "b"+strconv.Itoa(i)), nil), []byte("v"), nil)
	}
	r.padAuditPastCap(t, hardCap)
	for _, c := range []struct {
		name string
		w    *wire
		hdr  string
		val  []byte
	}{
		{"uid A's read", a, hdr(t, OpReadForExec, entryOf(uidA, "a0"), nil), nil},
		{"uid B's read", b, hdr(t, OpReadForExec, entryOf(uidB, "b0"), nil), nil},
		{"uid B's list", b, hdr(t, OpList, "", nil), nil},
		{"uid A's put", a, hdr(t, OpPut, entryOf(uidA, "new"), nil), []byte("v")},
	} {
		if code := codeOf(t, c.w.call(t, c.hdr, c.val)); code != CodeLogFull {
			t.Fatalf("%s past the hard cap: code %q, want log-full", c.name, code)
		}
	}
	if !r.fs.AuditFailing() {
		t.Fatal("the put's refusal line past the hard cap did not enter the global append failure")
	}
	if code := codeOf(t, b.call(t, hdr(t, OpPut, entryOf(uidB, "new"), nil), []byte("v"))); code != CodeRefused {
		t.Fatalf("a put while appends fail: code %q, want refused", code)
	}
	a.mustReply(t, hdr(t, OpRm, entryOf(uidA, "a2"), nil), nil, nil)
	if r.fs.AuditFailing() {
		t.Fatal("the rm's append on its margin did not end the global append failure")
	}
	a.mustReply(t, hdr(t, OpRotate, entryOf(uidA, "a0"), nil), []byte("v2"), nil)
	if code := codeOf(t, b.call(t, hdr(t, OpPut, entryOf(uidB, "new"), nil), []byte("v"))); code != CodeLogFull {
		t.Fatalf("uid B's put past the hard cap: code %q, want log-full", code)
	}
	// uid A rotates until its socket margin is spent.
	spent := false
	for i := range 40 {
		code := codeOf(t, a.call(t, hdr(t, OpRotate, entryOf(uidA, "a1"), nil), []byte("v"+strconv.Itoa(i))))
		if code == CodeLogFull {
			spent = true
			break
		}
		if code != "" {
			t.Fatalf("rotate %d: code %q", i, code)
		}
	}
	if !spent {
		t.Fatal("uid A rotated 40 times past the hard cap without spending its margin")
	}
	b.mustReply(t, hdr(t, OpRotate, entryOf(uidB, "b0"), nil), []byte("v2"), nil)
	b.mustReply(t, hdr(t, OpRm, entryOf(uidB, "b1"), nil), nil, nil)
	if f := b.mustReply(t, hdr(t, OpRotate, entryOf(uidB, "b2"), map[string]any{"from_version": 1}), nil, nil); f.Type != TypeReply {
		t.Fatal("uid B's rotate from a version was refused")
	}
}
