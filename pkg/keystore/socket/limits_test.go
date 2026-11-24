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
	"strconv"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// limitRig is a started real store whose bridge reads a clock that moves
// only when the test advances it, with the production operations served
// over a spy of the bridge.
type limitRig struct {
	*bridgeRig
	spy *spyStore
	ops *Handler
}

func newLimitRig(t *testing.T, tune func(*keystore.Config)) *limitRig {
	t.Helper()
	r := newBridgeRig(t, tune, &fixedClock{t: time.Unix(1_000_000, 0)})
	if err := r.fs.StartUserScopes(t.Context()); err != nil {
		t.Fatal(err)
	}
	spy := newSpyStore(r.b)
	h, err := NewOpsHandler(time.Now, spy)
	if err != nil {
		t.Fatal(err)
	}
	return &limitRig{bridgeRig: r, spy: spy, ops: h}
}

// storeCalls is how many calls reached the store behind the spy.
func (r *limitRig) storeCalls() int {
	n := 0
	for _, m := range []string{"Put", "Rotate", "RotateFrom", "Remove", "List", "ReadForExec"} {
		n += r.spy.n(m)
	}
	return n
}

// storeLinesOf is uid's audit lines but the socket's own refused lines:
// the lines the store wrote for its operations.
func (r *limitRig) storeLinesOf(t *testing.T, uid uint32) []auditEntry {
	t.Helper()
	var out []auditEntry
	for _, l := range r.linesOf(t, uid) {
		if l.Op != "refused" {
			out = append(out, l)
		}
	}
	return out
}

// TestMutationRateLimit (U34): one uid makes at most MutationsPerSecond
// mutating requests a second, put, rotate (either form), rm and the
// delivery placeholders deliver and withdraw counted together; past it a
// request is rate-limited before the store is called and writes no store
// line; another uid is not limited by it; the window slides with the
// clock.
func TestMutationRateLimit(t *testing.T) {
	if MutationsPerSecond != 5 {
		t.Fatalf("MutationsPerSecond = %d, want the design's 5", MutationsPerSecond)
	}
	r := newLimitRig(t, nil)
	a, b := dialOps(t, r.ops, uidA), dialOps(t, r.ops, uidB)
	e := entryOf(uidA, "a")
	a.mustReply(t, hdr(t, OpPut, e, nil), []byte("v1"), nil)
	a.mustReply(t, hdr(t, OpRotate, e, nil), []byte("v2"), nil)
	a.mustReply(t, hdr(t, OpRotate, e, map[string]any{"from_version": 1}), nil, nil)
	a.mustReply(t, hdr(t, OpPut, entryOf(uidA, "b"), nil), []byte("v"), nil)
	a.mustReply(t, hdr(t, OpRm, entryOf(uidA, "b"), nil), nil, nil)
	calls, lines := r.storeCalls(), len(r.storeLinesOf(t, uidA))
	for _, c := range []struct {
		name, hdr string
		val       []byte
	}{
		{"put", hdr(t, OpPut, entryOf(uidA, "c"), nil), []byte("v")},
		{"rotate", hdr(t, OpRotate, e, nil), []byte("v3")},
		{"rm", hdr(t, OpRm, e, nil), nil},
		{"deliver", hdr(t, OpDeliver, e, nil), nil},
		{"withdraw", hdr(t, OpWithdraw, e, nil), nil},
	} {
		if code := codeOf(t, a.call(t, c.hdr, c.val)); code != CodeRateLimited {
			t.Errorf("uid %d's %s past %d mutations in a second: code %q, want rate-limited", uidA, c.name, MutationsPerSecond, code)
		}
	}
	if n := r.storeCalls() - calls; n != 0 {
		t.Fatalf("rate-limited requests reached the store %d times", n)
	}
	if n := len(r.storeLinesOf(t, uidA)) - lines; n != 0 {
		t.Fatalf("rate-limited requests wrote %d store lines", n)
	}
	// Reads have limits of their own, which the mutations did not spend.
	a.mustReply(t, hdr(t, OpList, "", nil), nil, nil)
	a.mustReply(t, hdr(t, OpReadForExec, e, nil), nil, nil)
	for i := range MutationsPerSecond {
		b.mustReply(t, hdr(t, OpPut, entryOf(uidB, "b"+strconv.Itoa(i)), nil), []byte("v"), nil)
	}
	r.clock.advance(999 * time.Millisecond)
	if code := codeOf(t, a.call(t, hdr(t, OpRm, e, nil), nil)); code != CodeRateLimited {
		t.Fatalf("a mutation within the second: code %q, want rate-limited", code)
	}
	r.clock.advance(time.Millisecond)
	// The placeholders spend the limit as the operations they stand for.
	for range MutationsPerSecond {
		if code := codeOf(t, a.call(t, hdr(t, OpDeliver, e, nil), nil)); code != CodeRefused {
			t.Fatalf("deliver in a new second: code %q, want refused (not served yet)", code)
		}
	}
	if code := codeOf(t, a.call(t, hdr(t, OpPut, entryOf(uidA, "d"), nil), []byte("v"))); code != CodeRateLimited {
		t.Fatalf("a put after %d delivers in a second: code %q, want rate-limited", MutationsPerSecond, code)
	}
	r.clock.advance(time.Second)
	a.mustReply(t, hdr(t, OpRm, e, nil), nil, nil)
}

// TestExecReadCapPerUID (U34): one uid makes at most ExecReadsPerMinute
// read-for-exec requests a minute, each audited exec-read under its uid;
// past it a read is rate-limited before the store is called and hands out
// no value; another uid's reads, and the same uid's list, are not limited
// by it; the window is a sliding minute.
func TestExecReadCapPerUID(t *testing.T) {
	if ExecReadsPerMinute != 30 {
		t.Fatalf("ExecReadsPerMinute = %d, want the design's 30", ExecReadsPerMinute)
	}
	r := newLimitRig(t, nil)
	a, b := dialOps(t, r.ops, uidA), dialOps(t, r.ops, uidB)
	ea, eb := entryOf(uidA, "a"), entryOf(uidB, "b")
	a.mustReply(t, hdr(t, OpPut, ea, nil), []byte("va"), nil)
	b.mustReply(t, hdr(t, OpPut, eb, nil), []byte("vb"), nil)
	before := len(r.storeLinesOf(t, uidA))
	for i := range ExecReadsPerMinute {
		if f := a.mustReply(t, hdr(t, OpReadForExec, ea, nil), nil, nil); string(f.Value) != "va" {
			t.Fatalf("read %d = %q, want va", i, f.Value)
		}
		r.clock.advance(time.Second)
	}
	lines := r.storeLinesOf(t, uidA)[before:]
	if len(lines) != ExecReadsPerMinute {
		t.Fatalf("%d reads wrote %d lines, want one each", ExecReadsPerMinute, len(lines))
	}
	for _, l := range lines {
		if l.Op != "exec-read" || l.Result != "ok" || l.Via != "socket" || l.Caller.UID != uidA {
			t.Fatalf("a read's line is %+v, want exec-read ok via socket for uid %d", l, uidA)
		}
	}
	calls := r.spy.n("ReadForExec")
	// 30 seconds have passed: the first read is still inside the minute.
	f := a.call(t, hdr(t, OpReadForExec, ea, nil), nil)
	if code := codeOf(t, f); code != CodeRateLimited || f.Value != nil {
		t.Fatalf("read %d in a minute: code %q value %q, want rate-limited and no value", ExecReadsPerMinute+1, code, f.Value)
	}
	if n := r.spy.n("ReadForExec") - calls; n != 0 {
		t.Fatalf("a rate-limited read reached the store %d times", n)
	}
	if n := len(r.storeLinesOf(t, uidA)) - before; n != ExecReadsPerMinute {
		t.Fatalf("a rate-limited read wrote a store line: %d lines, want %d", n, ExecReadsPerMinute)
	}
	a.mustReply(t, hdr(t, OpList, "", nil), nil, nil)
	b.mustReply(t, hdr(t, OpReadForExec, eb, nil), nil, nil)
	// The first read leaves the window a minute after it was made.
	r.clock.advance(29 * time.Second)
	if code := codeOf(t, a.call(t, hdr(t, OpReadForExec, ea, nil), nil)); code != CodeRateLimited {
		t.Fatalf("a read 59 seconds after the first: code %q, want rate-limited", code)
	}
	r.clock.advance(time.Second)
	a.mustReply(t, hdr(t, OpReadForExec, ea, nil), nil, nil)
}

// deliveries shares list's per-uid limit, ListsPerSecond for the two
// together (docs/design/keystore.md § "The socket", "Bounds").
func TestDeliveriesSharesListLimit(t *testing.T) {
	r := newLimitRig(t, nil)
	a := dialOps(t, r.ops, uidA)
	for range ListsPerSecond - 1 {
		a.mustReply(t, hdr(t, OpList, "", nil), nil, nil)
	}
	if code := codeOf(t, a.call(t, hdr(t, OpDeliveries, "", nil), nil)); code != CodeRefused {
		t.Fatalf("deliveries within the limit: code %q, want refused (not served yet)", code)
	}
	for _, op := range []string{OpList, OpDeliveries} {
		if code := codeOf(t, a.call(t, hdr(t, op, "", nil), nil)); code != CodeRateLimited {
			t.Fatalf("%s past %d list and deliveries requests in a second: code %q, want rate-limited", op, ListsPerSecond, code)
		}
	}
}
