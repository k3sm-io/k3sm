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
	"strings"
	"testing"
	"time"
)

// refusedOfUID is uid's post-frame refused lines, summaries included.
func (r *bridgeRig) refusedOfUID(t *testing.T, uid uint32) []auditEntry {
	t.Helper()
	var out []auditEntry
	for _, l := range r.linesOf(t, uid) {
		if l.Op == "refused" {
			out = append(out, l)
		}
	}
	return out
}

// Each kind of refusal the socket gives itself after the first frame
// writes one refused line under the caller: its uid and pid, via socket,
// its own scope, the operation and the reason.
func TestRefusedLinesEachKind(t *testing.T) {
	r := newLimitRig(t, nil)
	a := dialOps(t, r.ops, uidA)
	e := entryOf(uidA, "a")
	a.mustReply(t, hdr(t, OpPut, e, nil), []byte("v"), nil)
	check := func(name, header string, value []byte, code Code, op, reason string) {
		t.Helper()
		before := len(r.refusedOfUID(t, uidA))
		if got := codeOf(t, a.call(t, header, value)); got != code {
			t.Fatalf("%s: code %q, want %q", name, got, code)
		}
		ls := r.refusedOfUID(t, uidA)
		if len(ls) != before+1 {
			t.Fatalf("%s wrote %d refused lines, want 1", name, len(ls)-before)
		}
		l := ls[len(ls)-1]
		if l.Via != "socket" || l.Caller.UID != uidA || l.Caller.PID != int32(uidA%1000) || l.Scope != "user/"+strconv.FormatUint(uint64(uidA), 10) ||
			l.Name != "" || l.Request != op || l.Result != reason {
			t.Fatalf("%s's line is %+v, want via socket, caller %d, its scope, request %s, result %s", name, l, uidA, op, reason)
		}
	}
	check("a header field of the wrong type", `{"op":"rm","entry":7}`, nil, CodeRefused, "rm", "bad-header")
	check("a kind the socket does not store", hdr(t, OpPut, e, map[string]any{"kind": "token"}), []byte("v"), CodeRefused, "put", "bad-header")
	check("a value where none belongs", hdr(t, OpReadForExec, e, nil), []byte("v"), CodeRefused, "exec-read", "bad-value")
	check("a put with no value", hdr(t, OpPut, e, nil), nil, CodeRefused, "put", "bad-value")
	check("a placeholder", hdr(t, OpWithdraw, e, nil), nil, CodeRefused, "withdraw", "not-served")
	for range ListsPerSecond {
		a.mustReply(t, hdr(t, OpList, "", nil), nil, nil)
	}
	check("past the rate limit", hdr(t, OpList, "", nil), nil, CodeRateLimited, "list", "rate-limited")
	// The fail-closed refusal's line is written once appends work again,
	// and that append ends the global failure: a refused request probes.
	r.breakAudit(t)
	r.clock.advance(time.Second)
	if code := codeOf(t, a.call(t, hdr(t, OpReadForExec, e, nil), nil)); code != CodeRefused || !r.fs.AuditFailing() {
		t.Fatalf("a read whose line fails: code %q, failing %v", code, r.fs.AuditFailing())
	}
	r.mendAudit(t)
	check("while appends fail", hdr(t, OpPut, entryOf(uidA, "b"), nil), []byte("v"), CodeRefused, "put", "audit-failing")
	if r.fs.AuditFailing() {
		t.Fatal("the refused line's successful append did not end the global append failure")
	}
	a.mustReply(t, hdr(t, OpPut, entryOf(uidA, "b"), nil), []byte("v"), nil)
}

// TestRefusedLinesRateLimited (U33): a uid's refused lines are limited to
// RefusalLinesPerMinute in any minute however many of its requests are
// refused, rate-limited answers included; the rest are counted and written
// as one summary line with the count, at most once a minute, the next time
// the uid is refused; another uid's lines draw on its own limit.
func TestRefusedLinesRateLimited(t *testing.T) {
	r := newLimitRig(t, nil)
	a, b := dialOps(t, r.ops, uidA), dialOps(t, r.ops, uidB)
	for i := range MutationsPerSecond {
		a.mustReply(t, hdr(t, OpPut, entryOf(uidA, "a"+strconv.Itoa(i)), nil), []byte("v"), nil)
	}
	const flood = 40
	for range flood {
		if code := codeOf(t, a.call(t, hdr(t, OpPut, entryOf(uidA, "x"), nil), []byte("v"))); code != CodeRateLimited {
			t.Fatalf("a put past the limit: code %q, want rate-limited", code)
		}
	}
	ls := r.refusedOfUID(t, uidA)
	if len(ls) != RefusalLinesPerMinute {
		t.Fatalf("%d rate-limited requests wrote %d refused lines, want %d: %+v", flood, len(ls), RefusalLinesPerMinute, ls)
	}
	for _, l := range ls {
		if l.Result != "rate-limited" || l.Request != "put" {
			t.Fatalf("a refused line is %+v, want put rate-limited", l)
		}
	}
	// Another uid's refusals have their own limit.
	for range RefusalLinesPerMinute {
		_ = b.call(t, `{"op":"rm","entry":7}`, nil)
	}
	if n := len(r.refusedOfUID(t, uidB)); n != RefusalLinesPerMinute {
		t.Fatalf("uid %d wrote %d refused lines, want its own %d", uidB, n, RefusalLinesPerMinute)
	}
	// Within the minute nothing more is written, summary included.
	r.clock.advance(59 * time.Second)
	_ = a.call(t, `{"op":"rm","entry":7}`, nil)
	if n := len(r.refusedOfUID(t, uidA)); n != RefusalLinesPerMinute {
		t.Fatalf("a refusal inside the minute wrote a line: %d lines", n)
	}
	// A minute on, the next refusal writes the summary, then its line.
	r.clock.advance(time.Second)
	_ = a.call(t, `{"op":"rm","entry":7}`, nil)
	ls = r.refusedOfUID(t, uidA)
	if len(ls) != RefusalLinesPerMinute+2 {
		t.Fatalf("%d refused lines after the minute, want the summary and the line", len(ls))
	}
	sum, line := ls[RefusalLinesPerMinute], ls[RefusalLinesPerMinute+1]
	if sum.Result != "dropped" || sum.Dropped != flood-RefusalLinesPerMinute+1 || sum.Request != "" || sum.Caller.UID != uidA {
		t.Fatalf("the summary is %+v, want dropped %d for uid %d", sum, flood-RefusalLinesPerMinute+1, uidA)
	}
	if line.Result != "bad-header" || line.Request != "rm" {
		t.Fatalf("the line after the summary is %+v", line)
	}
	// The summary is written at most once a minute: refusals past the limit
	// in this minute wait for the next one.
	for range 2 * RefusalLinesPerMinute {
		_ = a.call(t, `{"op":"rm","entry":7}`, nil)
	}
	ls = r.refusedOfUID(t, uidA)
	if len(ls) != 2*RefusalLinesPerMinute+1 {
		t.Fatalf("%d refused lines, want %d: the minute's %d and one summary", len(ls), 2*RefusalLinesPerMinute+1, RefusalLinesPerMinute)
	}
	if p := r.b.refusals.pending(uidA); p != RefusalLinesPerMinute+1 {
		t.Fatalf("%d refusals pending a summary, want %d", p, RefusalLinesPerMinute+1)
	}
}

// Nothing the peer sent reaches a refused line: not the entry it named,
// not its value, not the kind or field it gave.
func TestRefusedLinesCarryNothingFromThePeer(t *testing.T) {
	r := newLimitRig(t, nil)
	a := dialOps(t, r.ops, uidA)
	name := entryOf(uidA, "peername")
	for _, c := range []struct {
		header string
		value  []byte
	}{
		{hdr(t, OpPut, name, map[string]any{"kind": "peerkind"}), []byte("peervalue")},
		{hdr(t, OpRotate, name, map[string]any{"from_version": "peerversion"}), nil},
		{hdr(t, OpRm, name, nil), []byte("peervalue")},
		{hdr(t, OpDeliver, name, map[string]any{"namespace": "peerns"}), []byte("peervalue")},
		{`{"op":"list","peerfield":"peerfield"}`, []byte("peervalue")},
	} {
		if code := codeOf(t, a.call(t, c.header, c.value)); code != CodeRefused {
			t.Fatalf("%s: code %q, want refused", c.header, code)
		}
	}
	if n := len(r.refusedOfUID(t, uidA)); n != 5 {
		t.Fatalf("%d refused lines, want 5", n)
	}
	raw, err := os.ReadFile(r.auditPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"peername", "peervalue", "peerkind", "peerversion", "peerns", "peerfield"} {
		if strings.Contains(string(raw), s) {
			t.Errorf("the audit log carries %q, which the peer sent", s)
		}
	}
}
