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
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// The fake peers' uids: eligible, and never the test user's own, which
// stands in for the service uid.
const (
	uidA uint32 = 70001
	uidB uint32 = 70002
)

// testShare is a per-uid log share a few dozen lines fill.
const testShare = 8 << 10

func entryOf(uid uint32, name string) string {
	return "user/" + strconv.FormatUint(uint64(uid), 10) + "/" + name
}

// bridgeConfig tunes a store rig for the bridge: a fake GeneratedUID per
// uid, so no directory lookup runs, a share and a lock wait when not zero.
func bridgeConfig(share int64, lockWait time.Duration) func(*keystore.Config) {
	return func(c *keystore.Config) {
		c.GeneratedUID = func(uid uint32) ([16]byte, error) {
			return [16]byte{0x10, 0x20, byte(uid), byte(uid >> 8), byte(uid >> 16), byte(uid >> 24), 1}, nil
		}
		c.LogUIDShare = share
		c.LockWait = lockWait
	}
}

// fixedClock moves on by step at every reading (a second keeps every
// per-uid rate limit unreached; zero never moves) and by advance.
type fixedClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(c.step)
	return c.t
}

func (c *fixedClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// bridgeRig is a real, started store in t.TempDir() with the bridge over
// it and a handler whose test operations call the bridge.
type bridgeRig struct {
	*storeRig
	b     *FileStoreBridge
	h     *Handler
	clock *fixedClock
}

// newStartedBridge makes the store (tune, when not nil, runs after the
// bridge's own config), mints the master as root's verbs do, runs the
// start step and builds the bridge on a clock that moves a second a
// reading.
func newStartedBridge(t *testing.T, tune func(*keystore.Config)) *bridgeRig {
	t.Helper()
	r := newBridgeRig(t, tune, &fixedClock{t: time.Unix(1_000_000, 0), step: time.Second})
	if err := r.fs.StartUserScopes(t.Context()); err != nil {
		t.Fatalf("StartUserScopes: %v", err)
	}
	return r
}

// newBridgeRig is newStartedBridge on clock, without the start step.
func newBridgeRig(t *testing.T, tune func(*keystore.Config), clock *fixedClock) *bridgeRig {
	t.Helper()
	sr := newStoreRigWith(t, func(c *keystore.Config) {
		bridgeConfig(0, 0)(c)
		if tune != nil {
			tune(c)
		}
	})
	if _, err := sr.fs.Put(t.Context(), "seed", keystore.KindOpaque, []byte("x")); err != nil {
		t.Fatalf("minting the master: %v", err)
	}
	b, err := NewFileStoreBridge(sr.fs, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(time.Now, testBridgeOps(b)...)
	if err != nil {
		t.Fatal(err)
	}
	return &bridgeRig{storeRig: sr, b: b, h: h, clock: clock}
}

// testReq is the header the test operations read. The operations and
// their wire shapes are the bridge's tests' own, not the protocol's.
type testReq struct {
	Entry string `json:"entry"`
	From  uint64 `json:"from"`
}

// testBridgeOps are operations over b for the bridge's tests: each acts
// for the request's admitted peer, never a header field.
func testBridgeOps(b Store) []HandlerOption {
	parse := func(req Request) testReq {
		var r testReq
		_ = json.Unmarshal(req.Header, &r) // a test's own header
		return r
	}
	version := func(v keystore.Version, err error) (Reply, error) {
		return Reply{Header: map[string]any{"version": v.Version}}, err
	}
	admitted := func(op string, fn opFunc) HandlerOption {
		return withOp(op, func(ctx context.Context, req Request) (Reply, error) {
			if err := b.Admit(req.Peer, op); err != nil {
				return Reply{}, err
			}
			return fn(ctx, req)
		})
	}
	return []HandlerOption{
		admitted("put", func(ctx context.Context, req Request) (Reply, error) {
			return version(b.Put(ctx, req.Peer, parse(req).Entry, keystore.KindOpaque, req.Value))
		}),
		admitted("rotate", func(ctx context.Context, req Request) (Reply, error) {
			if r := parse(req); r.From != 0 {
				return version(b.RotateFrom(ctx, req.Peer, r.Entry, r.From))
			}
			return version(b.Rotate(ctx, req.Peer, parse(req).Entry, req.Value))
		}),
		admitted("rm", func(ctx context.Context, req Request) (Reply, error) {
			return Reply{}, b.Remove(ctx, req.Peer, parse(req).Entry)
		}),
		admitted("list", func(ctx context.Context, req Request) (Reply, error) {
			es, err := b.List(ctx, req.Peer)
			return Reply{Header: map[string]any{"entries": len(es)}}, err
		}),
		admitted("read-for-exec", func(ctx context.Context, req Request) (Reply, error) {
			v, val, err := b.ReadForExec(ctx, req.Peer, parse(req).Entry)
			return Reply{Header: map[string]any{"version": v.Version}, Value: val}, err
		}),
	}
}

// client is one fake peer's connection to the rig's handler, after HELLO.
type client struct {
	s *session
}

func (r *bridgeRig) connect(t *testing.T, uid uint32) *client {
	t.Helper()
	s := serveAs(t, r.h, Peer{UID: uid, PID: int32(uid % 1000)})
	s.hello(t)
	t.Cleanup(func() { _ = s.finish() })
	return &client{s: s}
}

// do sends op on entry (value as its binary part) and returns the reply's
// code, "" for ok, and the reply frame.
func (c *client) do(t *testing.T, op, entry string, value []byte) (Code, Frame) {
	t.Helper()
	hb, err := json.Marshal(map[string]string{"op": op, "entry": entry})
	if err != nil {
		t.Fatal(err)
	}
	c.s.send(t, TypeRequest, string(hb), value)
	f, hdr := c.s.recvFrame(t)
	if f.Type == TypeReply {
		return "", f
	}
	var code Code
	if err := json.Unmarshal(hdr["code"], &code); err != nil {
		t.Fatalf("error reply %s: %v", f.Header, err)
	}
	return code, f
}

// must is do, failing the test unless the reply is ok.
func (c *client) must(t *testing.T, op, entry string, value []byte) Frame {
	t.Helper()
	code, f := c.do(t, op, entry, value)
	if code != "" {
		t.Fatalf("%s %s: code %q, want ok", op, entry, code)
	}
	return f
}

// fill puts new entries for c's uid until the reply is not ok and returns
// that code; a uid that never stops within the bound fails the test.
func (c *client) fill(t *testing.T, uid uint32) Code {
	t.Helper()
	for i := range 200 {
		if code, _ := c.do(t, "put", entryOf(uid, "fill-"+strconv.Itoa(i)), []byte("v")); code != "" {
			return code
		}
	}
	t.Fatalf("uid %d put 200 entries without reaching its share", uid)
	return ""
}

// spend puts entries for p through the bridge until a put fails, and
// returns that error.
func (r *bridgeRig) spend(t *testing.T, p Peer) error {
	t.Helper()
	for i := range 200 {
		if _, err := r.b.Put(t.Context(), p, entryOf(p.UID, "spend-"+strconv.Itoa(i)), keystore.KindOpaque, []byte("v")); err != nil {
			return err
		}
	}
	t.Fatalf("uid %d put 200 entries without reaching its share", p.UID)
	return nil
}

// breakAudit makes every later append to the audit log fail: the store
// opens it for each append, and the log is no longer writable.
func (r *bridgeRig) breakAudit(t *testing.T) {
	t.Helper()
	if err := os.Chmod(r.auditPath(), 0o400); err != nil {
		t.Fatal(err)
	}
}

// lockedPut is a put through the bridge while the test holds the store
// lock exclusively, on a store whose lock wait is short.
func (r *bridgeRig) lockedPut(t *testing.T) error {
	t.Helper()
	sr := newStoreRigWith(t, bridgeConfig(0, 20*time.Millisecond))
	if _, err := sr.fs.Put(t.Context(), "seed", keystore.KindOpaque, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := sr.fs.StartUserScopes(t.Context()); err != nil {
		t.Fatal(err)
	}
	b, err := NewFileStoreBridge(sr.fs, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(sr.data, "server", "keystore", ".lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	_, err = b.Put(t.Context(), Peer{UID: uidA}, entryOf(uidA, "a"), keystore.KindOpaque, []byte("v"))
	if !keystore.LockBusy(err) {
		t.Fatalf("a put under a held lock = %v, want the store's busy error", err)
	}
	return err
}

// linesOf returns the audit lines charged to uid: those of its scope.
func (r *bridgeRig) linesOf(t *testing.T, uid uint32) []auditEntry {
	t.Helper()
	lines, _ := readAudit(t, r.auditPath())
	var out []auditEntry
	for _, e := range lines {
		if e.Scope == "user/"+strconv.FormatUint(uint64(uid), 10) {
			out = append(out, e)
		}
	}
	return out
}

// TestStoreInterfaceHasNoRevealMethod (U35): the socket server's interface
// onto the store, and the bridge behind it, have exactly the five
// operations' calls; none reveals, shows, rewraps, or reads a value
// unaudited.
func TestStoreInterfaceHasNoRevealMethod(t *testing.T) {
	want := []string{"Admit", "List", "Put", "ReadForExec", "Refused", "Remove", "Rotate", "RotateFrom"}
	banned := []string{"reveal", "show", "rewrap", "current", "get", "export", "dump"}
	for _, typ := range []reflect.Type{reflect.TypeFor[Store](), reflect.TypeFor[*FileStoreBridge]()} {
		var got []string
		for m := range typ.Methods() {
			got = append(got, m.Name)
			for _, b := range banned {
				if strings.Contains(strings.ToLower(m.Name), b) {
					t.Errorf("%v has the method %s, which reveals a value or the store", typ, m.Name)
				}
			}
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%v's methods are %v, want exactly %v", typ, got, want)
		}
	}
}

// Every bridge call opens the peer's own view stamped with the socket: its
// audit line carries via socket and the peer as caller, uid and pid.
func TestBridgeCallsAuditedViaSocket(t *testing.T) {
	r := newStartedBridge(t, nil)
	ctx := t.Context()
	p := Peer{UID: uidA, PID: 4321}
	e := entryOf(uidA, "a")
	calls := []struct {
		op string
		do func() error
	}{
		{"put", func() error { _, err := r.b.Put(ctx, p, e, keystore.KindOpaque, []byte("v1")); return err }},
		{"rotate", func() error { _, err := r.b.Rotate(ctx, p, e, []byte("v2")); return err }},
		{"rotate", func() error { _, err := r.b.RotateFrom(ctx, p, e, 1); return err }},
		{"exec-read", func() error {
			_, v, err := r.b.ReadForExec(ctx, p, e)
			if err == nil && string(v) != "v1" {
				t.Errorf("read-for-exec after a rotate from version 1 = %q, want v1", v)
			}
			return err
		}},
		{"list", func() error { _, err := r.b.List(ctx, p); return err }},
		{"rm", func() error { return r.b.Remove(ctx, p, e) }},
	}
	for i, c := range calls {
		if err := c.do(); err != nil {
			t.Fatalf("%s: %v", c.op, err)
		}
		lines := r.linesOf(t, uidA)
		if len(lines) != i+1 {
			t.Fatalf("after %s uid %d has %d audit lines, want %d", c.op, uidA, len(lines), i+1)
		}
		l := lines[i]
		if l.Op != c.op || l.Via != "socket" || l.Caller.UID != p.UID || l.Caller.PID != p.PID || l.Result != "ok" {
			t.Errorf("%s's line is %+v, want op %s, via socket, caller uid %d pid %d, result ok", c.op, l, c.op, p.UID, p.PID)
		}
	}
	// A refused call is audited the same way, under the peer's own uid.
	if err := r.b.Remove(ctx, p, entryOf(uidB, "a")); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("rm of another uid's entry = %v, want ErrNotFound", err)
	}
	lines := r.linesOf(t, uidA)
	if l := lines[len(lines)-1]; l.Op != "rm" || l.Via != "socket" || l.Caller.UID != uidA || l.Result != "not-found" {
		t.Errorf("the refused rm's line is %+v, want via socket, caller %d, not-found", l, uidA)
	}
}

// TestLogSharePerUIDRefusesOnlyThatUID (U51): a uid past its share has its
// own mutations and reads refused log-full, while another uid's mutations
// and reads succeed.
func TestLogSharePerUIDRefusesOnlyThatUID(t *testing.T) {
	r := newStartedBridge(t, func(c *keystore.Config) { c.LogUIDShare = testShare })
	a, b := r.connect(t, uidA), r.connect(t, uidB)
	b.must(t, "put", entryOf(uidB, "b"), []byte("vb"))
	if code := a.fill(t, uidA); code != CodeLogFull {
		t.Fatalf("uid %d's put past its share = %q, want log-full", uidA, code)
	}
	for _, c := range []struct{ op, entry string }{{"put", entryOf(uidA, "late")}, {"list", ""}, {"read-for-exec", entryOf(uidA, "fill-0")}} {
		if code, _ := a.do(t, c.op, c.entry, []byte("v")); code != CodeLogFull {
			t.Errorf("uid %d's %s past its share = %q, want log-full", uidA, c.op, code)
		}
	}
	b.must(t, "put", entryOf(uidB, "b2"), []byte("v"))
	b.must(t, "list", "", nil)
	if f := b.must(t, "read-for-exec", entryOf(uidB, "b"), nil); string(f.Value) != "vb" {
		t.Errorf("uid %d's read = %q, want vb", uidB, f.Value)
	}
}

// TestLogShareAtMostOneSixteenthOfHardCap (U51): the share is a fixed byte
// count of at most 1/16 of the hard cap, the default share when none is
// set included. A share above it refuses the start step, and the socket then answers user-scope-off; at 1/16 the
// store starts, and the uid's lines stop within that many bytes.
func TestLogShareAtMostOneSixteenthOfHardCap(t *testing.T) {
	const hardCap = 16 * testShare
	caps := func(share int64) func(*keystore.Config) {
		return func(c *keystore.Config) { c.LogSoftCap, c.LogHardCap, c.LogUIDShare = hardCap, hardCap, share }
	}
	// A store whose share is over refuses every operation, root's mint
	// included, so it is served as it is.
	over := &bridgeRig{storeRig: newStoreRigWith(t, func(c *keystore.Config) { bridgeConfig(0, 0)(c); caps(hardCap/16 + 1)(c) })}
	if err := over.fs.StartUserScopes(t.Context()); err == nil {
		t.Fatalf("the start step took a share of %d bytes over 1/16 of the hard cap %d", hardCap/16+1, hardCap)
	}
	ob, err := NewFileStoreBridge(over.fs, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if over.h, err = NewHandler(time.Now, testBridgeOps(ob)...); err != nil {
		t.Fatal(err)
	}
	if code, _ := over.connect(t, uidA).do(t, "put", entryOf(uidA, "a"), []byte("v")); code != CodeUserScopeOff {
		t.Fatalf("a put on a store whose start refused its share = %q, want user-scope-off", code)
	}
	// The share judged is the effective one: with no LogUIDShare, the
	// default share over 1/16 of a small hard cap refuses the start step
	// too, and the default caps, share and hard cap both unset, start.
	unset := newStoreRigWith(t, func(c *keystore.Config) { bridgeConfig(0, 0)(c); caps(0)(c) })
	if err := unset.fs.StartUserScopes(t.Context()); err == nil {
		t.Fatalf("the start step took the default share over 1/16 of a hard cap of %d", hardCap)
	}
	defaults := newStoreRigWith(t, bridgeConfig(0, 0))
	if err := defaults.fs.StartUserScopes(t.Context()); err != nil {
		t.Fatalf("the start step refused the default share and hard cap: %v", err)
	}
	r := newBridgeRig(t, caps(hardCap/16), &fixedClock{step: time.Second})
	if err := r.fs.StartUserScopes(t.Context()); err != nil {
		t.Fatalf("the start step refused a share of exactly 1/16 of the hard cap: %v", err)
	}
	if code := r.connect(t, uidA).fill(t, uidA); code != CodeLogFull {
		t.Fatalf("a put past the share = %q, want log-full", code)
	}
	raw, err := os.ReadFile(r.auditPath())
	if err != nil {
		t.Fatal(err)
	}
	var mine int64
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, `"scope":"user/`+strconv.FormatUint(uint64(uidA), 10)+`"`) {
			mine += int64(len(line)) + 2 // its newline and the leading one its append wrote
		}
	}
	if mine > hardCap/16 || mine < hardCap/16-1024 {
		t.Fatalf("uid %d's lines take %d bytes of the log, want at most its share %d and within a line of it", uidA, mine, hardCap/16)
	}
}

// TestShareRefusalIsNotGlobalAppendFailure (U51): a uid past its share is
// refused log-full, never the global append failure: the store does not
// enter it, counts nothing unaudited, and another uid's reads, which that
// failure would refuse, are served.
func TestShareRefusalIsNotGlobalAppendFailure(t *testing.T) {
	r := newStartedBridge(t, func(c *keystore.Config) { c.LogUIDShare = testShare })
	a, b := r.connect(t, uidA), r.connect(t, uidB)
	b.must(t, "put", entryOf(uidB, "b"), []byte("vb"))
	if code := a.fill(t, uidA); code != CodeLogFull {
		t.Fatalf("uid %d's put past its share = %q, want log-full", uidA, code)
	}
	if code, _ := a.do(t, "read-for-exec", entryOf(uidA, "fill-0"), nil); code != CodeLogFull {
		t.Fatalf("uid %d's read past its share = %q, want log-full, not refused", uidA, code)
	}
	if r.fs.AuditFailing() {
		t.Fatal("a uid's share refusal put the store in the global append failure")
	}
	if n := r.fs.UnauditedOps(); n != 0 {
		t.Fatalf("a share refusal counted %d unaudited operations", n)
	}
	b.must(t, "list", "", nil)
	b.must(t, "read-for-exec", entryOf(uidB, "b"), nil)
	// The global failure, by contrast, refuses every uid's reads.
	r.breakAudit(t)
	if code, _ := b.do(t, "read-for-exec", entryOf(uidB, "b"), nil); code != CodeRefused {
		t.Fatalf("a read while appends fail for everyone = %q, want refused", code)
	}
	if !r.fs.AuditFailing() {
		t.Fatal("an append the log refused did not put the store in the global append failure")
	}
}

// TestReadRateLimitPerUID (U51): list is limited per uid, at
// ListsPerSecond: past it the uid's list is rate-limited, reaches no store
// and writes no line, while another uid's list is served; the window
// slides with the clock.
func TestReadRateLimitPerUID(t *testing.T) {
	clock := &fixedClock{t: time.Unix(1_000_000, 0)}
	r := newBridgeRig(t, nil, clock)
	if err := r.fs.StartUserScopes(t.Context()); err != nil {
		t.Fatal(err)
	}
	a, b := r.connect(t, uidA), r.connect(t, uidB)
	a.must(t, "put", entryOf(uidA, "a"), []byte("v"))
	b.must(t, "put", entryOf(uidB, "b"), []byte("v"))
	for range ListsPerSecond {
		a.must(t, "list", "", nil)
	}
	before := len(r.linesOf(t, uidA))
	if code, _ := a.do(t, "list", "", nil); code != CodeRateLimited {
		t.Fatalf("uid %d's list %d in one second = %q, want rate-limited", uidA, ListsPerSecond+1, code)
	}
	if n := len(r.linesOf(t, uidA)); n != before {
		t.Fatalf("a rate-limited list wrote %d audit lines", n-before)
	}
	for range ListsPerSecond {
		b.must(t, "list", "", nil)
	}
	clock.advance(time.Second)
	a.must(t, "list", "", nil)
}

// TestReadsChargedToShare (U51): every read writes a line charged to its
// uid, so reads alone, with no mutation after the first put, spend the
// uid's share and are then refused log-full; another uid's reads go on.
func TestReadsChargedToShare(t *testing.T) {
	r := newStartedBridge(t, func(c *keystore.Config) { c.LogUIDShare = testShare })
	a, b := r.connect(t, uidA), r.connect(t, uidB)
	a.must(t, "put", entryOf(uidA, "a"), []byte("v"))
	b.must(t, "put", entryOf(uidB, "b"), []byte("v"))
	reads := 0
	for i := 0; ; i++ {
		if i == 200 {
			t.Fatalf("uid %d read 200 times without reaching its share", uidA)
		}
		op, entry := "list", ""
		if i%2 == 1 {
			op, entry = "read-for-exec", entryOf(uidA, "a")
		}
		before := len(r.linesOf(t, uidA))
		code, _ := a.do(t, op, entry, nil)
		if code == CodeLogFull {
			break
		}
		if code != "" {
			t.Fatalf("read %d: code %q", i, code)
		}
		lines := r.linesOf(t, uidA)
		want := map[string]string{"list": "list", "read-for-exec": "exec-read"}[op]
		if len(lines) != before+1 || lines[len(lines)-1].Op != want || lines[len(lines)-1].Caller.UID != uidA {
			t.Fatalf("read %d (%s) left uid %d with %d lines (was %d), last %+v; want one %s line charged to it", i, op, uidA, len(lines), before, lines[len(lines)-1], want)
		}
		reads++
	}
	if reads == 0 {
		t.Fatal("the first read was refused: nothing shows reads are what spent the share")
	}
	b.must(t, "list", "", nil)
	b.must(t, "read-for-exec", entryOf(uidB, "b"), nil)
}

// TestShareExhaustionIsolatedPerUID (U51): a uid past its share cannot get
// another uid's mutations, reads or revocations refused: every operation
// of the other uid succeeds and is audited ok under its own uid.
func TestShareExhaustionIsolatedPerUID(t *testing.T) {
	r := newStartedBridge(t, func(c *keystore.Config) { c.LogUIDShare = testShare })
	a, b := r.connect(t, uidA), r.connect(t, uidB)
	b.must(t, "put", entryOf(uidB, "keep"), []byte("v1"))
	b.must(t, "put", entryOf(uidB, "gone"), []byte("v1"))
	if code := a.fill(t, uidA); code != CodeLogFull {
		t.Fatalf("uid %d's put past its share = %q, want log-full", uidA, code)
	}
	before := len(r.linesOf(t, uidB))
	b.must(t, "put", entryOf(uidB, "new"), []byte("v"))
	b.must(t, "rotate", entryOf(uidB, "keep"), []byte("v2"))
	b.must(t, "list", "", nil)
	if f := b.must(t, "read-for-exec", entryOf(uidB, "keep"), nil); string(f.Value) != "v2" {
		t.Errorf("uid %d's read after its rotate = %q, want v2", uidB, f.Value)
	}
	b.must(t, "rm", entryOf(uidB, "gone"), nil)
	lines := r.linesOf(t, uidB)[before:]
	var ops []string
	for _, l := range lines {
		if l.Result != "ok" || l.Caller.UID != uidB {
			t.Errorf("uid %d's line %+v, want ok and its own uid", uidB, l)
		}
		ops = append(ops, l.Op)
	}
	if got := strings.Join(ops, ","); got != "put,rotate,list,exec-read,rm" {
		t.Errorf("uid %d's lines are %s, want put,rotate,list,exec-read,rm", uidB, got)
	}
	if code := b.fill(t, uidB); code != CodeLogFull {
		t.Fatalf("uid %d's own share is its own: past it its put = %q, want log-full", uidB, code)
	}
}
