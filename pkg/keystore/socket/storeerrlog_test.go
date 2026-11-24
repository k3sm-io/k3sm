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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// logCapture is a slog handler's output, read back as records.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(c, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		// No time: the check for a value's length reads every byte.
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
}

// records are the lines logged so far, each as its fields.
func (c *logCapture) records(t *testing.T) []map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(c.buf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("log line %s: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func (c *logCapture) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.buf.Bytes())
}

// checkStoreErrorLine holds rec to the shape of a store-error line: Warn,
// the op, the uid, requested_entry when entry names one, the class and its
// fixed remedy, suppressed when want is not 0, and no other field: never
// the error's text.
func checkStoreErrorLine(t *testing.T, rec map[string]any, op string, uid uint32, entry, class string, suppressed uint64) {
	t.Helper()
	keys := []string{"class", "level", "msg", "op", "remedy", "uid"}
	if entry != "" {
		keys = append(keys, "requested_entry")
	}
	if suppressed != 0 {
		keys = append(keys, "suppressed")
	}
	var got []string
	for k := range rec {
		got = append(got, k)
	}
	slices.Sort(got)
	slices.Sort(keys)
	if !slices.Equal(got, keys) {
		t.Errorf("log line %v has fields %q, want %q", rec, got, keys)
	}
	if rec["level"] != "WARN" || rec["op"] != op || rec["uid"] != float64(uid) || (entry != "" && rec["requested_entry"] != entry) ||
		rec["class"] != class || rec["remedy"] != damageRemedies[class] || (suppressed != 0 && rec["suppressed"] != float64(suppressed)) {
		t.Errorf("log line %v, want Warn for %s by uid %d naming %q, class %s, %d suppressed", rec, op, uid, entry, class, suppressed)
	}
}

// serveOne serves one HELLO and one request with header on h, for uidA.
func serveOne(t *testing.T, h *Handler, header string) {
	t.Helper()
	serveRequestAs(t, h, uidA, header)
}

// serveRequestAs serves one HELLO and one request with header on h, for uid.
func serveRequestAs(t *testing.T, h *Handler, uid uint32, header string) {
	t.Helper()
	var in bytes.Buffer
	in.Write(frameBytes(t, Frame{Type: TypeHello, Header: []byte(helloV1)}))
	in.Write(frameBytes(t, Frame{Type: TypeRequest, Header: []byte(header)}))
	if err := h.Serve(t.Context(), &recordingConn{in: bytes.NewReader(in.Bytes())}, Peer{UID: uid}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// leakyErr is an error whose text carries what a decoder might have built
// from a decrypted value: its bytes, a length and a tag.
func leakyErr(sentinel error) error {
	return fmt.Errorf("%w: tag 0x7e claims 4242 bytes: %s", sentinel, secretValue)
}

// The server logs the store errors that are damage, at Warn, with the op,
// the peer's uid, the entry when the request named a valid one, a class of
// the closed set and its fixed remedy, never the error's text: an error
// answered internal, a corrupt record, a floor that is stale or records a
// deleted entry, an orphan version, the floor's damage and the scope's
// quarantine. The ordinary outcomes, which have their audit lines, a
// change that committed and a cancelled or timed-out request are not
// logged, and no line carries a value, a length or a tag from the error.
func TestStoreErrorLogged(t *testing.T) {
	t.Run("each outcome", func(t *testing.T) {
		wrap := func(err error) error { return fmt.Errorf("user scope exec-read: %w", err) }
		for _, tc := range []struct {
			name  string
			err   error
			class string
		}{
			{"corrupt", wrap(leakyErr(keystore.ErrCorrupt)), DamageCorrupt},
			{"floor stale", wrap(fmt.Errorf("%w: the current pointer is older than the floor records", keystore.ErrCorrupt)), DamageCorrupt},
			{"floor records a deleted entry", wrap(keystore.ErrFloorRecordsEntry), DamageFloorRecordsEntry},
			{"orphan version", wrap(fmt.Errorf("%w: %w: rm and put it again", keystore.ErrCorrupt, keystore.ErrOrphanVersion)), DamageOrphanVersion},
			{"master missing", wrap(keystore.ErrMasterMissing), DamageInternal},
			{"internal", leakyErr(errors.New("an error no table names")), DamageInternal},
			{"not found", wrap(keystore.ErrNotFound), ""},
			{"exists", wrap(keystore.ErrExists), ""},
			{"quota", wrap(keystore.ErrQuota), ""},
			{"rate limited", ErrRateLimited, ""},
			{"busy", ErrBusy, ""},
			{"log full", wrap(keystore.ErrLogFull), ""},
			{"refused by the socket", refusedf("x"), ""},
			{"invalid name", wrap(keystore.ErrInvalidName), ""},
			{"committed", fmt.Errorf("%w: the floor line was not written", keystore.ErrCommitted), ""},
			{"cancelled", wrap(fmt.Errorf("%w: %w", keystore.ErrCorrupt, context.Canceled)), ""},
			{"timed out", wrap(context.DeadlineExceeded), ""},
			{"ok", nil, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var c logCapture
				clock := &fixedClock{t: time.Unix(1_000_000, 0)}
				h, err := NewHandler(clock.Now,
					withOp(OpReadForExec, func(context.Context, Request) (Reply, error) { return Reply{}, tc.err }))
				if err != nil {
					t.Fatal(err)
				}
				h.log = c.logger()
				serveOne(t, h, hdr(t, OpReadForExec, entryOf(uidA, "a"), nil))
				clock.advance(DamageLogInterval)
				serveOne(t, h, hdr(t, OpReadForExec, "not a name", nil))
				recs := c.records(t)
				if tc.class == "" {
					if len(recs) != 0 {
						t.Fatalf("%v logged %v, want nothing", tc.err, recs)
					}
					return
				}
				if len(recs) != 2 {
					t.Fatalf("%v logged %v, want one line a request", tc.err, recs)
				}
				checkStoreErrorLine(t, recs[0], OpReadForExec, uidA, entryOf(uidA, "a"), tc.class, 0)
				// A name that is not one is not logged.
				checkStoreErrorLine(t, recs[1], OpReadForExec, uidA, "", tc.class, 0)
				out := c.bytes()
				for _, leak := range []string{string(secretValue[:6]), "4242", "0x7e"} {
					if bytes.Contains(out, []byte(leak)) {
						t.Fatalf("the server log carries %q from the error: %s", leak, out)
					}
				}
			})
		}
	})
	t.Run("the real store", func(t *testing.T) {
		var c logCapture
		r := newOpsRig(t, nil)
		h, err := NewOpsHandler(time.Now, r.b)
		if err != nil {
			t.Fatal(err)
		}
		h.log = c.logger()
		w := dialOps(t, h, uidA)
		for _, name := range []string{"a", "b"} {
			w.mustReply(t, hdr(t, OpPut, entryOf(uidA, name), nil), secretValue, nil)
		}
		// An absent entry is not-found, which is not logged.
		if code := codeOf(t, w.call(t, hdr(t, OpReadForExec, entryOf(uidA, "absent"), nil), nil)); code != CodeNotFound {
			t.Fatalf("a read of an absent entry: code %q, want not-found", code)
		}
		if recs := c.records(t); len(recs) != 0 {
			t.Fatalf("ordinary requests logged %v", recs)
		}

		// A version that does not authenticate: corrupt, internal.
		dir := filepath.Join(r.data, "server", "keystore", ".user", strconv.FormatUint(uint64(uidA), 10), "entries", "a")
		v1 := filepath.Join(dir, "v1")
		b, err := os.ReadFile(v1)
		if err != nil {
			t.Fatal(err)
		}
		b[len(b)/2] ^= 0xff
		if err := os.WriteFile(v1, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if code := codeOf(t, w.call(t, hdr(t, OpReadForExec, entryOf(uidA, "a"), nil), nil)); code != CodeInternal {
			t.Fatalf("a read of a corrupt entry: code %q, want internal", code)
		}
		recs := c.records(t)
		if len(recs) != 1 {
			t.Fatalf("a corrupt read logged %v, want one line", recs)
		}
		checkStoreErrorLine(t, recs[0], OpReadForExec, uidA, entryOf(uidA, "a"), DamageCorrupt, 0)

		// A floor line no key can be read from: the floor is damaged for
		// every key, so a put, which carries a value, is refused; a read,
		// another op, logs its own line.
		fp := filepath.Join(r.data, "keystore-logs", "floor", "keystore-user-floor.log")
		fb, err := os.ReadFile(fp)
		if err != nil {
			t.Fatal(err)
		}
		last := bytes.LastIndexByte(fb[:len(fb)-1], '\n')
		for i := last + 1; i < len(fb)-1; i++ {
			fb[i] = 'X'
		}
		if err := os.WriteFile(fp, fb, 0o600); err != nil {
			t.Fatal(err)
		}
		if code := codeOf(t, w.call(t, hdr(t, OpPut, entryOf(uidA, "c"), nil), secretValue)); code != CodeRefused {
			t.Fatalf("a put over floor damage: code %q, want refused", code)
		}
		recs = c.records(t)
		if len(recs) != 2 {
			t.Fatalf("logged %v, want two lines", recs)
		}
		checkStoreErrorLine(t, recs[1], OpPut, uidA, entryOf(uidA, "c"), DamageFloorDegraded, 0)
		out := c.bytes()
		if bytes.Contains(out, secretValue[:6]) {
			t.Fatalf("the server log holds the value: %s", out)
		}
		if bytes.Contains(out, []byte(strconv.Itoa(len(secretValue)))) {
			t.Fatalf("the server log holds the value's length, %d: %s", len(secretValue), out)
		}
	})
}

// Standing damage logs at most one line per uid, op and class each
// DamageLogInterval: the lines between are suppressed and counted on the
// key's next line; another op or class has its own key.
func TestStoreErrorLogBounded(t *testing.T) {
	var c logCapture
	clock := &fixedClock{t: time.Unix(1_000_000, 0)}
	corrupt := func(context.Context, Request) (Reply, error) { return Reply{}, keystore.ErrCorrupt }
	h, err := NewHandler(clock.Now, withOp(OpReadForExec, corrupt), withOp(OpList, corrupt))
	if err != nil {
		t.Fatal(err)
	}
	h.log = c.logger()
	read := hdr(t, OpReadForExec, entryOf(uidA, "a"), nil)
	for range 5 {
		serveOne(t, h, read)
		clock.advance(time.Second)
	}
	serveOne(t, h, hdr(t, OpList, "", nil))
	if recs := c.records(t); len(recs) != 2 {
		t.Fatalf("five reads and a list in 5 s logged %v, want the first read's line and the list's", recs)
	}
	clock.advance(DamageLogInterval)
	serveOne(t, h, read)
	recs := c.records(t)
	if len(recs) != 3 {
		t.Fatalf("logged %v, want a third line once the interval passed", recs)
	}
	checkStoreErrorLine(t, recs[0], OpReadForExec, uidA, entryOf(uidA, "a"), DamageCorrupt, 0)
	checkStoreErrorLine(t, recs[1], OpList, uidA, "", DamageCorrupt, 0)
	checkStoreErrorLine(t, recs[2], OpReadForExec, uidA, entryOf(uidA, "a"), DamageCorrupt, 4)
}

// One uid's standing damage never suppresses another uid's line: uid A's
// repeated damage leaves uid B's first line for the same op and class to
// pass, and each uid's later lines are counted against its own key.
func TestStoreErrorLogPerUID(t *testing.T) {
	var c logCapture
	clock := &fixedClock{t: time.Unix(1_000_000, 0)}
	corrupt := func(context.Context, Request) (Reply, error) { return Reply{}, keystore.ErrCorrupt }
	h, err := NewHandler(clock.Now, withOp(OpReadForExec, corrupt))
	if err != nil {
		t.Fatal(err)
	}
	h.log = c.logger()
	for range 5 {
		serveRequestAs(t, h, uidA, hdr(t, OpReadForExec, entryOf(uidA, "a"), nil))
		clock.advance(time.Second)
	}
	serveRequestAs(t, h, uidB, hdr(t, OpReadForExec, entryOf(uidB, "a"), nil))
	serveRequestAs(t, h, uidB, hdr(t, OpReadForExec, entryOf(uidB, "a"), nil))
	recs := c.records(t)
	if len(recs) != 2 {
		t.Fatalf("five reads by uid %d and two by uid %d logged %v, want one line each", uidA, uidB, recs)
	}
	checkStoreErrorLine(t, recs[0], OpReadForExec, uidA, entryOf(uidA, "a"), DamageCorrupt, 0)
	checkStoreErrorLine(t, recs[1], OpReadForExec, uidB, entryOf(uidB, "a"), DamageCorrupt, 0)
	clock.advance(DamageLogInterval)
	serveRequestAs(t, h, uidB, hdr(t, OpReadForExec, entryOf(uidB, "a"), nil))
	recs = c.records(t)
	if len(recs) != 3 {
		t.Fatalf("logged %v, want uid %d's second line", recs, uidB)
	}
	checkStoreErrorLine(t, recs[2], OpReadForExec, uidB, entryOf(uidB, "a"), DamageCorrupt, 1)
}

// The limiter's keys stay at most maxDamageKeys however many uids log: a
// new key past the cap evicts the one whose last line is the oldest, and
// passes.
func TestDamageLimiterBounded(t *testing.T) {
	var l damageLimiter
	start := time.Unix(1_000_000, 0)
	key := func(uid int) damageKey { return damageKey{uid: uint32(uid), op: OpReadForExec, class: DamageCorrupt} }
	for i := range 2 * maxDamageKeys {
		if ok, _ := l.pass(key(i), start.Add(time.Duration(i)*time.Millisecond)); !ok {
			t.Fatalf("uid %d's first line was suppressed", i)
		}
		if n := len(l.keys); n > maxDamageKeys {
			t.Fatalf("the limiter holds %d keys, want at most %d", n, maxDamageKeys)
		}
	}
	if _, ok := l.keys[key(maxDamageKeys-1)]; ok {
		t.Fatalf("uid %d's key outlived %d newer keys", maxDamageKeys-1, maxDamageKeys)
	}
	if _, ok := l.keys[key(2*maxDamageKeys-1)]; !ok {
		t.Fatal("the newest key was evicted")
	}
}

// The supervisor gives its logger to the handler, so the store errors that
// are damage reach the server's log, not the process default.
func TestSupervisorLogReceivesDamage(t *testing.T) {
	var c logCapture
	corrupt := func(context.Context, Request) (Reply, error) { return Reply{}, keystore.ErrCorrupt }
	h, err := NewHandler(time.Now, withOp(OpReadForExec, corrupt))
	if err != nil {
		t.Fatal(err)
	}
	r := &supRig{
		ck:    &startChecks{euid: serviceUID, servers: 1},
		creds: &panickyCreds{fakeCreds: &fakeCreds{peers: make(map[net.Conn]PeerCred)}},
		box:   &fakeSandbox{sandboxed: make(map[AuditToken]bool), fail: make(map[AuditToken]bool)},
		log:   &logBuf{},
		h:     h,
	}
	cfg := r.config()
	cfg.Log = c.logger()
	if _, err := NewSupervisor(cfg); err != nil {
		t.Fatal(err)
	}
	serveOne(t, h, hdr(t, OpReadForExec, entryOf(uidA, "a"), nil))
	recs := c.records(t)
	if len(recs) != 1 {
		t.Fatalf("the supervisor's logger received %v, want the damage line", recs)
	}
	checkStoreErrorLine(t, recs[0], OpReadForExec, uidA, entryOf(uidA, "a"), DamageCorrupt, 0)
}

// damageCodes is the reply each class is logged beside (outcomeOf).
var damageCodes = map[string]Code{
	DamageOrphanVersion:     CodeRefused,
	DamageFloorDegraded:     CodeRefused,
	DamageFloorRecordsEntry: CodeInternal,
	DamageCorrupt:           CodeInternal,
	DamageInternal:          CodeInternal,
}

// floorDegradedErr is a real store's refusal of a put over a floor line no
// key can be read from (keystore.FloorDegraded).
func floorDegradedErr(t *testing.T) error {
	t.Helper()
	r := newStartedBridge(t, nil)
	p := Peer{UID: uidA, PID: 1}
	if _, err := r.b.Put(t.Context(), p, entryOf(uidA, "a"), keystore.KindOpaque, []byte("v")); err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(r.data, "keystore-logs", "floor", "keystore-user-floor.log")
	fb, err := os.ReadFile(fp)
	if err != nil {
		t.Fatal(err)
	}
	last := bytes.LastIndexByte(fb[:len(fb)-1], '\n')
	for i := last + 1; i < len(fb)-1; i++ {
		fb[i] = 'X'
	}
	if err := os.WriteFile(fp, fb, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = r.b.Put(t.Context(), p, entryOf(uidA, "c"), keystore.KindOpaque, []byte("v"))
	if !keystore.FloorDegraded(err) {
		t.Fatalf("a put over floor damage = %v, want FloorDegraded", err)
	}
	return err
}

// damageClass and outcomeOf judge every error in one order: each error
// kind either function reads has its pinned reply and class, and over
// every pair of them joined in one chain the class is one logged beside
// the reply outcomeOf gives, and every internal reply that is not a
// cancelled or timed-out request is logged.
func TestDamageClassAgreesWithOutcome(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("user scope op: %w", err) }
	kinds := []struct {
		name  string
		err   error
		code  Code
		class string
	}{
		{"committed", fmt.Errorf("%w: the floor line was not written", keystore.ErrCommitted), "", ""},
		{"socket busy", ErrBusy, CodeBusy, ""},
		{"rate limited", ErrRateLimited, CodeRateLimited, ""},
		{"request refused", refusedf("x"), CodeRefused, ""},
		{"log full", wrap(keystore.ErrLogFull), CodeLogFull, ""},
		{"not found", wrap(keystore.ErrNotFound), CodeNotFound, ""},
		{"version not found", wrap(keystore.ErrVersionNotFound), CodeNotFound, ""},
		{"scope absent", wrap(keystore.ErrScopeAbsent), CodeNotFound, ""},
		{"quota", wrap(keystore.ErrQuota), CodeQuota, ""},
		{"owner changed", wrap(keystore.ErrScopeOwnerChanged), CodeScopeOwnerChanged, ""},
		{"owner unknown", wrap(keystore.ErrScopeOwnerUnknown), CodeScopeOwnerUnknown, ""},
		{"exists", wrap(keystore.ErrExists), CodeRefused, ""},
		{"invalid name", wrap(keystore.ErrInvalidName), CodeRefused, ""},
		{"kind mismatch", wrap(keystore.ErrKindMismatch), CodeRefused, ""},
		{"typed credential", wrap(keystore.ErrTypedCredential), CodeRefused, ""},
		{"rewrap in progress", wrap(keystore.ErrRewrapInProgress), CodeRefused, ""},
		{"floor degraded", floorDegradedErr(t), CodeRefused, DamageFloorDegraded},
		{"orphan version", wrap(fmt.Errorf("%w: %w", keystore.ErrCorrupt, keystore.ErrOrphanVersion)), CodeRefused, DamageOrphanVersion},
		{"corrupt", wrap(keystore.ErrCorrupt), CodeInternal, DamageCorrupt},
		{"floor records entry", wrap(keystore.ErrFloorRecordsEntry), CodeInternal, DamageFloorRecordsEntry},
		{"master missing", wrap(keystore.ErrMasterMissing), CodeInternal, DamageInternal},
		{"master untrusted", wrap(keystore.ErrMasterUntrusted), CodeInternal, DamageInternal},
		{"kind unsupported", wrap(keystore.ErrKindUnsupported), CodeInternal, DamageInternal},
		{"cancelled", context.Canceled, CodeInternal, ""},
		{"timed out", context.DeadlineExceeded, CodeInternal, ""},
		{"unknown", errors.New("x"), CodeInternal, DamageInternal},
	}
	for _, k := range kinds {
		if code, _ := outcomeOf(k.err); code != k.code {
			t.Errorf("%s: outcomeOf = %q, want %q", k.name, code, k.code)
		}
		if class := damageClass(k.err); class != k.class {
			t.Errorf("%s: damageClass = %q, want %q", k.name, class, k.class)
		}
	}
	cancelled := func(err error) bool {
		return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}
	for _, a := range kinds {
		for _, b := range kinds {
			err := errors.Join(a.err, b.err)
			code, _ := outcomeOf(err)
			class := damageClass(err)
			if class != "" && damageCodes[class] != code {
				t.Errorf("%s with %s: class %q is logged beside %q, but the reply is %q", a.name, b.name, class, damageCodes[class], code)
			}
			if code == CodeInternal && class == "" && !cancelled(err) {
				t.Errorf("%s with %s: an internal reply logs no class", a.name, b.name)
			}
		}
	}
}
