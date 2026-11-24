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
	var in bytes.Buffer
	in.Write(frameBytes(t, Frame{Type: TypeHello, Header: []byte(helloV1)}))
	in.Write(frameBytes(t, Frame{Type: TypeRequest, Header: []byte(header)}))
	if err := h.Serve(t.Context(), &recordingConn{in: bytes.NewReader(in.Bytes())}, Peer{UID: uidA}); err != nil {
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

// Standing damage logs at most one line per op and class each
// DamageLogInterval: the lines between are suppressed and counted on the
// pair's next line; another op or class has its own pair.
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
	var l damageLimiter
	for i := range 2 * maxDamageKeys {
		l.pass(damageKey{strconv.Itoa(i), DamageCorrupt}, clock.Now())
	}
	if n := len(l.keys); n != maxDamageKeys {
		t.Fatalf("the limiter holds %d pairs, want at most %d", n, maxDamageKeys)
	}
}
