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
	"strings"
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
// the op, the uid, the entry when want names one, the error text, and no
// other field.
func checkStoreErrorLine(t *testing.T, rec map[string]any, op string, uid uint32, entry string) {
	t.Helper()
	keys := []string{"error", "level", "msg", "op", "uid"}
	if entry != "" {
		keys = append(keys, "entry")
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
	if rec["level"] != "WARN" || rec["op"] != op || rec["uid"] != float64(uid) || (entry != "" && rec["entry"] != entry) {
		t.Errorf("log line %v, want Warn for %s by uid %d naming %q", rec, op, uid, entry)
	}
	if s, _ := rec["error"].(string); s == "" {
		t.Errorf("log line %v carries no error text", rec)
	}
}

// The server logs the store errors that are damage, at Warn, with the op,
// the peer's uid, the entry when the request named a valid one, and the
// error's text: an error answered internal, a corrupt record, a floor that
// is stale or records a deleted entry, an orphan version, the floor's
// damage and the scope's quarantine. The ordinary outcomes, which have
// their audit lines, are not logged, and no line carries a value or its
// length.
func TestStoreErrorLogged(t *testing.T) {
	t.Run("each outcome", func(t *testing.T) {
		wrap := func(err error) error { return fmt.Errorf("user scope exec-read: %w", err) }
		for _, tc := range []struct {
			name   string
			err    error
			logged bool
		}{
			{"corrupt", wrap(keystore.ErrCorrupt), true},
			{"floor stale", wrap(fmt.Errorf("%w: the current pointer is older than the floor records", keystore.ErrCorrupt)), true},
			{"floor records a deleted entry", wrap(keystore.ErrFloorRecordsEntry), true},
			{"orphan version", wrap(fmt.Errorf("%w: %w: rm and put it again", keystore.ErrCorrupt, keystore.ErrOrphanVersion)), true},
			{"master missing", wrap(keystore.ErrMasterMissing), true},
			{"internal", errors.New("an error no table names"), true},
			{"not found", wrap(keystore.ErrNotFound), false},
			{"exists", wrap(keystore.ErrExists), false},
			{"quota", wrap(keystore.ErrQuota), false},
			{"rate limited", ErrRateLimited, false},
			{"busy", ErrBusy, false},
			{"log full", wrap(keystore.ErrLogFull), false},
			{"refused by the socket", refusedf("x"), false},
			{"invalid name", wrap(keystore.ErrInvalidName), false},
			{"committed", fmt.Errorf("%w: the floor line was not written", keystore.ErrCommitted), false},
			{"ok", nil, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var c logCapture
				h, err := NewHandler(time.Now,
					withOp(OpReadForExec, func(context.Context, Request) (Reply, error) { return Reply{}, tc.err }))
				if err != nil {
					t.Fatal(err)
				}
				h.log = c.logger()
				for _, header := range []string{
					hdr(t, OpReadForExec, entryOf(uidA, "a"), nil),
					hdr(t, OpReadForExec, "not a name", nil),
				} {
					var in bytes.Buffer
					in.Write(frameBytes(t, Frame{Type: TypeHello, Header: []byte(helloV1)}))
					in.Write(frameBytes(t, Frame{Type: TypeRequest, Header: []byte(header)}))
					conn := &recordingConn{in: bytes.NewReader(in.Bytes())}
					if err := h.Serve(t.Context(), conn, Peer{UID: uidA}); err != nil {
						t.Fatalf("Serve: %v", err)
					}
				}
				recs := c.records(t)
				if !tc.logged {
					if len(recs) != 0 {
						t.Fatalf("%v logged %v, want nothing", tc.err, recs)
					}
					return
				}
				if len(recs) != 2 {
					t.Fatalf("%v logged %v, want one line a request", tc.err, recs)
				}
				checkStoreErrorLine(t, recs[0], OpReadForExec, uidA, entryOf(uidA, "a"))
				// A name that is not one is not logged.
				checkStoreErrorLine(t, recs[1], OpReadForExec, uidA, "")
				if !strings.Contains(recs[0]["error"].(string), tc.err.Error()) {
					t.Errorf("log line %v, want the error text %q", recs[0], tc.err)
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
		checkStoreErrorLine(t, recs[0], OpReadForExec, uidA, entryOf(uidA, "a"))
		if s := recs[0]["error"].(string); !strings.Contains(s, "corrupt") {
			t.Errorf("the corrupt read's line %q does not say corrupt", s)
		}

		// A floor line no key can be read from: the floor is damaged for
		// every key, so a put, which carries a value, and a read are
		// refused.
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
		if code := codeOf(t, w.call(t, hdr(t, OpReadForExec, entryOf(uidA, "b"), nil), nil)); code != CodeRefused {
			t.Fatalf("a read over floor damage: code %q, want refused", code)
		}
		recs = c.records(t)
		if len(recs) != 3 {
			t.Fatalf("logged %v, want three lines", recs)
		}
		checkStoreErrorLine(t, recs[1], OpPut, uidA, entryOf(uidA, "c"))
		checkStoreErrorLine(t, recs[2], OpReadForExec, uidA, entryOf(uidA, "b"))
		for _, rec := range recs[1:] {
			if s := rec["error"].(string); !strings.Contains(s, "floor") {
				t.Errorf("the floor-damage line %q does not name the floor", s)
			}
		}
		out := c.bytes()
		if bytes.Contains(out, secretValue[:6]) {
			t.Fatalf("the server log holds the value: %s", out)
		}
		if bytes.Contains(out, []byte(strconv.Itoa(len(secretValue)))) {
			t.Fatalf("the server log holds the value's length, %d: %s", len(secretValue), out)
		}
	})
}
