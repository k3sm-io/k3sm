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

// panicAt is a step seam that panics once, at the step named at, or at
// the first step when at is "".
func panicAt(at string) func(string) error {
	done := false
	return func(name string) error {
		if done || (at != "" && name != at) {
			return nil
		}
		done = true
		panic("injected panic at " + name)
	}
}

// A panic inside an operation's store-lock hold never leaves an ok audit
// line as the operation's last word: its deferred audit saw a nil error,
// so before the in-flight check a rotate, an rm and a withdraw wrote an
// ok line for an operation that never finished, and a put, a minting put
// and a deliver left their write-ahead ok line standing alone. A
// revocation (rotate, rm, withdraw) writes no line and is counted
// unaudited; a grant (put, a minting put, deliver), whose ok line was
// written before its first write, gets the second line the design gives a
// commit that fails after the line, naming "error", and is not counted.
// The panic still reaches the caller, the socket's listener, which
// recovers it.
func TestPanicInHoldWritesNoOKLine(t *testing.T) {
	d := testDelivery(1)
	for _, tc := range []struct {
		name, op, step string
		grant          bool
		setup          func(t *testing.T, u *UserScope)
		run            func(ctx context.Context, s *FileStore, u *UserScope)
	}{
		{"rotate at write v2", "rotate", "write v2", false, nil, func(ctx context.Context, _ *FileStore, u *UserScope) {
			_, _ = u.Rotate(ctx, "user/1001/a", []byte("two"))
		}},
		{"rotate at sync v2", "rotate", "sync v2", false, nil, func(ctx context.Context, _ *FileStore, u *UserScope) {
			_, _ = u.Rotate(ctx, "user/1001/a", []byte("two"))
		}},
		{"rm at delete a", "rm", "delete a", false, nil, func(ctx context.Context, _ *FileStore, u *UserScope) {
			_ = u.Delete(ctx, "user/1001/a")
		}},
		{"put at write v1", "put", "write v1", true, nil, func(ctx context.Context, _ *FileStore, u *UserScope) {
			_, _ = u.Put(ctx, "user/1001/b", KindOpaque, []byte("b"))
		}},
		{"a minting put at its first write", "put", "", true, nil, func(ctx context.Context, s *FileStore, _ *UserScope) {
			fresh, err := s.UserScope(1002)
			if err != nil {
				panic(err)
			}
			_, _ = fresh.Put(ctx, "user/1002/b", KindOpaque, []byte("b"))
		}},
		{"deliver at its first write", "deliver", "", true, nil, func(ctx context.Context, _ *FileStore, u *UserScope) {
			_ = u.Deliver(ctx, exportDelivery(d))
		}},
		{"withdraw at its first write", "withdraw", "", false, func(t *testing.T, u *UserScope) {
			if err := u.Deliver(context.Background(), exportDelivery(d)); err != nil {
				t.Fatalf("Deliver: %v", err)
			}
		}, func(ctx context.Context, _ *FileStore, u *UserScope) {
			_ = u.Withdraw(ctx, d.uid)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newMasteredStore(t)
			fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1), 1002: guid(0xA2)})
			u := userScope(t, s, 1001)
			userPut(t, u, "user/1001/a", "one")
			userPut(t, u, "user/1001/token", "a value")
			if tc.setup != nil {
				tc.setup(t, u)
			}
			_, audit := userLogs(s)
			audit.mu.Lock()
			before := len(audit.lines)
			audit.mu.Unlock()
			unaudited := s.UnauditedOps()
			s.step = panicAt(tc.step)
			func() {
				defer func() {
					if recover() == nil {
						t.Fatalf("the %s did not reach its step %q", tc.op, tc.step)
					}
				}()
				tc.run(context.Background(), s, u)
			}()
			s.step = func(string) error { return nil }
			audit.mu.Lock()
			var lines []auditLine
			for _, l := range audit.lines[before:] {
				if l.op == tc.op {
					lines = append(lines, l)
				}
			}
			audit.mu.Unlock()
			counted := s.UnauditedOps() - unaudited
			if !tc.grant {
				if len(lines) != 0 || counted != 1 {
					t.Fatalf("a %s that panicked in its hold wrote %+v and counted %d unaudited, want no line and 1", tc.op, lines, counted)
				}
				return
			}
			if len(lines) != 2 || lines[0].result != auditResultOK || lines[1].result != "error" || counted != 0 {
				t.Fatalf("a %s that panicked after its ok line wrote %+v and counted %d unaudited, want ok then error and 0", tc.op, lines, counted)
			}
		})
	}
}
