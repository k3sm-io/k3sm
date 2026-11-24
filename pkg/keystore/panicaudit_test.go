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

// A panic inside a rotate's or an rm's store-lock hold writes no audit
// line for the operation: its deferred append saw a nil error, so before
// the gap was counted it wrote an ok line for an operation that never
// finished. The operation is counted unaudited instead, and the panic
// still reaches the caller, the socket's listener, which recovers it.
func TestPanicInHoldWritesNoOKLine(t *testing.T) {
	for _, tc := range []struct{ op, step string }{
		{"rotate", "write v2"},
		{"rotate", "sync v2"},
		{"rm", "delete a"},
	} {
		t.Run(tc.op+" at "+tc.step, func(t *testing.T) {
			s, u := rotateScope(t)
			_, audit := userLogs(s)
			audit.mu.Lock()
			before := len(audit.lines)
			audit.mu.Unlock()
			s.step = failUsageStep(tc.step, true)
			func() {
				defer func() {
					if recover() == nil {
						t.Fatalf("the %s did not reach its %q step", tc.op, tc.step)
					}
				}()
				ctx := context.Background()
				if tc.op == "rotate" {
					_, _ = u.Rotate(ctx, "user/1001/a", []byte("two"))
				} else {
					_ = u.Delete(ctx, "user/1001/a")
				}
			}()
			audit.mu.Lock()
			lines := append([]auditLine(nil), audit.lines[before:]...)
			audit.mu.Unlock()
			for _, l := range lines {
				if l.op == tc.op {
					t.Fatalf("a %s that panicked at %q wrote the audit line %+v", tc.op, tc.step, l)
				}
			}
			if n := s.UnauditedOps(); n != 1 {
				t.Fatalf("UnauditedOps = %d after a %s that panicked in its hold, want 1", n, tc.op)
			}
		})
	}
}
