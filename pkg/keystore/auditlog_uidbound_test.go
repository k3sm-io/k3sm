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
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// The audit reader's per-uid map of bytes charged past the hard cap is
// bounded: forged lines past the cap charged to more distinct uids than
// maxChargedUIDs are sticky damage, and the map grows no further.
func TestAuditReaderBoundsChargedUIDs(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	size := int64(len(readLog(t, s, auditLogName)))
	s.logSoftCap, s.logHardCap = size, size
	var forged bytes.Buffer
	for i := range maxChargedUIDs + 50 {
		b, err := marshalAuditLine(auditLine{op: "rm", scope: userScopeOf(uint32(minScopeUID + i)), name: "x", result: "ok"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		forged.Write(b)
		if b[len(b)-1] != '\n' {
			forged.WriteByte('\n')
		}
	}
	appendLogBytes(t, s, auditLogName, forged.Bytes())
	if _, _, err := s.CheckLogBounds(ctx); !errors.Is(err, errLogTooManyUIDs) || !errors.Is(err, errLogTooLarge) {
		t.Fatalf("CheckLogBounds: %v, want errLogTooManyUIDs", err)
	}
	a := s.auditSink.(*fileAuditLog).log
	a.mu.Lock()
	n := len(a.state.pastCap)
	a.mu.Unlock()
	if n > maxChargedUIDs {
		t.Fatalf("the reader charged %d distinct uids, past its bound of %d", n, maxChargedUIDs)
	}
	// A second read is the same sticky damage, with no growth.
	if _, _, err := s.CheckLogBounds(ctx); !errors.Is(err, errLogTooManyUIDs) {
		t.Fatalf("the second CheckLogBounds: %v, want errLogTooManyUIDs", err)
	}
	a.mu.Lock()
	if m := len(a.state.pastCap); m != n {
		t.Errorf("the map grew from %d to %d uids on a second read", n, m)
	}
	a.mu.Unlock()
}
