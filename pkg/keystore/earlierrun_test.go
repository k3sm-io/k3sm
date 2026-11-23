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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A verb that fails after its swap committed returns a Committed error
// with its report: a rebuild's drop counts are still there.
func TestSwapFailureAfterCommitIsCommitted(t *testing.T) {
	for _, at := range []string{swapStepClean, swapStepEnd} {
		t.Run(at, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			appendLogBytes(t, s, userFloorLogName, []byte("not a floor line\n"))
			rep, err := s.RebuildFloor(context.Background(), &stepCrash{at: at})
			if !Committed(err) {
				t.Fatalf("a rebuild failing at %s after the swap: %v, want Committed", at, err)
			}
			if rep.Dropped != 1 {
				t.Fatalf("the committed rebuild reports %d dropped lines, want 1", rep.Dropped)
			}
			if _, err := s.RotateAudit(context.Background(), &stepCrash{at: at}, false); !Committed(err) {
				t.Fatalf("a rotate failing at %s after the swap: %v, want Committed", at, err)
			}
		})
	}
}

// A committed run of one verb, left in the marker, is reported by a run of
// the other verb before it replaces the marker: through the context, with
// the saved report, and as an audit line (op the earlier verb, result
// committed).
func TestEarlierCommittedRunReported(t *testing.T) {
	for _, first := range maintVerbs {
		t.Run(first.name, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			appendLogBytes(t, s, userFloorLogName, []byte("not a floor line\n"))
			if err := first.run(s, &stepCrash{at: swapStepEnd}); !Committed(err) {
				t.Fatalf("%s failing at end: %v, want Committed", first.name, err)
			}
			var got []EarlierRun
			ctx := WithEarlierRun(context.Background(), func(r EarlierRun) { got = append(got, r) })
			var op string
			if first.log == userFloorLogName {
				op = verbRebuild
				if _, err := s.RotateAudit(ctx, &inoRecorder{}, false); err != nil {
					t.Fatalf("rotate after a committed rebuild: %v", err)
				}
			} else {
				op = verbRotate
				if _, err := s.RebuildFloor(ctx, &inoRecorder{}); err != nil {
					t.Fatalf("rebuild after a committed rotate: %v", err)
				}
			}
			if len(got) != 1 || got[0].Verb != op || got[0].AuditErr != nil {
				t.Fatalf("the earlier run reported: %+v, want one %s with its audit line written", got, op)
			}
			if op == verbRebuild && got[0].Report["dropped"] != 1 {
				t.Fatalf("the earlier rebuild's report: %v, want dropped=1", got[0].Report)
			}
			msg := got[0].String()
			if !strings.HasPrefix(msg, "an earlier "+verbDisplay(op)+" committed and was not reported: ") {
				t.Fatalf("the stderr line: %q", msg)
			}
			// The audit line was written before the marker was replaced: a
			// rotate carries it into .1, a rebuild leaves it in the live log.
			logs := readLog(t, s, auditLogName)
			if one, err := os.ReadFile(filepath.Join(s.dataRoot, logsDirName, auditDirName, auditArchiveName(1))); err == nil {
				logs = append(logs, one...)
			}
			found := false
			for l := range bytes.SplitSeq(logs, []byte("\n")) {
				if bytes.Contains(l, []byte(op)) && bytes.Contains(l, []byte(auditResultCommitted)) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %s committed audit line in %q", op, logs)
			}
		})
	}
}
