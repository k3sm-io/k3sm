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
	"os"
	"testing"
)

// A foreign writer's unterminated fragment that lands between any check
// of the tail and the server's write cannot glue to the server's line:
// every append leads with a newline, so the fragment is one damaged line
// and every server line parses, in both logs.
func TestForeignFragmentBeforeWriteIsOwnLine(t *testing.T) {
	s, server, u := fileLogScope(t)
	fragment := []byte("user/1001 foreign")
	race := func(f *os.File, b []byte) (int, error) {
		if _, err := f.Write(fragment); err != nil {
			return 0, err
		}
		return f.Write(b)
	}
	s.userFloor.(*fileFloorLog).log.write = race
	s.auditSink.(*fileAuditLog).log.write = race
	userPut(t, u, "user/1001/raced", "v")
	gen := entryGeneration(t, server, "raced")
	if seq, err := s.userFloor.floor("user/1001", "raced", gen); err != nil || seq != 1 {
		t.Fatalf("the floor line written after a foreign fragment: %d, %v; want it read at sequence 1", seq, err)
	}
	if n := floorDamage(t, s); n != 1 {
		t.Fatalf("floor damage after one foreign fragment is %d, want 1", n)
	}
	frags := 0
	for _, line := range splitLines(readLog(t, s, auditLogName)) {
		if len(line) == 0 {
			continue
		}
		if string(line) == string(fragment) {
			frags++
			continue
		}
		if _, err := parseAuditLine(line); err != nil {
			t.Fatalf("an audit line written after a foreign fragment does not parse: %q: %v", line, err)
		}
	}
	if frags == 0 {
		t.Fatal("no foreign fragment stands as a line of its own in the audit log")
	}
}

// nonEmptyLines is splitLines without the empty lines, each append's
// leading newline.
func nonEmptyLines(b []byte) [][]byte {
	var out [][]byte
	for _, l := range splitLines(b) {
		if len(l) > 0 {
			out = append(out, l)
		}
	}
	return out
}

// splitLines is b's lines without their newlines; a last line with none is
// kept.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
