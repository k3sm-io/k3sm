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

// A floor line at sequence 0 is present: floor --rebuild writes one for an
// entry with no authenticated pointer, so it keeps the entry damage. The
// reader records the key on its first line even at sequence 0, counts it
// against the key bound and lists its generation as live, so an rm of the
// name buries it.
func TestFloorSeqZeroLineIsPresent(t *testing.T) {
	s, _, u := fileLogScope(t)
	l := s.userFloor.(*fileFloorLog).log
	if err := s.userFloor.check(); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	keys := l.state.keys
	l.mu.Unlock()
	line, err := floorLine("user/1001", "zero", guid(0xC0), 0)
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, line)
	if err := s.userFloor.check(); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	got, inSeq := l.state.keys, false
	_, inSeq = l.state.maxSeq[floorKey{"user/1001", "zero", guid(0xC0)}]
	l.mu.Unlock()
	if got != keys+1 || !inSeq {
		t.Fatalf("after a sequence-0 line: %d keys (was %d), recorded %v; want it counted and recorded", got, keys, inSeq)
	}
	live, err := s.userFloor.liveGens("user/1001", "zero")
	if err != nil || len(live) != 1 || live[0] != guid(0xC0) {
		t.Fatalf("liveGens after a sequence-0 line: %x, %v", live, err)
	}
	if err := u.Delete(context.Background(), "user/1001/zero"); err != nil {
		t.Fatalf("rm of an absent name present at sequence 0: %v, want it buried", err)
	}
	if _, err := s.userFloor.floor("user/1001", "zero", guid(0xC0)); err != errFloorBuried {
		t.Fatalf("floor after rm: %v, want errFloorBuried", err)
	}
}
