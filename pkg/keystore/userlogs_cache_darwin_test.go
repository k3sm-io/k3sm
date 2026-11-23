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
	"testing"

	"golang.org/x/sys/unix"
)

// A file at the same (dev, ino) with another birth time is another file,
// so what was read of the first is dropped. (x/sys spells st_birthtimespec
// Btim.)
func TestLogSyncForgetsOnNewBirthTime(t *testing.T) {
	s, _, u := fileLogScope(t)
	_, last, _ := cachedFloor(t, s, u)
	l := s.userFloor.(*fileFloorLog).log
	f, st, err := l.open(unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	spoilLineAt(t, s, last)
	if state := syncFloor(t, l, st); state.bad != nil || state.damaged() != 0 {
		t.Fatalf("the same file read again: %v, %d damaged (the earlier line is not read again)", state.bad, state.damaged())
	}
	st.Btim.Nsec++
	if state := syncFloor(t, l, st); state.damaged() != 1 {
		t.Fatal("a file with a new birth time was not read again: the spoiled line was not seen")
	}
}
