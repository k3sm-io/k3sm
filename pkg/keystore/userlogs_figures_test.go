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
	"strconv"
	"strings"
	"testing"
)

// The log errors a socket caller can see name no figure: not the free
// bytes of a nearly full volume, not the size of a log past the reader's
// bound, and not the byte offset of a floor line that does not parse.
func TestLogErrorsNameNoFigures(t *testing.T) {
	ctx := context.Background()
	t.Run("no space", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		s.userFloor.(*fileFloorLog).log.freeSpace = func(int) (uint64, error) { return 777777, nil }
		_, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v"))
		if !errors.Is(err, errLogNoSpace) || strings.Contains(err.Error(), "777777") {
			t.Fatalf("put on a nearly full volume: %v, want errLogNoSpace naming no free bytes", err)
		}
	})
	t.Run("too large", func(t *testing.T) {
		s, server, u := fileLogScope(t)
		line, err := floorLine("user/1001", "token", entryGeneration(t, server, "token"), 1)
		if err != nil {
			t.Fatal(err)
		}
		appendLogBytes(t, s, userFloorLogName, bytes.Repeat(line, (2<<20)/len(line)))
		size := len(readLog(t, s, userFloorLogName))
		s.logSoftCap, s.logHardCap, s.logRevokeBudget = 1, 1, 1
		_, _, err = u.Current(ctx, "user/1001/token")
		if !errors.Is(err, errFloorLogMalformed) || strings.Contains(err.Error(), strconv.Itoa(size)) || strings.Contains(err.Error(), strconv.FormatInt(s.logReadBound(), 10)) {
			t.Fatalf("current over a floor past the reader's bound: %v, want it refused naming no size", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		appendLogBytes(t, s, userFloorLogName, []byte("not a floor line\n"))
		_, _, err := u.Current(ctx, "user/1001/token")
		if !errors.Is(err, errFloorLogMalformed) || strings.Contains(err.Error(), "at byte") {
			t.Fatalf("current over a malformed floor: %v, want it refused naming no offset", err)
		}
		l := s.userFloor.(*fileFloorLog).log
		l.mu.Lock()
		at := l.state.badAt
		l.mu.Unlock()
		if want := int64(len(readLog(t, s, userFloorLogName)) - len("not a floor line\n")); at != want {
			t.Fatalf("the kept offset is %d, want %d", at, want)
		}
	})
}
