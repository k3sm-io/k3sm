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

// A configuration whose reader's bounds sit below what an existing log
// holds is refused at store open, with the figures in that root-only error;
// one that holds the log opens.
func TestCheckLogBoundsRefusesShrunkCaps(t *testing.T) {
	ctx := context.Background()
	s, server, _ := fileLogScope(t)
	if _, _, err := s.CheckLogBounds(ctx); err != nil {
		t.Fatalf("store open at the default caps: %v", err)
	}
	line, err := floorLine("user/1001", "token", entryGeneration(t, server, "token"), 1)
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, bytes.Repeat(line, (4<<20)/len(line)))
	size := int64(len(readLog(t, s, userFloorLogName)))
	s.logSoftCap, s.logHardCap, s.logRevokeBudget = 1, 1, minLogRevokeBudget
	_, _, err = s.CheckLogBounds(ctx)
	if !errors.Is(err, errInvalidConfig) || !errors.Is(err, errLogBoundsBelowLog) {
		t.Fatalf("store open with caps below the floor's size: %v, want errLogBoundsBelowLog", err)
	}
	if !strings.Contains(err.Error(), strconv.FormatInt(size, 10)) {
		t.Fatalf("the root-only open error %q does not name the floor's size %d", err, size)
	}
}

// A floor holding more keys than a configured key bound is refused at
// store open.
func TestCheckLogBoundsRefusesKeysPastBound(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	l := syncedFloor(t, s)
	l.mu.Lock()
	l.maxKeys = l.state.keys - 1
	l.mu.Unlock()
	if _, _, err := s.CheckLogBounds(ctx); !errors.Is(err, errLogBoundsBelowLog) {
		t.Fatalf("store open with a key bound below the floor's keys: %v, want errLogBoundsBelowLog", err)
	}
}
