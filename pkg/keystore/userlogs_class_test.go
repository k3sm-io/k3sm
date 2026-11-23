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
	"regexp"
	"strings"
	"testing"
)

// Past the hard cap a floor line that does not revoke draws on no
// revocation budget and is refused; a revocation's line is written.
func TestFloorLineBudgetFollowsClass(t *testing.T) {
	s, _, _ := fileLogScope(t)
	s.logSoftCap, s.logHardCap = 1, 1
	err := s.userFloor.append("user/1001", "other", guid(0xB1), 1, false)
	if !errors.Is(err, ErrLogFull) {
		t.Fatalf("a non-revoking floor line past the hard cap: %v, want ErrLogFull", err)
	}
	if err := s.userFloor.append("user/1001", "other", guid(0xB1), 1, true); err != nil {
		t.Fatalf("a revocation's floor line past the hard cap: %v, want it written", err)
	}
}

// ErrLogFull's texts name no size, key count, cap or uid: they reach the
// socket, and the numbers are root's to read with doctor.
func TestLogFullTextNamesNoNumbers(t *testing.T) {
	ctx := context.Background()
	digits := regexp.MustCompile(`[0-9]`)
	check := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, ErrLogFull) {
			t.Fatalf("%v, want ErrLogFull", err)
		}
		if digits.MatchString(strings.ReplaceAll(err.Error(), "k3sm", "")) {
			t.Fatalf("the ErrLogFull text %q names a number", err)
		}
	}
	t.Run("hard cap", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		s.logSoftCap, s.logHardCap = 1, 1
		_, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v"))
		check(t, err)
	})
	t.Run("key bound", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		l := s.userFloor.(*fileFloorLog).log
		if err := s.userFloor.check(); err != nil {
			t.Fatal(err)
		}
		l.mu.Lock()
		l.maxKeys = l.state.keys
		l.mu.Unlock()
		_, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v"))
		check(t, err)
	})
	t.Run("revocation budget", func(t *testing.T) {
		s, server, u := fileLogScope(t)
		s.logSoftCap, s.logHardCap = 1, 1
		s.logRevokeBudget = minLogRevokeBudget
		// Spend uid 1001's budget with lines past the hard cap that add no
		// key.
		line, err := floorLine("user/1001", "token", entryGeneration(t, server, "token"), 1)
		if err != nil {
			t.Fatal(err)
		}
		appendLogBytes(t, s, userFloorLogName, bytes.Repeat(line, minLogRevokeBudget/len(line)+1))
		check(t, u.Delete(ctx, "user/1001/token"))
	})
}
