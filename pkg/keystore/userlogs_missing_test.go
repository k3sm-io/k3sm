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
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// With user scopes present, a missing log names the matched-set restore,
// never install: a floor install created now would lower every scope's.
func TestLogMissingWithScopesNamesRestore(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	if err := os.Remove(filepath.Join(s.dataRoot, logsDirName, userFloorLogName)); err != nil {
		t.Fatal(err)
	}
	_, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v"))
	if !errors.Is(err, errLogMissing) || strings.Contains(err.Error(), "install") || !strings.Contains(err.Error(), "matched set") {
		t.Fatalf("put with user scopes and no floor: %v, want errLogMissing naming the matched-set restore, not install", err)
	}
}

// checkConfig bounds the caps from above, so logReadBound cannot overflow.
func TestCheckConfigBoundsCapsAbove(t *testing.T) {
	for _, tc := range []struct {
		name               string
		soft, hard, revoke int64
		ok                 bool
	}{
		{"at the bounds", maxLogHardCap, maxLogHardCap, maxLogRevokeBudget, true},
		{"hard cap past its bound", 1, maxLogHardCap + 1, 1, false},
		{"hard cap at MaxInt64", 1, math.MaxInt64, 1, false},
		{"revocation budget past its bound", 1, 1, maxLogRevokeBudget + 1, false},
		{"revocation budget overflowing the read bound", 1, 1, math.MaxInt64 / 512, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			s.logSoftCap, s.logHardCap, s.logRevokeBudget = tc.soft, tc.hard, tc.revoke
			err := s.checkConfig()
			if tc.ok {
				if err != nil {
					t.Fatalf("checkConfig: %v", err)
				}
				if b := s.logReadBound(); b <= s.logHardCap {
					t.Fatalf("logReadBound() = %d at the bounds, overflowed", b)
				}
				return
			}
			if !errors.Is(err, errInvalidConfig) {
				t.Fatalf("checkConfig: %v, want errInvalidConfig", err)
			}
		})
	}
}
