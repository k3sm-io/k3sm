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
	"testing"
)

// startScopes runs s's user-scope start step, which every test that builds
// a user scope owes before UserScope, once per store. A scope the catch-up
// could not open (a test's planted damage) does not hold the start, as in
// the server; a start that did not happen fails the test.
func startScopes(t *testing.T, s *FileStore) {
	t.Helper()
	if s.userScopesStarted != nil && s.userScopesStarted.Load() {
		return
	}
	err := s.startUserScopes(context.Background())
	if s.userScopesStarted == nil || !s.userScopesStarted.Load() {
		t.Fatalf("startUserScopes: %v", err)
	}
}

// UserScope refuses (errUserScopesNotStarted) until the start step has run,
// and builds the scope after it.
func TestUserScopeRefusedBeforeStart(t *testing.T) {
	s, _ := newTestStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	if _, err := s.UserScope(1001); !errors.Is(err, errUserScopesNotStarted) {
		t.Fatalf("UserScope before the start step: %v, want errUserScopesNotStarted", err)
	}
	startScopes(t, s)
	if _, err := s.UserScope(1001); err != nil {
		t.Fatalf("UserScope after the start step: %v", err)
	}
}

// The start step runs CheckLogBounds first: a configuration it refuses
// leaves the user scope unstarted.
func TestStartUserScopesChecksBoundsFirst(t *testing.T) {
	s, _ := newTestStore(t)
	s.logHardCap, s.logSoftCap = 1, 2
	if err := s.startUserScopes(context.Background()); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("start with a configuration CheckLogBounds refuses: %v, want errInvalidConfig", err)
	}
	if s.userScopesStarted.Load() {
		t.Fatal("the user scope started after CheckLogBounds refused")
	}
	if _, err := s.UserScope(1001); !errors.Is(err, errUserScopesNotStarted) {
		t.Fatalf("UserScope after a refused start: %v, want errUserScopesNotStarted", err)
	}
}
