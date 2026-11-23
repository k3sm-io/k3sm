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
	"os"
	"path/filepath"
	"testing"
)

// testLogCheckRefusesAtStart is U21's start-step half, a subtest of
// TestFlagCheckRefusesUnflagged: the start step and the doctor's check
// (CheckLogFlags) refuse when either log's SF_APPEND flag is clear or
// either log is not the service user's, and pass both flagged logs the
// service user owns.
func testLogCheckRefusesAtStart(t *testing.T) {
	clearOn := func(name string) func(*os.File) (uint32, error) {
		return func(f *os.File) (uint32, error) {
			if filepath.Base(f.Name()) == name {
				return 0, nil
			}
			return sfAppend, nil
		}
	}
	for _, tc := range []struct {
		name   string
		inject func(s *FileStore)
		want   error
	}{
		{"floor flag clear", func(s *FileStore) { s.logFlags = clearOn(userFloorLogName) }, errLogNotAppendOnly},
		{"audit flag clear", func(s *FileStore) { s.logFlags = clearOn(auditLogName) }, errLogNotAppendOnly},
		{"not the service user's", func(s *FileStore) { s.uid++ }, errLogUntrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, _, _ := fileLogScope(t)
			if err := s.CheckLogFlags(ctx); err != nil {
				t.Fatalf("CheckLogFlags on both flagged, service-owned logs: %v", err)
			}
			tc.inject(s)
			if err := s.CheckLogFlags(ctx); !errors.Is(err, tc.want) {
				t.Fatalf("CheckLogFlags = %v, want %v", err, tc.want)
			}
			s.userScopesStarted.Store(false)
			if err := s.startUserScopes(ctx); !errors.Is(err, tc.want) {
				t.Fatalf("the start step = %v, want %v", err, tc.want)
			}
			if s.userScopesStarted.Load() {
				t.Fatal("the user scope started over a refused log")
			}
		})
	}
}
