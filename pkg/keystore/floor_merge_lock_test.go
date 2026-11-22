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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMergeFloorIgnoresEntryLock (U192): the merge writes only the
// root-owned floor under keystore-lock and never takes keystore/.lock, which
// the service user can hold or replace, so a held .lock and a .lock replaced
// by a directory each leave the merge's burials written.
func TestMergeFloorIgnoresEntryLock(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, lock string)
	}{
		{"held", func(t *testing.T, lock string) {
			held, err := os.Open(lock)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = held.Close() })
			if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
				t.Fatal(err)
			}
		}},
		{"replaced by a directory", func(t *testing.T, lock string) {
			remove(t, lock)
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, server := newTestStore(t)
			mustPut(t, s, "k", KindOpaque, []byte("one"))
			s.lockWait = 200 * time.Millisecond
			path := writeAsideFloor(t, server, floor{"gone": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}})
			tc.plant(t, filepath.Join(server, "keystore", lockName))
			r, err := s.MergeFloor(ctx, path, nil)
			if err != nil || r.Merged != 1 {
				t.Fatalf("MergeFloor under a %s .lock = %+v, %v; want 1 merged", tc.name, r, err)
			}
			if fl := readFloorFile(t, server); !fl["gone"].buries(mgen(1)) {
				t.Fatalf("floor after the merge = %+v, want gone's burial", fl)
			}
		})
	}
}

// TestMergeFloorRefusesWrongInput (U192): the merge refuses, writing
// nothing, onto an absent live floor (the saved floor was never put back),
// from a file whose highest delete sequence is below the live floor's (the
// restored floor, not the one moved aside) and from a file equal to the
// live floor.
func TestMergeFloorRefusesWrongInput(t *testing.T) {
	ctx := context.Background()
	aside := floor{"gone": {Buried: []burial{{Generation: mgen(1), Deleted: 3}}}}
	for _, tc := range []struct {
		name string
		live floor // nil: no live floor file
		want string
	}{
		{"an absent live floor", nil, "restore the saved keystore-floor.json first"},
		{"an older input", floor{"x": {Buried: []burial{{Generation: mgen(2), Deleted: 7}}}}, "older than the live floor's"},
		{"the live floor itself", aside, "the live floor itself"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server := newTestStore(t)
			if tc.live != nil {
				putFloorFile(t, server, tc.live)
			}
			path := writeAsideFloor(t, server, aside)
			before, _ := os.ReadFile(floorPath(server))
			_, err := s.MergeFloor(ctx, path, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("MergeFloor: %v, want a refusal saying %q", err, tc.want)
			}
			after, aerr := os.ReadFile(floorPath(server))
			if tc.live == nil {
				if !errors.Is(aerr, fs.ErrNotExist) {
					t.Fatalf("live floor after the refusal: %v, want it still absent", aerr)
				}
				return
			}
			if string(after) != string(before) {
				t.Fatalf("live floor after the refusal = %s, want %s", after, before)
			}
		})
	}
}
