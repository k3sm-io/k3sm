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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// rm-scope removes a scope whose delivery record does not read, corrupt
// or missing beside entries/, since listing needs only scope.key: the
// scope is listed and its tree removed, and the result is committed (exit
// 4), saying the record could not be read, so its deliveries were not
// checked and a Secret it delivered stays until withdrawn or removed by
// hand. Floor --rebuild then runs.
func TestRemoveScopeUnreadableDeliveryRecord(t *testing.T) {
	for name, damage := range map[string]func(path string) error{
		"corrupt": func(p string) error { return os.WriteFile(p, []byte("not a record"), fileMode) },
		"missing": os.Remove,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, server, _ := fileLogScope(t)
			userPut(t, userScope(t, s, 1002), "user/1002/x", "x")
			if _, err := s.RebuildFloor(ctx, &attrRecorder{}); err != nil {
				t.Fatalf("rebuild before the damage: %v", err)
			}
			if err := damage(filepath.Join(scopeDir(server, "1002"), deliveriesName)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.RebuildFloor(ctx, &attrRecorder{}); !errors.Is(err, errRebuildRefused) || !strings.Contains(err.Error(), "rm-scope user/1002") {
				t.Fatalf("rebuild with the record damaged: %v, want a refusal naming rm-scope user/1002", err)
			}
			recorded, err := s.RemoveScope(ctx, 1002)
			if !recorded || !Committed(err) {
				t.Fatalf("rm-scope: recorded %v, %v; want listed and committed", recorded, err)
			}
			for _, want := range []string{"removed user/1002", "delivery record could not be read", "deliveries from this scope were not checked", "stays until it is withdrawn or removed by hand"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error %q does not say %q", err, want)
				}
			}
			if _, err := os.Lstat(scopeDir(server, "1002")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the scope directory is still there: %v", err)
			}
			if !readRecord(t, s).listed(1002) {
				t.Fatal("the removed scope is not listed")
			}
			rebuild(t, s)
		})
	}
}

// rm-scope of a scope whose scope.key is present but cannot be trusted (a
// second link, a mode wider than 0600, content that does not parse), all
// of which the service user can cause, removes the tree unlisted, as with
// no scope.key, and is committed (exit 4), saying the key file could not
// be trusted and its floor lines are kept; floor --rebuild, which refused
// the scope naming rm-scope, then runs. No repair loop is left.
func TestRemoveScopeUntrustedKeyUnlisted(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, p string){
		"second link": func(t *testing.T, p string) {
			if err := os.Link(p, filepath.Join(filepath.Dir(p), "alias")); err != nil {
				t.Fatal(err)
			}
		},
		"mode 0640": func(t *testing.T, p string) {
			if err := os.Chmod(p, 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"bad content": func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("not a key record"), fileMode); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, server, _ := fileLogScope(t)
			userPut(t, userScope(t, s, 1002), "user/1002/x", "x")
			damage(t, filepath.Join(scopeDir(server, "1002"), scopeKeyName))
			if _, err := s.RebuildFloor(ctx, &attrRecorder{}); !errors.Is(err, errRebuildRefused) || !strings.Contains(err.Error(), "rm-scope user/1002") {
				t.Fatalf("rebuild with scope.key damaged: %v, want a refusal naming rm-scope user/1002", err)
			}
			recorded, err := s.RemoveScope(ctx, 1002)
			if recorded || !Committed(err) {
				t.Fatalf("rm-scope: recorded %v, %v; want unlisted and committed", recorded, err)
			}
			for _, want := range []string{"removed user/1002 without listing it", "its scope.key could not be trusted", "its floor lines are kept"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error %q does not say %q", err, want)
				}
			}
			if _, err := os.Lstat(scopeDir(server, "1002")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the scope directory is still there: %v", err)
			}
			if readRecord(t, s).listed(1002) {
				t.Fatal("a scope with an untrusted scope.key was listed")
			}
			rebuild(t, s)
		})
	}
}

// rm-scope proceeds past a delivery record that does not read only when
// the record is damaged (ErrCorrupt, the judge's refusal, a planted name,
// a missing record): then it removes the scope, committed. A transient
// failure to read it (a cancelled context, EINTR, EMFILE, EIO) refuses,
// saying nothing was changed and to run it again, and the scope stays
// unlisted and in place.
func TestRemoveScopeTransientDeliveryReadRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		err     error
		damaged bool
	}{
		"corrupt":   {fmt.Errorf("%w: deliveries does not authenticate", ErrCorrupt), true},
		"judged":    {fmt.Errorf("%w: deliveries: %w", ErrCorrupt, errBadFile), true},
		"planted":   {fmt.Errorf("%w: deliveries", errPlanted), true},
		"missing":   {fmt.Errorf("%w: no record", ErrScopeAbsent), true},
		"cancelled": {fmt.Errorf("read deliveries: %w", context.Canceled), false},
		"EINTR":     {fmt.Errorf("read deliveries: %w", unix.EINTR), false},
		"EMFILE":    {fmt.Errorf("read deliveries: %w", unix.EMFILE), false},
		"EIO":       {fmt.Errorf("read deliveries: %w", unix.EIO), false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := deliveriesDamaged(tc.err); got != tc.damaged {
				t.Fatalf("deliveriesDamaged(%v) = %v, want %v", tc.err, got, tc.damaged)
			}
			ctx := context.Background()
			s, server, _ := fileLogScope(t)
			userPut(t, userScope(t, s, 1002), "user/1002/x", "x")
			saved := rmReadDeliveries
			rmReadDeliveries = func(*UserScope, *openedScope) (uint64, []delivery, error) { return 0, nil, tc.err }
			t.Cleanup(func() { rmReadDeliveries = saved })
			recorded, err := s.RemoveScope(ctx, 1002)
			_, serr := os.Lstat(scopeDir(server, "1002"))
			if tc.damaged {
				if !recorded || !Committed(err) || !errors.Is(serr, os.ErrNotExist) {
					t.Fatalf("rm-scope over a damaged record: recorded %v, %v, directory %v; want listed, committed and removed", recorded, err, serr)
				}
				return
			}
			if recorded || err == nil || Committed(err) || !strings.Contains(err.Error(), "nothing was changed; run it again") {
				t.Fatalf("rm-scope over a transient read failure: recorded %v, %v; want a refusal saying nothing was changed; run it again", recorded, err)
			}
			if serr != nil {
				t.Fatalf("the scope directory is gone after a refusal: %v", serr)
			}
			if readRecord(t, s).listed(1002) {
				t.Fatal("a refused rm-scope listed the scope")
			}
		})
	}
}
