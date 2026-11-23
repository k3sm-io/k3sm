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
	"strings"
	"testing"
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
