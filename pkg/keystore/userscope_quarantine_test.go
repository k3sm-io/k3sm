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
	"testing"
)

// tornFloorWrite makes l's appends land with no newline and fail: a crash
// mid-write as the reader sees it.
func tornFloorWrite(l *appendLog) {
	l.write = func(f *os.File, b []byte) (int, error) {
		n, err := f.Write(b[:len(b)-1])
		if err != nil {
			return n, err
		}
		return n, errors.New("injected torn floor write")
	}
}

// uid A's put whose floor line tore (a crash between the pointer and the
// floor line) quarantines only A after a restart: the start step starts the
// user scope, UserScope refuses A with errFloorDegraded, and uid B starts
// and works.
func TestTornPutLineQuarantinesOnlyItsScope(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	ub := userScope(t, s, 1002)
	userPut(t, ub, "user/1002/token", "b value")
	fl := s.userFloor.(*fileFloorLog).log
	tornFloorWrite(fl)
	if _, err := u.Put(ctx, "user/1001/lost", KindOpaque, []byte("v")); !errors.Is(err, errCommitted) {
		t.Fatalf("put whose floor line tears: %v, want errCommitted", err)
	}
	fl.write = nil

	s2 := reopenStore(t, s)
	err := s2.startUserScopes(ctx)
	if !s2.userScopesStarted.Load() {
		t.Fatalf("start over one scope's refused catch-up: %v, and the user scope is not started", err)
	}
	if !errors.Is(err, errCatchUpRefused) {
		t.Fatalf("start: %v, want the refused catch-up named", err)
	}
	if _, err := s2.UserScope(1001); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("UserScope of the quarantined uid: %v, want errFloorDegraded", err)
	}
	ub2 := userScope(t, s2, 1002)
	if _, _, err := ub2.Current(ctx, "user/1002/token"); err != nil {
		t.Fatalf("current in the other scope: %v", err)
	}
	if _, err := ub2.Put(ctx, "user/1002/more", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("put in the other scope: %v", err)
	}
}
