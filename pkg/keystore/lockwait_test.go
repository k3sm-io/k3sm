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
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// Config.LockWait sets the store's lock bound: zero keeps the root verbs'
// 10 s, a value is taken as given, and a negative one is refused.
func TestLockWaitConfig(t *testing.T) {
	if got := New(Config{}).lockWait; got != lockTimeout {
		t.Fatalf("the default lock wait is %v, want %v", got, lockTimeout)
	}
	if got := New(Config{LockWait: 2 * time.Second}).lockWait; got != 2*time.Second {
		t.Fatalf("LockWait 2s gives %v", got)
	}
	s, _ := newTestStore(t)
	s.lockWait = -time.Second
	if err := s.checkConfig(); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("checkConfig with a negative LockWait: %v, want errInvalidConfig", err)
	}
}

// Under a held store lock, every user-scope operation of a store built
// with LockWait 2s gives the store's busy error once 2 s of bubble time
// have passed, and not before: a grant, a revocation, a rotate and both
// audited reads. No assertion reads the wall clock.
func TestLockWaitBoundsUserOps(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		s, server := newMasteredStore(t)
		fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
		u := userScope(t, s, 1001)
		userPut(t, u, "user/1001/a", "one")
		s.lockWait = New(Config{LockWait: 2 * time.Second}).lockWait
		f, err := os.OpenFile(filepath.Join(server, "keystore", lockName), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
			t.Fatal(err)
		}
		for _, op := range []struct {
			name string
			fn   func() error
		}{
			{"put", func() error { _, err := u.Put(ctx, "user/1001/b", KindOpaque, []byte("b")); return err }},
			{"rm", func() error { return u.Delete(ctx, "user/1001/a") }},
			{"rotate", func() error { _, err := u.Rotate(ctx, "user/1001/a", []byte("two")); return err }},
			{"exec-read", func() error { _, _, err := u.ReadForExec(ctx, "user/1001/a"); return err }},
			{"list", func() error { _, err := u.List(ctx); return err }},
		} {
			start := time.Now()
			err := op.fn()
			if took := time.Since(start); !errors.Is(err, errLockTimeout) || took < 2*time.Second || took > 3*time.Second {
				t.Fatalf("%s under a held lock: %v after %v, want errLockTimeout after 2s", op.name, err, took)
			}
		}
	})
}

// A refusal that comes before its operation takes the lock appends its
// line under the lock taken briefly; under a lock held past its wait the
// line is not written and is counted in the uid's post-frame dropped
// count, so the summary still accounts for it.
func TestAuditBrieflyCountsLineLockKeptOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, server := newMasteredStore(t)
		fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
		u := userScope(t, s, 1001)
		userPut(t, u, "user/1001/a", "one")
		badPut := func(ctx context.Context) {
			if _, err := u.Put(ctx, "user/1001/Bad Name", KindOpaque, []byte("v")); !errors.Is(err, ErrInvalidName) {
				t.Fatalf("a put of a bad name: %v, want ErrInvalidName", err)
			}
		}
		badPut(context.Background())
		if n := s.PostFrameDropped(1001); n != 0 {
			t.Fatalf("a refusal whose line was written counted %d dropped, want 0", n)
		}
		s.lockWait = New(Config{LockWait: 2 * time.Second}).lockWait
		f, err := os.OpenFile(filepath.Join(server, "keystore", lockName), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
			t.Fatal(err)
		}
		badPut(context.Background())
		if n := s.PostFrameDropped(1001); n != 1 {
			t.Fatalf("a refusal under a lock held past its wait counted %d dropped, want 1", n)
		}
	})
}
