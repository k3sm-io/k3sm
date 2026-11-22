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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A user Put never mints the master: root verbs create it. On a fresh store
// it answers ErrMasterMissing and leaves no master and no .user.
func TestUserPutNeverMintsMaster(t *testing.T) {
	s, server := newTestStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	if _, err := userScope(t, s, 1001).Put(context.Background(), "user/1001/token", KindOpaque, []byte("v")); !errors.Is(err, ErrMasterMissing) {
		t.Fatalf("a user Put on a fresh store: %v, want ErrMasterMissing", err)
	}
	for _, p := range []string{
		filepath.Join(server, "cred", "keystore-master", masterName),
		filepath.Join(server, "keystore", userScopesName),
	} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("a refused user Put left %s: %v", p, err)
		}
	}
}

// A user Put while a Rewrap is half done (master.next present, or a master
// swap not completed) is refused with ErrRewrapInProgress and changes
// nothing: no .user, which would refuse Rewrap's resume, and no completed
// swap, which only a root verb may make. So no scope.key is ever sealed
// under a W a Rewrap is about to replace, and reading one needs no
// master.next fallback.
func TestUserPutRefusedDuringRewrap(t *testing.T) {
	for _, tt := range []struct {
		name  string
		files []string
	}{
		{"master.next present", []string{masterNextName, masterNextFingerprintName}},
		{"master.next alone", []string{masterNextName}},
		{"swap not completed", []string{masterNextFingerprintName}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, server := newMasteredStore(t)
			fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
			mdir := filepath.Join(server, "cred", "keystore-master")
			for _, f := range tt.files {
				if err := os.WriteFile(filepath.Join(mdir, f), []byte("half-done rewrap\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := dirContents(t, mdir)
			u := userScope(t, s, 1001)
			if _, err := u.Put(context.Background(), "user/1001/token", KindOpaque, []byte("v")); !errors.Is(err, ErrRewrapInProgress) {
				t.Fatalf("a user Put during a rewrap: %v, want ErrRewrapInProgress", err)
			}
			if _, err := os.Lstat(filepath.Join(server, "keystore", userScopesName)); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("a user Put during a rewrap created %s: %v", userScopesName, err)
			}
			if after := dirContents(t, mdir); !mapsEqual(before, after) {
				t.Fatalf("a user Put during a rewrap changed the master directory: %v, then %v", before, after)
			}
			for _, f := range tt.files {
				if err := os.Remove(filepath.Join(mdir, f)); err != nil {
					t.Fatal(err)
				}
			}
			userPut(t, u, "user/1001/token", "v")
			// The scope key is sealed under the live master's W, and that W
			// alone opens it.
			b, err := os.ReadFile(filepath.Join(scopeDir(server, "1001"), scopeKeyName))
			if err != nil {
				t.Fatal(err)
			}
			r, err := parseScopeKey(b)
			if err != nil {
				t.Fatal(err)
			}
			k, err := s.loadMaster()
			if err != nil {
				t.Fatal(err)
			}
			if k.next != nil {
				t.Fatal("a master.next fallback is loaded with no rewrap in progress")
			}
			if _, err := r.open(k.wrap, "user/1001"); err != nil {
				t.Fatalf("scope.key under the live W: %v", err)
			}
		})
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// waitLookupsIdle waits until no GeneratedUID lookup is outstanding, once a
// test has released its stuck ones, so no flight outlives its test.
func waitLookupsIdle(t *testing.T) {
	t.Helper()
	for {
		lookups.mu.Lock()
		var f *flight
		for _, f = range lookups.inflight {
			break
		}
		lookups.mu.Unlock()
		if f == nil {
			return
		}
		<-f.done
	}
}

// stuckLookups installs a GeneratedUID lookup that blocks until the test
// ends, and a deadline that has already passed; it counts the lookups made.
func stuckLookups(t *testing.T) *atomic.Int32 {
	t.Helper()
	release := make(chan struct{})
	calls := new(atomic.Int32)
	t.Cleanup(func() { close(release); waitLookupsIdle(t) })
	setSeam(t, &generatedUIDSeam, func(uint32) ([generationSize]byte, error) {
		calls.Add(1)
		<-release
		return guid(0xA1), nil
	})
	var asked time.Duration
	setSeam(t, &timerSeam, firesAt(&asked))
	return calls
}

// Stuck lookups are bounded: one outstanding lookup per uid, joined by every
// concurrent caller, and, once it is past its deadline, every later caller
// fails closed at once without starting another; and at most
// maxOutstandingLookups across uids, past which a new uid fails closed at
// once.
func TestGeneratedUIDLookupBoundsStuckCalls(t *testing.T) {
	t.Run("one per uid", func(t *testing.T) {
		calls := stuckLookups(t)
		const n = 16
		var wg sync.WaitGroup
		errs := make([]error, n)
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = lookupGeneratedUID(1001)
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if !errors.Is(err, ErrScopeOwnerUnknown) {
				t.Fatalf("caller %d: %v, want ErrScopeOwnerUnknown", i, err)
			}
		}
		if _, err := lookupGeneratedUID(1001); !errors.Is(err, ErrScopeOwnerUnknown) {
			t.Fatalf("a caller after the deadline: %v, want ErrScopeOwnerUnknown", err)
		}
		if c := calls.Load(); c != 1 {
			t.Fatalf("%d lookups started for one uid, want 1", c)
		}
	})
	t.Run("global cap", func(t *testing.T) {
		calls := stuckLookups(t)
		for uid := uint32(1); uid <= maxOutstandingLookups; uid++ {
			if _, err := lookupGeneratedUID(uid + 1000); !errors.Is(err, ErrScopeOwnerUnknown) {
				t.Fatalf("uid %d: %v", uid+1000, err)
			}
		}
		// Every seam call may not have begun yet, but each flight is
		// counted from its start.
		if _, err := lookupGeneratedUID(5000); !errors.Is(err, ErrScopeOwnerUnknown) {
			t.Fatalf("a lookup past the cap: %v, want ErrScopeOwnerUnknown", err)
		}
		lookups.mu.Lock()
		n := len(lookups.inflight)
		lookups.mu.Unlock()
		if n != maxOutstandingLookups {
			t.Fatalf("%d lookups outstanding, want the cap, %d", n, maxOutstandingLookups)
		}
		_ = calls
	})
}

// The short-name resolver has the GeneratedUID lookup's deadline: a getpwnam
// past it fails closed.
func TestShortNameResolverHasTheDeadline(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	setSeam(t, &uidResolverSeam, func(string) (uint32, error) {
		<-release
		return 1001, nil
	})
	var asked time.Duration
	setSeam(t, &timerSeam, firesAt(&asked))
	if _, err := ResolveEntry("user/alice/token"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("a resolver past the deadline: %v, want a refusal", err)
	}
	if asked != generatedUIDDeadline {
		t.Fatalf("the resolver asked for a %s deadline, want %s", asked, generatedUIDDeadline)
	}
}

// The store has no scope for a uid a socket peer could not be: below 501,
// at 2^31 or above, or the service uid.
func TestUserScopeRefusesIneligibleUIDs(t *testing.T) {
	s, _ := newTestStore(t)
	startScopes(t, s)
	for _, uid := range []uint32{0, 1, 500, s.uid, 2147483648, 4294967294} {
		if _, err := s.UserScope(uid); err == nil {
			t.Errorf("UserScope(%d) built a scope", uid)
		}
	}
	for _, uid := range []uint32{501, 2147483647} {
		if uid == s.uid {
			continue
		}
		if _, err := s.UserScope(uid); err != nil {
			t.Errorf("UserScope(%d): %v", uid, err)
		}
	}
	// mint checks it too, for a UserScope built around the constructor.
	u := &UserScope{s: s, uid: s.uid, scope: userScopeOf(s.uid)}
	if _, _, err := u.mint(nil, nil, func() error { return nil }); err == nil {
		t.Fatal("mint made a scope for the service uid")
	}
}

// Until the user-scope floor lands, a user entry directory with no current
// pointer is damage, never an absent entry: an interrupted Put cannot be told
// from a committed entry whose pointer was unlinked. It is refused with
// ErrCorrupt, never ErrNotFound, and never removed.
func TestUserEntryWithoutPointerIsCorrupt(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name   string
		remove []string
	}{
		{"current unlinked", []string{currentName}},
		{"current and v1 unlinked", []string{currentName, versionName(1)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, server := newMasteredStore(t)
			fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
			u := userScope(t, s, 1001)
			userPut(t, u, "user/1001/token", "live value")
			dir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")
			for _, f := range tt.remove {
				remove(t, filepath.Join(dir, f))
			}
			before := dirContents(t, dir)
			if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrNotFound) {
				t.Fatalf("Current: %v, want ErrCorrupt and not ErrNotFound", err)
			}
			if _, err := u.Put(ctx, "user/1001/token", KindOpaque, []byte("new")); !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrNotFound) {
				t.Fatalf("Put over it: %v, want ErrCorrupt", err)
			}
			l, err := u.List(ctx)
			if err != nil || len(l) != 1 || !errors.Is(l[0].Err, ErrCorrupt) {
				t.Fatalf("List: %+v, %v; want the entry with ErrCorrupt", l, err)
			}
			if after := dirContents(t, dir); !mapsEqual(before, after) {
				t.Fatalf("the damaged entry changed: %v, then %v", before, after)
			}
		})
	}
}
