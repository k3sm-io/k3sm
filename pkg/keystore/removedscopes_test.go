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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// removedRecordPath is the removed-scopes record in s's data root.
func removedRecordPath(s *FileStore) string { return filepath.Join(s.dataRoot, removedScopesName) }

// assertScopeRemovedEverywhere checks that every open of uid's scope
// refuses with want: a read, a put, the start step's catch-up and a
// rebuild.
func assertScopeRemovedEverywhere(t *testing.T, s *FileStore, uid uint32, want error) {
	t.Helper()
	ctx := context.Background()
	u := &UserScope{s: s, uid: uid, scope: userScopeOf(uid)}
	name := fmt.Sprintf("user/%d/token", uid)
	if _, _, err := u.Current(ctx, name); !errors.Is(err, want) {
		t.Errorf("read: %v, want %v", err, want)
	}
	if _, err := u.Put(ctx, fmt.Sprintf("user/%d/new", uid), KindOpaque, []byte("v")); !errors.Is(err, want) {
		t.Errorf("put: %v, want %v", err, want)
	}
	if _, scopeErrs, err := s.catchUpUser(ctx); err != nil || !errors.Is(scopeErrs, want) {
		t.Errorf("the start step's catch-up: %v / %v, want %v", err, scopeErrs, want)
	}
	if _, err := s.RebuildFloor(ctx, &attrRecorder{}); !errors.Is(err, want) || !errors.Is(err, errRebuildRefused) {
		t.Errorf("rebuild: %v, want a refusal with %v", err, want)
	}
}

// rm-scope lists the scope key in the removed-scopes record, so the old
// directory copied back is refused at every open; a scope minted fresh for
// the uid has a new key and opens.
func TestRemovedScopeCopiedBackRefused(t *testing.T) {
	ctx := context.Background()
	s, server, _ := fileLogScope(t)
	saved := filepath.Join(t.TempDir(), "1001")
	copyTree(t, scopeDir(server, "1001"), saved)
	recorded, err := s.RemoveScope(ctx, 1001)
	if err != nil || !recorded {
		t.Fatalf("RemoveScope: %v, recorded %v", err, recorded)
	}
	var st unix.Stat_t
	if err := unix.Lstat(removedRecordPath(s), &st); err != nil || st.Mode&0o7777 != removedScopesMode || int64(st.Uid) != int64(s.floorUID) {
		t.Fatalf("the record is mode %04o uid %d (%v), want %04o, the data root's owner", st.Mode&0o7777, st.Uid, err, removedScopesMode)
	}
	copyTree(t, saved, scopeDir(server, "1001"))
	assertScopeRemovedEverywhere(t, s, 1001, errScopeRemoved)

	// A rerun of rm-scope on the copied-back directory finishes, and the
	// record lists the key once.
	if recorded, err := s.RemoveScope(ctx, 1001); err != nil || !recorded {
		t.Fatalf("rm-scope of the copied-back directory: %v, recorded %v", err, recorded)
	}
	r := readRecord(t, s)
	if r.keys() != 1 {
		t.Fatalf("the record lists %d keys, want 1", r.keys())
	}

	// Re-minted: a fresh K_u, which opens.
	u := userScope(t, s, 1001)
	userPut(t, u, "user/1001/token", "after re-mint")
	if _, got, err := u.Current(ctx, "user/1001/token"); err != nil || string(got) != "after re-mint" {
		t.Fatalf("the re-minted scope: %q, %v", got, err)
	}
	rebuild(t, s)
}

func readRecord(t *testing.T, s *FileStore) *removedScopes {
	t.Helper()
	dfd, err := s.openLogDataRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(dfd) }()
	r, err := s.readRemovedScopes(dfd)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A full record does not stop rm-scope: the scope is removed unlisted, and
// rebuild keeps its floor keys (fail closed for a copy-back).
func TestRemovedScopesFullKeepsFloorKeys(t *testing.T) {
	ctx := context.Background()
	s, server, _ := fileLogScope(t)
	v := userScope(t, s, 1002)
	userPut(t, v, "user/1002/x", "1002's value")
	full := &removedScopes{Version: removedScopesVersion}
	for i := range maxRemovedScopeKeys {
		if !full.add(uint32(5000+i%8), fmt.Sprintf("%064x", i), 0, 0) {
			t.Fatal("the record filled early")
		}
	}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRemovedScopes(dfd, full); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(dfd)
	recorded, err := s.RemoveScope(ctx, 1002)
	if err != nil || recorded {
		t.Fatalf("RemoveScope with a full record: %v, recorded %v; want removed, unrecorded", err, recorded)
	}
	if _, err := os.Lstat(scopeDir(server, "1002")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope directory is still there: %v", err)
	}
	rep, _ := rebuild(t, s)
	if rep.RemovedKeys != 0 {
		t.Errorf("dropped %d keys of an unrecorded removed scope, want 0", rep.RemovedKeys)
	}
	if !bytes.Contains(readLog(t, s, userFloorLogName), []byte("user/1002 ")) {
		t.Fatal("rebuild dropped the floor keys of a scope the full record could not list")
	}
}

// A removed-scopes record that does not judge or parse fails closed: no
// scope opens, rm-scope and rebuild refuse.
func TestRemovedScopesMalformedFailsClosed(t *testing.T) {
	for name, body := range map[string]string{
		"truncated":     `{"version":1,"scopes":[`,
		"unknown field": `{"version":1,"scopes":[],"extra":1}`,
		"trailing data": `{"version":1,"scopes":[]} {}`,
		"duplicate uid": fmt.Sprintf(`{"version":1,"scopes":[{"uid":7,"keys":["%064x"]},{"uid":7,"keys":["%064x"]}]}`, 1, 2),
		"bad key":       `{"version":1,"scopes":[{"uid":7,"keys":["ABC"]}]}`,
		"version":       `{"version":2,"scopes":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, _, _ := fileLogScope(t)
			if err := os.WriteFile(removedRecordPath(s), []byte(body), removedScopesMode); err != nil {
				t.Fatal(err)
			}
			assertScopeRemovedEverywhere(t, s, 1001, errRemovedScopesBad)
			if _, err := s.RemoveScope(ctx, 1001); !errors.Is(err, errRemovedScopesBad) {
				t.Errorf("rm-scope: %v, want errRemovedScopesBad", err)
			}
		})
	}
	t.Run("group-writable", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		if err := os.WriteFile(removedRecordPath(s), []byte(`{"version":1,"scopes":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(removedRecordPath(s), 0o664); err != nil {
			t.Fatal(err)
		}
		assertScopeRemovedEverywhere(t, s, 1001, errRemovedScopesBad)
	})
}
