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
	"strconv"
	"strings"
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
	res, err := s.RemoveScope(ctx, 1001)
	recorded := res.Recorded
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
	if res, err := s.RemoveScope(ctx, 1001); err != nil || !res.Recorded {
		t.Fatalf("rm-scope of the copied-back directory: %v, recorded %v", err, res.Recorded)
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
		if !full.add(uint32(5000+i%8), fmt.Sprintf("%064x", i), floorIdentity{}, 0) {
			t.Fatal("the record filled early")
		}
	}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeRemovedScopes(dfd, full); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(dfd)
	res, err := s.RemoveScope(ctx, 1002)
	recorded := res.Recorded
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

// A scope directory with no scope.key, for a uid the record does not
// list, is removed, but the removal is committed, not clean: the error
// says it was removed without being listed, because its key file was
// absent, so a copy the service user puts back opens again, held only to
// the scope's floor lines, which are kept. It never says the record is full.
func TestRemoveScopeMissingKeyUnlistedCommitted(t *testing.T) {
	ctx := context.Background()
	s, server, _ := fileLogScope(t)
	userPut(t, userScope(t, s, 1002), "user/1002/x", "x")
	if err := os.Remove(filepath.Join(scopeDir(server, "1002"), scopeKeyName)); err != nil {
		t.Fatal(err)
	}
	res, err := s.RemoveScope(ctx, 1002)
	recorded := res.Recorded
	if recorded || !Committed(err) {
		t.Fatalf("rm-scope of an unlisted keyless scope: %v, recorded %v; want committed, unlisted", err, recorded)
	}
	for _, want := range []string{"without listing it", "scope.key was absent", "put back by the service user opens again", "held only to the scope's floor lines, which are kept"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "full") {
		t.Errorf("the error %q speaks of a full record", err)
	}
	if _, err := os.Lstat(scopeDir(server, "1002")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope directory is still there: %v", err)
	}
	if readRecord(t, s).listed(1002) {
		t.Fatal("the keyless scope was listed")
	}
}

// The repair text names the mode the judge accepts and the service user
// can read: a record restored at that mode reads, and opens a scope.
func TestRemovedScopesBadNamesAcceptedMode(t *testing.T) {
	msg := errRemovedScopesBad.Error()
	i := strings.Index(msg, "mode 0")
	if i < 0 || !strings.Contains(msg, "root:wheel") {
		t.Fatalf("the repair text %q names no owner and mode", msg)
	}
	mode, err := strconv.ParseUint(msg[i+len("mode "):i+len("mode 0644")], 8, 32)
	if err != nil {
		t.Fatal(err)
	}
	if mode != removedScopesMode || mode&0o004 == 0 {
		t.Fatalf("the repair text names mode %04o, want %04o, readable by the service user", mode, removedScopesMode)
	}
	s, _, _ := fileLogScope(t)
	if err := os.WriteFile(removedRecordPath(s), []byte(`{"version":1,"scopes":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(removedRecordPath(s), os.FileMode(mode)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserScope(1001); err != nil {
		t.Fatalf("a scope under a record restored at mode %04o: %v", mode, err)
	}
}

// A log at a location no release keeps one at is not a supported layout:
// the text says where the logs belong and names a restore from backup,
// never an unflag or a delete.
func TestLogOldLocationTextNamesRestore(t *testing.T) {
	msg := errLogOldLocation(userFloorLogName).Error()
	for _, want := range []string{"not a supported layout", "keystore-logs/floor/", "keystore-logs/audit/", "restore the data root from a backup"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the text %q does not say %q", msg, want)
		}
	}
	for _, bad := range []string{"chflags", "sudo rm", "k3sm install"} {
		if strings.Contains(msg, bad) {
			t.Errorf("the text %q names %q", msg, bad)
		}
	}
}

// The data root's fsync after the record's rename fails (through the
// seam): the record already lists the scope, so rm-scope stops committed
// (exit 4, audited committed), saying the record lists it but its
// durability is unknown, and leaves the scope directory untouched.
func TestRmScopeRecordFsyncFailureIsCommitted(t *testing.T) {
	s, server, _ := fileLogScope(t)
	setSeam(t, &removedScopesFsync, func(int) error { return unix.EIO })
	res, err := s.RemoveScope(t.Context(), 1001)
	if !Committed(err) || !errors.Is(err, unix.EIO) {
		t.Fatalf("rm-scope with the record's fsync failing: %v, want committed wrapping EIO", err)
	}
	if !res.Recorded {
		t.Error("the result says the scope is not listed")
	}
	if !strings.Contains(err.Error(), "the record lists the scope but its durability is unknown") {
		t.Errorf("the error %q does not say the record lists the scope of unknown durability", err)
	}
	if !readRecord(t, s).listed(1001) {
		t.Fatal("the record does not list the scope after its rename")
	}
	if _, err := os.Lstat(filepath.Join(scopeDir(server, "1001"), scopeKeyName)); err != nil {
		t.Fatalf("scope.key after a stop at the record: %v, want the directory untouched", err)
	}
}
