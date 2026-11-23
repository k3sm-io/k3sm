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
	"testing"
)

// A grant (put, deliver) appends its audit line before it takes effect: a
// failed append refuses it and writes nothing, the scope's mint included.
// A revocation (withdraw, rm) commits, then appends, and reports a failed
// append without undoing the change.
func TestAuditBeforeGrant(t *testing.T) {
	ctx := context.Background()
	t.Run("deliver", func(t *testing.T) {
		s, server, u := newDeliveryScope(t)
		_, audit := userLogs(s)
		before := userRecords(t, server)
		audit.fail = true
		if err := u.addDelivery(ctx, testDelivery(1)); err == nil {
			t.Fatal("deliver with a failing audit append was not refused")
		}
		checkTreeUnchanged(t, before, userRecords(t, server))
	})
	t.Run("put", func(t *testing.T) {
		s, server, u := newDeliveryScope(t)
		_, audit := userLogs(s)
		before := userRecords(t, server)
		audit.fail = true
		if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); err == nil {
			t.Fatal("put with a failing audit append was not refused")
		}
		checkTreeUnchanged(t, before, userRecords(t, server))
	})
	t.Run("a minting put", func(t *testing.T) {
		s, server := newMasteredStore(t)
		fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
		_, audit := userLogs(s)
		audit.fail = true
		if _, err := userScope(t, s, 1001).Put(ctx, "user/1001/token", KindOpaque, []byte("v")); err == nil {
			t.Fatal("put with a failing audit append was not refused")
		}
		if _, err := os.Lstat(filepath.Join(server, "keystore", userScopesName)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("a refused mint created %s: %v", userScopesName, err)
		}
	})
	t.Run("the grant line precedes the change", func(t *testing.T) {
		s, _, u := newDeliveryScope(t)
		_, audit := userLogs(s)
		n := len(audit.all())
		if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
			t.Fatal(err)
		}
		lines := audit.all()[n:]
		if len(lines) != 1 || lines[0].op != "deliver" || lines[0].result != "ok" || lines[0].name != "token" || lines[0].namespace != "team-a" {
			t.Fatalf("deliver audit lines %+v", lines)
		}
	})
	t.Run("revocations commit, then report the failed append", func(t *testing.T) {
		s, server, u := newDeliveryScope(t)
		_, audit := userLogs(s)
		if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
			t.Fatal(err)
		}
		audit.fail = true
		if err := u.withdrawDelivery(ctx, testDelivery(1).uid); !errors.Is(err, ErrCommitted) {
			t.Fatalf("withdraw with a failing audit: %v, want the change made and reported", err)
		}
		if d, _ := recordedDelivery(t, s, server, 1); !d.withdrawn {
			t.Fatal("the withdraw was undone")
		}
		if err := u.Delete(ctx, "user/1001/token"); !errors.Is(err, ErrCommitted) {
			t.Fatalf("rm with a failing audit: %v, want the change made and reported", err)
		}
		checkEntryGone(t, server, "token")
		audit.fail = false
		userPut(t, u, "user/1001/token", "again")
		n := len(audit.all())
		if err := u.Delete(ctx, "user/1001/token"); err != nil {
			t.Fatal(err)
		}
		if lines := audit.all()[n:]; len(lines) != 1 || lines[0].op != "rm" || lines[0].result != "ok" || lines[0].name != "token" {
			t.Fatalf("rm audit lines %+v", lines)
		}
	})
}

// In a store built by New, with no fake floor or audit sink, every
// mutating user verb refuses, and a refused mint creates no directory:
// errUserLogsUnbuilt's "nothing was changed" holds.
func TestUserVerbsRefuseInProduction(t *testing.T) {
	ctx := context.Background()
	fake, server := newMasteredStore(t)
	s := New(Config{
		Dir: fake.dir, MasterDir: fake.masterDir, UID: fake.uid, GID: fake.gid,
		DataRoot: fake.dataRoot, FloorUID: fake.floorUID, FloorGID: fake.floorGID,
	})
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	u := userScope(t, s, 1001)
	snap := treeSnapshot(t, server)
	if _, err := u.Put(ctx, "user/1001/token", KindOpaque, []byte("v")); !errors.Is(err, errUserLogsUnbuilt) {
		t.Fatalf("put: %v, want errUserLogsUnbuilt", err)
	}
	if err := u.addDelivery(ctx, testDelivery(1)); !errors.Is(err, errUserLogsUnbuilt) {
		t.Fatalf("deliver: %v, want errUserLogsUnbuilt", err)
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err == nil {
		t.Fatal("withdraw was not refused")
	}
	if err := u.Delete(ctx, "user/1001/token"); err == nil {
		t.Fatal("rm was not refused")
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, server))
	if _, err := os.Lstat(filepath.Join(server, "keystore", userScopesName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused verb created %s: %v", userScopesName, err)
	}
}

// The withdraw audit line names the delivery UID and its recorded
// namespace.
func TestWithdrawAuditNamesDelivery(t *testing.T) {
	ctx := context.Background()
	s, _, u := newDeliveryScope(t)
	_, audit := userLogs(s)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	n := len(audit.all())
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatal(err)
	}
	lines := audit.all()[n:]
	if len(lines) != 1 || lines[0].op != "withdraw" || lines[0].result != "ok" || lines[0].delivery != testDelivery(1).uid || lines[0].namespace != "team-a" {
		t.Fatalf("withdraw audit lines %+v", lines)
	}
	// A UID outside the grammar is audited as the placeholder, never as
	// given.
	n = len(audit.all())
	if err := u.withdrawDelivery(ctx, "not a uid"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("withdraw of a malformed UID: %v, want ErrNotFound", err)
	}
	if lines := audit.all()[n:]; len(lines) != 1 || lines[0].delivery != auditPlaceholder || lines[0].result != "not-found" {
		t.Fatalf("malformed withdraw audit lines %+v", lines)
	}
}

// A mint refused for an entries/ that holds names and no scope.key writes
// one audit line, the refusal, and no grant line before it: the grant line
// follows the mint's own refusals.
func TestMintRefusalAuditsOnce(t *testing.T) {
	ctx := context.Background()
	s, server := newMasteredStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	_, audit := userLogs(s)
	scope := scopeDir(server, "1001")
	if err := os.MkdirAll(filepath.Join(scope, scopeEntriesName, "orphan"), 0o700); err != nil {
		t.Fatal(err)
	}
	// As root the planted tree is root's; hand it to the service user, as
	// a tree the store made would be, so the mint reaches its own refusal.
	giveToService(t, filepath.Dir(scope), scope, filepath.Join(scope, scopeEntriesName), filepath.Join(scope, scopeEntriesName, "orphan"))
	if _, err := userScope(t, s, 1001).Put(ctx, "user/1001/token", KindOpaque, []byte("v")); !errors.Is(err, ErrScopeAbsent) {
		t.Fatalf("put over an orphaned entries/: %v, want ErrScopeAbsent", err)
	}
	if lines := audit.all(); len(lines) != 1 || lines[0].result != "scope-absent" {
		t.Fatalf("refused mint audit lines %+v, want the one refusal", lines)
	}
}
