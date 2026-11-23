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
	"strings"
	"syscall"
	"testing"
)

// attrRecorder is a file-attribute writer that records each call and, for
// fchflags, what it set: a non-root test cannot set sappnd.
type attrRecorder struct {
	calls []string
	// flagged is set once the new file's sappnd is set; the store's flag
	// source reads it.
	flagged bool
}

func (r *attrRecorder) Fchown(fd, uid, gid int) error {
	r.calls = append(r.calls, fmt.Sprintf("fchown %d", uid))
	return ownAsRoot(fd, uid, gid)
}

func (r *attrRecorder) Fchmod(fd int, mode uint32) error {
	r.calls = append(r.calls, fmt.Sprintf("fchmod %o", mode))
	return modeAsRoot(fd, mode)
}

// ownAsRoot applies a recorded fchown when the test runs as root, so a
// rebuilt log is the service user's as the verb leaves it (R1); a non-root
// test owns every file already and changes nothing.
func ownAsRoot(fd, uid, gid int) error {
	if !asRoot() {
		return nil
	}
	return syscall.Fchown(fd, uid, gid)
}

// modeAsRoot is ownAsRoot for fchmod.
func modeAsRoot(fd int, mode uint32) error {
	if !asRoot() {
		return nil
	}
	return syscall.Fchmod(fd, mode)
}

func (r *attrRecorder) Fchflags(_, flags int) error {
	r.calls = append(r.calls, fmt.Sprintf("fchflags %#x", flags))
	if flags == sfAppend {
		r.flagged = true
	}
	return nil
}

func rebuild(t *testing.T, s *FileStore) (RebuildReport, *attrRecorder) {
	t.Helper()
	rec := &attrRecorder{}
	rep, err := s.RebuildFloor(context.Background(), rec)
	if err != nil {
		t.Fatalf("RebuildFloor: %v", err)
	}
	return rep, rec
}

// assertNoMaintenanceLeft checks that a run left neither the marker nor the
// staging directory.
func assertNoMaintenanceLeft(t *testing.T, s *FileStore) {
	t.Helper()
	for _, n := range []string{maintenanceMarkerName, stagingDirName} {
		if _, err := os.Lstat(filepath.Join(s.dataRoot, n)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind: %v", n, err)
		}
	}
}

// floorRecs parses every whole line of the floor.
func floorRecs(t *testing.T, s *FileStore) []floorRec {
	t.Helper()
	var out []floorRec
	for _, l := range bytes.Split(readLog(t, s, userFloorLogName), []byte{'\n'}) {
		if len(l) == 0 {
			continue
		}
		r, err := parseFloorLine(l)
		if err != nil {
			t.Fatalf("the rebuilt floor holds a line that does not parse: %q", l)
		}
		out = append(out, r)
	}
	return out
}

func entryGen(t *testing.T, server, uid, name string) [generationSize]byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Join(scopeDir(server, uid), scopeEntriesName, name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	g, err := readGeneration(root)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// U193: rebuild carries every tombstone and each key's highest sequence
// forward, drops only the torn line and names the count, and a tree copied
// back after the rm is still refused; a floor that cannot be read refuses
// the rebuild, which changes nothing.
func TestRebuildCarriesTombstonesForward(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	userPut(t, u, "user/1001/gone", "deleted later")
	gone := entryGen(t, server, "1001", "gone")
	saved := filepath.Join(t.TempDir(), "gone")
	copyTree(t, filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "gone"), saved)
	if err := u.Delete(ctx, "user/1001/gone"); err != nil {
		t.Fatal(err)
	}
	token := entryGen(t, server, "1001", "token")
	high, err := floorLine("user/1001", "token", token, 7)
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, append([]byte{'\n'}, high...))
	appendLogBytes(t, s, userFloorLogName, []byte("user/1001 torn"))

	rep, _ := rebuild(t, s)
	if rep.Dropped != 1 {
		t.Errorf("dropped %d lines, want 1 (the torn tail)", rep.Dropped)
	}
	assertNoMaintenanceLeft(t, s)
	var tomb, seq7 bool
	for _, r := range floorRecs(t, s) {
		switch {
		case r.key == floorKey{"user/1001", "gone", gone} && r.tomb:
			tomb = true
		case r.key == floorKey{"user/1001", "token", token} && r.seq == 7:
			seq7 = true
		case r.key.name == "token" && r.seq != 7:
			t.Errorf("token's line at %d, want the carried 7 over the disk's 1", r.seq)
		}
	}
	if !tomb || !seq7 {
		t.Fatalf("rebuilt floor lost the tombstone (%v) or the carried sequence (%v)", tomb, seq7)
	}
	if bytes.Contains(readLog(t, s, userFloorLogName), []byte("torn")) {
		t.Fatal("the torn line reached the rebuilt floor")
	}
	copyTree(t, saved, filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "gone"))
	if _, err := s.userFloor.floor("user/1001", "gone", gone); !errors.Is(err, errFloorBuried) {
		t.Fatalf("the copied-back tree's generation after rebuild: %v, want buried", err)
	}
	if _, _, err := u.Current(ctx, "user/1001/gone"); err == nil {
		t.Fatal("the copied-back tree was served after rebuild")
	}

	// A floor that cannot be read refuses, changing nothing.
	p := filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName)
	before := readLog(t, s, userFloorLogName)
	aside := p + ".aside"
	if err := os.Rename(p, aside); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RebuildFloor(ctx, &attrRecorder{}); !errors.Is(err, errRebuildRefused) {
		t.Fatalf("rebuild over an unreadable floor: %v, want refused", err)
	}
	assertNoMaintenanceLeft(t, s)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(aside, p); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readLog(t, s, userFloorLogName)) {
		t.Fatal("a refused rebuild changed the floor")
	}
}

// U194: after rm-scope, rebuild drops every key of that scope, live or
// buried, and frees the uid's key share; the re-minted scope has a fresh
// K_u.
func TestRebuildDropsRemovedScopeKeys(t *testing.T) {
	ctx := context.Background()
	s, server, _ := fileLogScope(t)
	v := userScope(t, s, 1002)
	userPut(t, v, "user/1002/x", "1002's value")
	if err := v.Delete(ctx, "user/1002/x"); err != nil {
		t.Fatal(err)
	}
	userPut(t, v, "user/1002/y", "1002's live value")
	oldKey, err := os.ReadFile(filepath.Join(scopeDir(server, "1002"), scopeKeyName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveScope(ctx, 1002); err != nil {
		t.Fatalf("RemoveScope: %v", err)
	}
	if _, err := os.Lstat(scopeDir(server, "1002")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope directory is still there: %v", err)
	}
	rep, _ := rebuild(t, s)
	if rep.RemovedKeys != 3 { // .deliveries, x (buried) and y
		t.Errorf("dropped %d keys of the removed scope, want 3", rep.RemovedKeys)
	}
	if bytes.Contains(readLog(t, s, userFloorLogName), []byte("user/1002 ")) {
		t.Fatal("a key of the removed scope reached the rebuilt floor")
	}
	if err := s.userFloor.(*fileFloorLog).read(func(st *logState) {
		if n := st.uidKeys[1002]; n != 0 {
			t.Errorf("uid 1002 still holds %d keys of its share", n)
		}
	}); err != nil {
		t.Fatal(err)
	}
	userPut(t, v, "user/1002/x", "after re-mint")
	newKey, err := os.ReadFile(filepath.Join(scopeDir(server, "1002"), scopeKeyName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldKey, newKey) {
		t.Fatal("the re-minted scope has the old scope.key")
	}
}

// U88: rebuild reads an owner-changed and a departed scope without the
// GeneratedUID check; a scope whose scope.key does not open under W refuses
// it, naming the scope and changing nothing.
func TestRebuildRefusesOnUnopenableScope(t *testing.T) {
	ctx := context.Background()
	s, server, _ := fileLogScope(t)
	guids := map[uint32][generationSize]byte{1001: guid(0xA1), 1002: guid(0xA2)}
	fakeGUIDs(t, guids)
	userPut(t, userScope(t, s, 1002), "user/1002/x", "1002's value")
	guids[1001] = guid(0xB1) // the owner changed
	delete(guids, 1002)      // the account departed
	rep, _ := rebuild(t, s)
	if rep.Scopes != 2 {
		t.Fatalf("rebuilt %d scopes, want both", rep.Scopes)
	}
	var deliveries1002 bool
	for _, r := range floorRecs(t, s) {
		if r.key.scope == "user/1002" && r.key.name == deliveriesFloorName {
			deliveries1002 = true
		}
	}
	if !deliveries1002 {
		t.Fatal("the departed scope's delivery record has no line")
	}

	before := readLog(t, s, userFloorLogName)
	k1, err := os.ReadFile(filepath.Join(scopeDir(server, "1001"), scopeKeyName))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(scopeDir(server, "1002"), scopeKeyName)
	if err := os.WriteFile(p, k1, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = s.RebuildFloor(ctx, &attrRecorder{})
	if !errors.Is(err, errRebuildRefused) || !strings.Contains(err.Error(), "user/1002") {
		t.Fatalf("rebuild over an unopenable scope: %v, want refused naming user/1002", err)
	}
	assertNoMaintenanceLeft(t, s)
	if !bytes.Equal(before, readLog(t, s, userFloorLogName)) {
		t.Fatal("a refused rebuild changed the floor")
	}
}

// U88: a copied-back older delivery record is refused against the floor,
// before and after a rebuild, which writes the record's key at the higher
// sequence.
func TestCopiedBackDeliveriesRecordRefused(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	p := filepath.Join(scopeDir(server, "1001"), deliveriesName)
	old, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	d := testDelivery(1)
	if err := u.Deliver(ctx, exportDelivery(d)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, old, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, when := range []string{"before", "after"} {
		if when == "after" {
			rebuild(t, s)
		}
		_, err := u.Delivery(ctx, d.uid)
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "older than the user-scope floor") {
			t.Fatalf("%s rebuild, the copied-back record: %v, want refused against the floor", when, err)
		}
	}
	var seq uint64
	for _, r := range floorRecs(t, s) {
		if r.key.name == deliveriesFloorName && r.key.scope == "user/1001" {
			seq = r.seq
		}
	}
	if seq != 2 {
		t.Fatalf("the rebuilt floor holds the record at %d, want 2", seq)
	}
}

// U25: a restored tree whose logs lost their flags is refused until floor
// --rebuild, which builds the new floor's directory in staging, hands the
// new floor to the service user and flags it on its held descriptor, and
// swaps the directory in, after which the scope opens.
func TestBackupRestoreRoundTripRebuild(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	backup := t.TempDir()
	ks := filepath.Join(server, "keystore")
	copyTree(t, ks, filepath.Join(backup, "keystore"))
	floor := readLog(t, s, userFloorLogName)
	if err := os.RemoveAll(ks); err != nil {
		t.Fatal(err)
	}
	copyTree(t, filepath.Join(backup, "keystore"), ks)
	p := filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, floor, logMode); err != nil {
		t.Fatal(err)
	}
	// Restored as the service user's, so the flag is what refuses it.
	giveToService(t, p)
	rec := &attrRecorder{}
	s.logFlags = func(*os.File) (uint32, error) {
		if rec.flagged {
			return sfAppend, nil
		}
		return 0, nil
	}
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errLogNotAppendOnly) {
		t.Fatalf("read before the rebuild: %v, want the unflagged floor refused", err)
	}
	if _, err := s.RebuildFloor(ctx, rec); err != nil {
		t.Fatal(err)
	}
	assertNoMaintenanceLeft(t, s)
	svc := fmt.Sprintf("fchown %d", s.uid)
	// The new log is handed over, set to 0600 and flagged before it is
	// reachable; the restored log is unflagged and, in this non-root test,
	// the floor owner's, so it is taken as a restore; no other call is made.
	want := []string{svc, "fchmod 600", fmt.Sprintf("fchflags %#x", sfAppend)}
	if strings.Join(rec.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("attribute calls %q, want %q", rec.calls, want)
	}
	if _, v, err := u.Current(ctx, "user/1001/token"); err != nil || string(v) != "a value" {
		t.Fatalf("read after the rebuild: %q, %v", v, err)
	}
}

// U25: rebuild writes a line, at sequence 0, for an entry directory whose
// pointer does not authenticate, so the entry stays ErrCorrupt and never
// reads as ErrNotFound.
func TestRebuildKeepsDamagedEntryCorrupt(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	userPut(t, u, "user/1001/broken", "soon damaged")
	gen := entryGen(t, server, "1001", "broken")
	cur := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "broken", currentName)
	if err := os.WriteFile(cur, []byte("not a pointer"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The restored floor lost the entry's line.
	if err := os.WriteFile(filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName), nil, logMode); err != nil {
		t.Fatal(err)
	}
	rebuild(t, s)
	var zero bool
	for _, r := range floorRecs(t, s) {
		if r.key == (floorKey{"user/1001", "broken", gen}) && r.seq == 0 && !r.tomb {
			zero = true
		}
	}
	if !zero {
		t.Fatal("the damaged entry has no line at sequence 0")
	}
	_, _, err := u.Current(ctx, "user/1001/broken")
	if !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrNotFound) {
		t.Fatalf("the damaged entry after rebuild: %v, want ErrCorrupt and not ErrNotFound", err)
	}
}

// U80 (rm-scope and floor --rebuild): floor --rebuild refuses a symlink
// planted in a scope's tree, changing nothing; rm-scope removes a planted
// symlink, FIFO and extra directories without following any of them.
func TestRootWalksRefusePlantedNames(t *testing.T) {
	ctx := context.Background()
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	entry := filepath.Join(dir, scopeEntriesName, "token")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("not the scope's"), 0o600); err != nil {
		t.Fatal(err)
	}
	// floor --rebuild refuses a symlink planted at the delivery record.
	p := filepath.Join(dir, deliveriesName)
	if err := os.Rename(p, p+".aside"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p+".aside", p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RebuildFloor(ctx, &attrRecorder{}); !errors.Is(err, errRebuildRefused) || !strings.Contains(err.Error(), "user/1001") {
		t.Fatalf("rebuild over a planted symlink: %v, want refused naming user/1001", err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p+".aside", p); err != nil {
		t.Fatal(err)
	}
	plants := []struct {
		name  string
		plant func(p string) error
		at    string
	}{
		{"symlink", func(p string) error { return os.Symlink(outside, p) }, filepath.Join(entry, "evil")},
		{"symlink to a directory", func(p string) error { return os.Symlink(filepath.Dir(outside), p) }, filepath.Join(dir, "evil-link")},
		{"fifo", func(p string) error { return syscall.Mkfifo(p, 0o600) }, filepath.Join(dir, "evil")},
		{"directory", func(p string) error { return os.MkdirAll(filepath.Join(p, "a", "b"), 0o700) }, filepath.Join(entry, "evil-dir")},
		{"fifo in a directory in the scope", func(p string) error {
			if err := os.Mkdir(p, 0o700); err != nil {
				return err
			}
			return syscall.Mkfifo(filepath.Join(p, "fifo"), 0o600)
		}, filepath.Join(dir, "evil-dir")},
	}
	for _, tc := range plants {
		if err := tc.plant(tc.at); err != nil {
			t.Fatalf("plant a %s: %v", tc.name, err)
		}
	}
	if _, err := s.RemoveScope(ctx, 1001); err != nil {
		t.Fatalf("rm-scope over planted names: %v", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope directory is still there: %v", err)
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "not the scope's" {
		t.Fatalf("rm-scope followed a planted symlink: %q, %v", b, err)
	}
}

// rm-scope that stops part-way says what state it left, and a rerun
// finishes the removal.
func TestRemoveScopeRerunFinishesPartialRemoval(t *testing.T) {
	if asRoot() {
		t.Skip("root removes in a read-only directory; the partial removal needs a non-root run")
	}
	ctx := context.Background()
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	entry := filepath.Join(dir, scopeEntriesName, "token")
	if err := os.Chmod(entry, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(entry, 0o700) })
	_, err := s.RemoveScope(ctx, 1001)
	if err == nil || !strings.Contains(err.Error(), "is listed as removed") || !strings.Contains(err.Error(), "partly or wholly present") || !strings.Contains(err.Error(), "rerun sudo k3sm keys rm-scope user/1001 --yes") || strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("a stopped rm-scope: %v; want the recorded, partly present state and the rerun", err)
	}
	if r := readRecord(t, s); r.keys() != 1 {
		t.Fatalf("the record lists %d keys, want 1", r.keys())
	}
	if err := os.Chmod(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	if recorded, err := s.RemoveScope(ctx, 1001); err != nil || !recorded {
		t.Fatalf("the rerun: %v, recorded %v", err, recorded)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope directory is still there after the rerun: %v", err)
	}

	// A directory left without scope.key is finished as it stands.
	if err := os.MkdirAll(filepath.Join(dir, scopeEntriesName, "left"), 0o700); err != nil {
		t.Fatal(err)
	}
	if recorded, err := s.RemoveScope(ctx, 1001); err != nil || !recorded {
		t.Fatalf("rm-scope of a directory without scope.key: %v, recorded %v", err, recorded)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the keyless scope directory is still there: %v", err)
	}
}
