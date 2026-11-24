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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// flagged is a flag source that reports SF_APPEND on every file.
func flagged(*os.File) (uint32, error) { return sfAppend, nil }

// withFileLogs gives s the file-backed logs in its data root, as install
// makes them: both files the service user's at 0600. The flag source
// reports SF_APPEND, which a non-root test cannot set.
func withFileLogs(t *testing.T, s *FileStore) {
	t.Helper()
	for _, n := range []string{userFloorLogName, auditLogName} {
		p := filepath.Join(s.dataRoot, logsDirName, logDirOf(n), n)
		if err := os.WriteFile(p, nil, logMode); err != nil {
			t.Fatal(err)
		}
		giveToService(t, p)
	}
	s.logFlags = flagged
	s.userFloor, s.auditSink = newFileFloorLog(s), newFileAuditLog(s)
}

// fileLogScope is newDeliveryScope over the file-backed logs: uid 1001's
// scope holding user/1001/token.
func fileLogScope(t *testing.T) (*FileStore, string, *UserScope) {
	t.Helper()
	s, server := newMasteredStore(t)
	withFileLogs(t, s)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1), 1002: guid(0xA2)})
	u := userScope(t, s, 1001)
	userPut(t, u, "user/1001/token", "a value")
	return s, server, u
}

func readLog(t *testing.T, s *FileStore, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.dataRoot, logsDirName, logDirOf(name), name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func appendLogBytes(t *testing.T, s *FileStore, name string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(s.dataRoot, logsDirName, logDirOf(name), name), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// U20: a user-scope current put back below the user-scope floor is refused,
// by Current and by List, with the user-scope floor message, which names
// floor --rebuild and says removing keystore-floor.json does not help. The
// user scope has no rotate yet, so the later write the copy predates is
// the floor line it would append (sequence 2); the pointer on disk is the
// older one, sequence 1.
func TestUserFloorRefusesCopiedBackCurrent(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	gen := entryGeneration(t, server, "token")
	if got, err := s.userFloor.floor("user/1001", "token", gen); err != nil || got != 1 {
		t.Fatalf("floor after put: %d, %v, want 1 (put appends its line)", got, err)
	}
	if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
		t.Fatalf("current at the floor: %v", err)
	}
	// A line of another generation, and a lower one, change nothing.
	line, err := floorLine("user/1001", "token", guid(0x77), 9)
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, line)
	if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
		t.Fatalf("current with another generation's line: %v", err)
	}
	if err := s.userFloor.append("user/1001", "token", gen, 2, false); err != nil {
		t.Fatal(err)
	}
	if err := s.userFloor.append("user/1001", "token", gen, 1, false); err != nil {
		t.Fatal(err)
	}
	_, _, err = u.Current(ctx, "user/1001/token")
	checkUserStale(t, "current", err)
	es, err := u.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 {
		t.Fatalf("list %+v", es)
	}
	checkUserStale(t, "list", es[0].Err)
}

func checkUserStale(t *testing.T, op string, err error) {
	t.Helper()
	var stale *userStaleError
	if !errors.Is(err, ErrCorrupt) || !errors.As(err, &stale) {
		t.Fatalf("%s of a copied-back current: %v, want the user-scope floor refusal", op, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "restore the matched set") || !strings.Contains(msg, "removing keystore-floor.json does not help") {
		t.Fatalf("%s: the message %q does not name the matched-set restore over removing keystore-floor.json", op, msg)
	}
}

// entryGeneration reads uid 1001's entry name's generation file.
func entryGeneration(t *testing.T, server, name string) [generationSize]byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, name))
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

// An absent user-scope floor does not let a withdraw re-seal the record it
// cannot check: the withdraw is refused with errWithdrawUnsealed, which says
// to delete the delivered Secret anyway, and nothing is sealed. A grant
// refuses without the floor too.
func TestWithdrawAbsentFloorProceeds(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName)); err != nil {
		t.Fatal(err)
	}
	before := readDeliveriesBytes(t, server)
	err := u.withdrawDelivery(ctx, testDelivery(1).uid)
	if !errors.Is(err, errWithdrawUnsealed) || errors.Is(err, errCommitted) || !strings.Contains(err.Error(), "delete the delivered Secret anyway") {
		t.Fatalf("withdraw with no floor: %v, want errWithdrawUnsealed naming the Secret's deletion", err)
	}
	if !bytes.Equal(before, readDeliveriesBytes(t, server)) {
		t.Fatal("a withdraw with no floor re-sealed the delivery record")
	}
	// A grant still refuses without the floor.
	if err := u.addDelivery(ctx, testDelivery(2)); !errors.Is(err, errLogMissing) {
		t.Fatalf("deliver with no floor: %v, want errLogMissing", err)
	}
}

// A user-scope floor past the reader's bound refuses even a withdraw, with
// ErrCorrupt naming the matched-set restore and what it brings back, and
// writes nothing: damage is not an absent floor. A line that does not
// parse, or a last line with no newline, is not this damage: the reader
// skips it (TestFloorGarbageTailIsSkippedDamage).
func TestWithdrawMalformedFloorRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(t *testing.T, s *FileStore)
	}{
		{"past its key bound", func(t *testing.T, s *FileStore) {
			// token's key, the delivery record's and one more: one past two.
			s.userFloor.(*fileFloorLog).log.maxKeys = 2
			line, err := floorLine("user/1001", "pad", guid(9), 1)
			if err != nil {
				t.Fatal(err)
			}
			appendLogBytes(t, s, userFloorLogName, line)
		}},
		{"past its size bound", func(t *testing.T, s *FileStore) {
			size := int64(len(readLog(t, s, userFloorLogName)))
			s.logSoftCap, s.logHardCap, s.logRevokeBudget = 1, 1, minLogRevokeBudget
			line, err := floorLine("user/1001", "pad", guid(9), 1)
			if err != nil {
				t.Fatal(err)
			}
			appendLogBytes(t, s, userFloorLogName, bytes.Repeat(line, int(s.logReadBound()-size)/len(line)+1))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, server, u := fileLogScope(t)
			if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
				t.Fatal(err)
			}
			tc.spoil(t, s)
			snap := treeSnapshot(t, server)
			err := u.withdrawDelivery(ctx, testDelivery(1).uid)
			if !errors.Is(err, ErrCorrupt) || !errors.Is(err, errFloorLogMalformed) || !strings.Contains(err.Error(), "matched set") || !strings.Contains(err.Error(), "brings back every entry deleted since the backup") {
				t.Fatalf("withdraw over a malformed floor: %v, want ErrCorrupt naming the matched-set restore", err)
			}
			checkTreeUnchanged(t, snap, treeSnapshot(t, server))
			if d, _ := recordedDelivery(t, s, server, 1); d.withdrawn {
				t.Fatal("the delivery was withdrawn over a malformed floor")
			}
			if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorLogMalformed) {
				t.Fatalf("current over a malformed floor: %v", err)
			}
		})
	}
}

// U21 (the store's half): a log whose SF_APPEND flag is clear, or which is
// not the service user's 0600 regular file with one link, is refused with a
// named error, and a grant over it writes nothing. The flag is read on the
// descriptor through the flag source.
func TestFlagCheckRefusesUnflagged(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	var seen []string
	s.logFlags = func(f *os.File) (uint32, error) {
		seen = append(seen, filepath.Base(f.Name()))
		return 0, nil
	}
	snap := treeSnapshot(t, server)
	audit := readLog(t, s, auditLogName)
	if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); !errors.Is(err, errLogNotAppendOnly) {
		t.Fatalf("put over unflagged logs: %v, want errLogNotAppendOnly", err)
	}
	if len(seen) == 0 {
		t.Fatal("the flag source was not consulted")
	}
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errLogNotAppendOnly) {
		t.Fatalf("current over an unflagged floor: %v, want errLogNotAppendOnly", err)
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, server))
	if !bytes.Equal(audit, readLog(t, s, auditLogName)) {
		t.Fatal("a line was appended to an unflagged audit log")
	}
	s.logFlags = func(*os.File) (uint32, error) { return 0, errors.New("injected") }
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errLogNotAppendOnly) {
		t.Fatalf("current when the flags cannot be read: %v, want errLogNotAppendOnly", err)
	}
	s.logFlags = flagged

	floorPath := filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName)
	t.Run("mode", func(t *testing.T) {
		chmod(t, floorPath, 0o640)
		defer chmod(t, floorPath, logMode)
		if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errLogUntrusted) {
			t.Fatalf("current over a 0640 floor: %v, want errLogUntrusted", err)
		}
	})
	t.Run("owner", func(t *testing.T) {
		other := *s
		other.uid = otherUID(t)
		f, err := os.Open(floorPath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		var st unix.Stat_t
		if err := other.judgeLog(f, &st); !errors.Is(err, errLogUntrusted) {
			t.Fatalf("a floor owned by another uid: %v, want errLogUntrusted", err)
		}
	})
	t.Run("hard link", func(t *testing.T) {
		link := filepath.Join(s.dataRoot, logsDirName, floorDirName, "floor-link")
		if err := os.Link(floorPath, link); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Remove(link) }()
		if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errLogUntrusted) {
			t.Fatalf("current over a floor with two links: %v, want errLogUntrusted", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		auditPath := filepath.Join(s.dataRoot, logsDirName, auditDirName, auditLogName)
		moved := auditPath + ".real"
		if err := os.Rename(auditPath, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, auditPath); err != nil {
			t.Fatal(err)
		}
		if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); !errors.Is(err, errLogUntrusted) {
			t.Fatalf("put over a symlinked audit log: %v, want errLogUntrusted", err)
		}
	})
	t.Run("start step and doctor check", testLogCheckRefusesAtStart)
}

// U23: every audited operation writes one v:1 line, and no line carries
// the value, its encodings or any length field.
func TestAuditLineNeverCarriesValue(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	value := []byte("s3cret-value-that-must-not-appear")
	if _, err := u.Put(ctx, "user/1001/secret", KindOpaque, value); err != nil {
		t.Fatal(err)
	}
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatal(err)
	}
	if err := u.Delete(ctx, "user/1001/secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Put(ctx, "user/1001/token", KindOpaque, value); !errors.Is(err, ErrExists) {
		t.Fatalf("put over an entry: %v, want ErrExists", err)
	}
	b := readLog(t, s, auditLogName)
	lines := nonEmptyLines(b)
	// fileLogScope's put of token, then the five above.
	wantOps := []string{"put", "put", "deliver", "withdraw", "rm", "put"}
	if len(lines) != len(wantOps) {
		t.Fatalf("%d audit lines, want %d:\n%s", len(lines), len(wantOps), b)
	}
	for i, line := range lines {
		r, err := parseAuditLine(line)
		if err != nil {
			t.Fatalf("line %d %q: %v", i, line, err)
		}
		if r.V != 1 || r.Op != wantOps[i] || r.Scope != "user/1001" || r.TS == "" {
			t.Fatalf("line %d: %+v, want v 1, op %s", i, r, wantOps[i])
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		for k := range m {
			switch k {
			case "v", "ts", "op", "scope", "name", "namespace", "delivery", "result":
			case "version", "fingerprint":
				// The version a put wrote and its per-scope keyed
				// fingerprint: never the value, never its length.
				if r.Op != "put" || r.Result != "ok" {
					t.Fatalf("line %d (%s %s) carries %q", i, r.Op, r.Result, k)
				}
			default:
				t.Fatalf("line %d carries the field %q", i, k)
			}
		}
	}
	for _, enc := range [][]byte{value, []byte(base64.StdEncoding.EncodeToString(value)), []byte(hex.EncodeToString(value))} {
		if bytes.Contains(b, enc) {
			t.Fatalf("the audit log carries the value (%q)", enc)
		}
	}
	if r, _ := parseAuditLine(lines[len(lines)-1]); r.Result != "exists" {
		t.Fatalf("refused put's result %q, want exists", r.Result)
	}
}

// U23: the reader ignores fields it does not know, and refuses another
// format version, a line that is not a JSON object, and one over 1 KiB.
func TestAuditReaderIgnoresUnknownFields(t *testing.T) {
	r, err := parseAuditLine([]byte(`{"v":1,"ts":"2026-11-22T00:00:00Z","op":"put","via":"socket","caller":{"uid":501,"user":"alice","pid":4242},"scope":"user/501","name":"a","namespace":"","result":"ok","future":[1,2,3]}`))
	if err != nil {
		t.Fatalf("a line with unknown fields: %v", err)
	}
	if r.Op != "put" || r.Scope != "user/501" || r.Name != "a" || r.Result != "ok" {
		t.Fatalf("parsed %+v", r)
	}
	for name, line := range map[string]string{
		"another version": `{"v":2,"op":"put"}`,
		"no version":      `{"op":"put"}`,
		"not an object":   `[1]`,
		"not json":        `put ok`,
		"over 1 KiB":      `{"v":1,"name":"` + strings.Repeat("a", maxLogLine) + `"}`,
	} {
		if _, err := parseAuditLine([]byte(line)); err == nil {
			t.Errorf("%s: accepted %q", name, line)
		}
	}
}

// U24: past the hard cap every mutating user operation is ErrLogFull and
// writes nothing, an rm or withdraw that revokes nothing included; a
// revocation still goes ahead, drawing on its own uid's revocation budget,
// and is refused only once that budget is spent, never for another uid's
// lines. LogSizes reports the sizes and caps for the doctor row.
func TestLogHardCapRefusesMutations(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	u2 := userScope(t, s, 1002)
	userPut(t, u2, "user/1002/token", "b")
	for i := 1; i <= 3; i++ {
		if err := u.addDelivery(ctx, testDelivery(i)); err != nil {
			t.Fatal(err)
		}
	}
	userPut(t, u, "user/1001/second", "c")
	sizes, err := s.LogSizes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sizes.UserFloor != int64(len(readLog(t, s, userFloorLogName))) || sizes.Audit != int64(len(readLog(t, s, auditLogName))) ||
		sizes.SoftCap != defaultLogSoftCap || sizes.HardCap != defaultLogHardCap {
		t.Fatalf("LogSizes %+v", sizes)
	}
	// Both logs are now at or past a hard cap of the smaller one's size.
	s.logHardCap = min(sizes.UserFloor, sizes.Audit)
	s.logSoftCap = s.logHardCap
	s.logRevokeBudget = 3 * maxLogLine

	snap := treeSnapshot(t, server)
	floorBefore, auditBefore := readLog(t, s, userFloorLogName), readLog(t, s, auditLogName)
	if _, err := u.Put(ctx, "user/1001/new", KindOpaque, []byte("v")); !errors.Is(err, ErrLogFull) {
		t.Fatalf("put past the hard cap: %v, want ErrLogFull", err)
	}
	if err := u.addDelivery(ctx, testDelivery(9)); !errors.Is(err, ErrLogFull) {
		t.Fatalf("deliver past the hard cap: %v, want ErrLogFull", err)
	}
	if err := u.Delete(ctx, "user/1001/absent"); !errors.Is(err, ErrLogFull) {
		t.Fatalf("rm of an absent entry past the hard cap: %v, want ErrLogFull", err)
	}
	if err := u.withdrawDelivery(ctx, "00000000-0000-0000-0000-999999999999"); !errors.Is(err, ErrLogFull) {
		t.Fatalf("withdraw of an absent delivery past the hard cap: %v, want ErrLogFull", err)
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, server))
	if !bytes.Equal(floorBefore, readLog(t, s, userFloorLogName)) || !bytes.Equal(auditBefore, readLog(t, s, auditLogName)) {
		t.Fatal("a refused operation appended a line past the hard cap")
	}

	// The revocation class goes ahead, on uid 1001's budget.
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw past the hard cap: %v", err)
	}
	if err := u.Delete(ctx, "user/1001/second"); err != nil {
		t.Fatalf("rm past the hard cap: %v", err)
	}
	checkEntryGone(t, server, "second")
	// Spend the rest of uid 1001's budget in the audit log; its next
	// revocation is refused and changes nothing.
	spend, err := marshalAuditLine(auditLine{op: "rm", scope: "user/1001", name: "token", result: "ok"}, s.now())
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, auditLogName, bytes.Repeat(spend, 2*maxLogLine/len(spend)+1))
	auditUsed := int64(len(readLog(t, s, auditLogName))) - max(s.logHardCap, sizes.Audit)
	s.logRevokeBudget = auditUsed + maxLogLine - 1
	if err := u.withdrawDelivery(ctx, testDelivery(2).uid); !errors.Is(err, ErrLogFull) {
		t.Fatalf("withdraw with the budget spent: %v, want ErrLogFull", err)
	}
	if d, _ := recordedDelivery(t, s, server, 2); d.withdrawn {
		t.Fatal("a withdraw refused for its budget wrote its tombstone")
	}
	// Another uid's revocation is not refused for uid 1001's lines.
	if err := u2.Delete(ctx, "user/1002/token"); err != nil {
		t.Fatalf("uid 1002's rm after uid 1001 spent its budget: %v", err)
	}

	t.Run("config", func(t *testing.T) {
		for _, c := range []Config{{LogSoftCap: -1}, {LogHardCap: 10, LogSoftCap: 11}, {LogRevocationBudget: -1}} {
			bad := New(Config{Dir: s.dir, MasterDir: s.masterDir, UID: s.uid, GID: s.gid, DataRoot: s.dataRoot,
				FloorUID: s.floorUID, FloorGID: s.floorGID, LogSoftCap: c.LogSoftCap, LogHardCap: c.LogHardCap, LogRevocationBudget: c.LogRevocationBudget})
			if err := bad.checkConfig(); !errors.Is(err, errInvalidConfig) {
				t.Errorf("caps %+v: %v, want errInvalidConfig", c, err)
			}
		}
	})
}

// U24: a line over 1 KiB is refused and never written, by the audit log
// and by the floor; the longest line the store can write today fits.
func TestAuditLineBoundedAtOneKiB(t *testing.T) {
	s, _, _ := fileLogScope(t)
	before := readLog(t, s, auditLogName)
	long := auditLine{op: "put", scope: "user/1001", name: strings.Repeat("a", maxLogLine), result: "ok"}
	if err := s.auditSink.append(long); !errors.Is(err, errLogLineTooLong) {
		t.Fatalf("a line over 1 KiB: %v, want errLogLineTooLong", err)
	}
	if !bytes.Equal(before, readLog(t, s, auditLogName)) {
		t.Fatal("a line over 1 KiB was written")
	}
	if _, err := parseFloorLine(bytes.Repeat([]byte("a"), maxLogLine)); !errors.Is(err, errLogLineTooLong) {
		t.Fatalf("a floor line over 1 KiB: %v", err)
	}
	if err := s.userFloor.append("user/1001", strings.Repeat("a", maxLogLine), guid(1), 1, false); err == nil {
		t.Fatal("a floor line with an over-long name was written")
	}
	// The widest line: the longest name, namespace and delivery UID, the
	// widest uid, and every op and result this package writes.
	widest := auditLine{
		op: "withdraw", scope: "user/2147483647", name: strings.Repeat("a", maxNameLen),
		namespace: strings.Repeat("n", 63), delivery: testDelivery(1).uid, result: "scope-absent", revoke: true,
	}
	if b, err := marshalAuditLine(widest, s.now()); err != nil || len(b) > maxLogLine {
		t.Fatalf("the widest audit line: %d bytes, %v", len(b), err)
	}
	if b, err := floorLine("user/2147483647", strings.Repeat("a", maxNameLen), guid(1), ^uint64(0)); err != nil || len(b) > maxLogLine {
		t.Fatalf("the widest floor line: %d bytes, %v", len(b), err)
	}
}
