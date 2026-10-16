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

package buildledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLedger(t *testing.T) (*Ledger, *time.Time) {
	t.Helper()
	l := New(filepath.Join(t.TempDir(), "builds"))
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }
	return l, &now
}

// TestLedgerKeepsTheNewest200 pins the bound: a write past MaxRecords removes
// the oldest records, and only those.
func TestLedgerKeepsTheNewest200(t *testing.T) {
	l, _ := testLedger(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const extra = 5
	for i := range MaxRecords + extra {
		r := Record{ID: fmt.Sprintf("%012x", i), Tag: "t:v1", StartedAt: t0.Add(time.Duration(i) * time.Minute), Status: StatusSucceeded}
		if err := l.Write(r); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	recs, err := l.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != MaxRecords {
		t.Fatalf("ledger holds %d records, want %d", len(recs), MaxRecords)
	}
	if recs[0].ID != fmt.Sprintf("%012x", MaxRecords+extra-1) || recs[len(recs)-1].ID != fmt.Sprintf("%012x", extra) {
		t.Errorf("kept %s..%s, want the newest %d", recs[0].ID, recs[len(recs)-1].ID, MaxRecords)
	}
	des, err := os.ReadDir(l.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != MaxRecords {
		t.Errorf("directory holds %d entries, want %d", len(des), MaxRecords)
	}
	for i := range extra {
		if _, err := os.Stat(filepath.Join(l.Dir(), fmt.Sprintf("%012x.json", i))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("record %d survived the bound: %v", i, err)
		}
	}
}

// TestLedgerStartFinish pins the record lifecycle and the file modes.
func TestLedgerStartFinish(t *testing.T) {
	l, now := testLedger(t)
	start := *now
	r, err := l.Start(Record{Tag: "a:v1", Engine: EngineNative, Status: StatusFailed, Error: "stale"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.ID) != 12 || r.Status != StatusRunning || !r.StartedAt.Equal(start) || r.FinishedAt != nil || r.Error != "" {
		t.Errorf("started = %+v", r)
	}
	*now = now.Add(7 * time.Second)
	done, err := l.Finish(r, "sha256:abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != StatusSucceeded || done.ImageDigest != "sha256:abc" || done.Duration(time.Time{}) != 7*time.Second {
		t.Errorf("finished = %+v", done)
	}
	recs, err := l.List()
	if err != nil || len(recs) != 1 || recs[0].Status != StatusSucceeded {
		t.Fatalf("list = %+v, %v; want the one rewritten record", recs, err)
	}

	fi, err := os.Stat(l.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %v, want 0700", fi.Mode().Perm())
	}
	fi, err = os.Stat(filepath.Join(l.Dir(), r.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %v, want 0600", fi.Mode().Perm())
	}

	failed, err := l.Finish(r, "sha256:ignored", errors.New(strings.Repeat("é", MaxErrorBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if failed.Status != StatusFailed || failed.ImageDigest != "" || len(failed.Error) > MaxErrorBytes || len(failed.Error) < MaxErrorBytes-1 {
		t.Errorf("failed record: status %s digest %q error %d bytes", failed.Status, failed.ImageDigest, len(failed.Error))
	}
	if !strings.HasPrefix(strings.Repeat("é", MaxErrorBytes), failed.Error) {
		t.Error("the clipped error split a rune")
	}
}

// TestLedgerWidensNothingAndSkipsJunk pins the directory narrowing and the
// reader's tolerance: a wider existing directory is narrowed, and files that
// are not records, or records that do not decode, never reach the listing.
func TestLedgerWidensNothingAndSkipsJunk(t *testing.T) {
	l, _ := testLedger(t)
	if err := os.MkdirAll(l.Dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"notes.txt":                  "hi",
		"0123456789ab.json":          "{not json",
		"ffffffffffff.json":          `{"id":"eeeeeeeeeeee"}`,
		".aaaaaaaaaaaa.json.tmp-123": `{"id":"aaaaaaaaaaaa"}`,
	} {
		if err := os.WriteFile(filepath.Join(l.Dir(), name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := l.Start(Record{Tag: "a:v1"})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(l.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %v, want 0700", fi.Mode().Perm())
	}
	recs, err := l.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ID != r.ID {
		t.Errorf("list = %+v, want only %s", recs, r.ID)
	}
	if err := l.Write(Record{ID: "../escape"}); err == nil {
		t.Error("a record id with a path in it was written")
	}
}

// TestLedgerRedactsBeforeClipping pins the order in Finish: the error is
// redacted first, so a credential near the clip boundary cannot survive as a
// partial match the redactor no longer recognises.
func TestLedgerRedactsBeforeClipping(t *testing.T) {
	l, _ := testLedger(t)
	r, err := l.Start(Record{Tag: "a:v1"})
	if err != nil {
		t.Fatal(err)
	}
	msg := strings.Repeat("x", MaxErrorBytes-30) + " https://user:hunter2@registry.example.com/v2/"
	done, err := l.Finish(r, "", errors.New(msg))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(done.Error, "hunter2") || strings.Contains(done.Error, "user:") {
		t.Errorf("stored error kept the credential: %q", done.Error[len(done.Error)-60:])
	}
}

// TestLedgerRefusesASymlinkedDirectory pins that the records never follow a
// symlink at the ledger path.
func TestLedgerRefusesASymlinkedDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	l := New(filepath.Join(base, "builds"))
	if err := os.Symlink(target, l.Dir()); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Start(Record{Tag: "a:v1"}); err == nil {
		t.Fatal("a symlinked ledger directory was written through")
	}
	des, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != 0 {
		t.Errorf("the symlink target gained %d entries", len(des))
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("the symlink target's mode changed to %v", fi.Mode().Perm())
	}
}

// TestLedgerNarrowsOnlyAnOwnedDirectory pins the chmod: a wider directory this
// user owns is narrowed to 0700, and one another user owns is neither narrowed
// nor written.
func TestLedgerNarrowsOnlyAnOwnedDirectory(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owned bool
	}{{"owned is narrowed", true}, {"not owned is refused", false}} {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := testLedger(t)
			if err := os.MkdirAll(l.Dir(), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(l.Dir(), 0o755); err != nil {
				t.Fatal(err)
			}
			if !tc.owned {
				real := geteuid()
				geteuid = func() int { return real + 1 }
				t.Cleanup(func() { geteuid = os.Geteuid })
			}
			_, err := l.Start(Record{Tag: "a:v1"})
			fi, serr := os.Stat(l.Dir())
			if serr != nil {
				t.Fatal(serr)
			}
			des, _ := os.ReadDir(l.Dir())
			if tc.owned {
				if err != nil || fi.Mode().Perm() != 0o700 || len(des) != 1 {
					t.Errorf("owned: err %v, mode %v, %d entries; want nil, 0700, 1", err, fi.Mode().Perm(), len(des))
				}
				return
			}
			if err == nil || fi.Mode().Perm() != 0o755 || len(des) != 0 {
				t.Errorf("not owned: err %v, mode %v, %d entries; want an error, 0755, 0", err, fi.Mode().Perm(), len(des))
			}
		})
	}
}

// TestDefaultDirRefusesAHomeAnotherUserOwns pins the sudo case: as root in the
// operator's home the ledger records nothing rather than leaving root-owned
// files there.
func TestDefaultDirRefusesAHomeAnotherUserOwns(t *testing.T) {
	home := t.TempDir()
	got, err := defaultDir(home, os.Geteuid())
	if err != nil || got != filepath.Join(home, ".k3sm", "builds") {
		t.Errorf("own home: %q, %v", got, err)
	}
	if _, err := defaultDir(home, os.Geteuid()+1); err == nil {
		t.Error("a home owned by another uid was accepted")
	}
	if _, err := defaultDir("", os.Geteuid()); err == nil {
		t.Error("an empty home was accepted")
	}
}

// TestLedgerPruneFailureIsNotAWriteFailure pins that a record which was
// installed is reported as written even when removing old ones fails.
func TestLedgerPruneFailureIsNotAWriteFailure(t *testing.T) {
	l, _ := testLedger(t)
	l.max = 1
	l.remove = func(string) error { return errors.New("operation not permitted") }
	for i := range 2 {
		if _, err := l.Start(Record{Tag: fmt.Sprintf("t:%d", i)}); err != nil {
			t.Fatalf("write %d returned the prune failure: %v", i, err)
		}
	}
	recs, err := l.List()
	if err != nil || len(recs) != 2 {
		t.Errorf("list = %d records, %v; want both installed", len(recs), err)
	}
}

// TestLedgerReadIsBounded pins the reader's two limits: an oversized record
// file is skipped, and a future start time cannot keep a record newest and
// out of the prune.
func TestLedgerReadIsBounded(t *testing.T) {
	l, now := testLedger(t)
	l.max = 3
	big := Record{ID: "0000000000aa", Tag: strings.Repeat("x", maxRecordBytes), StartedAt: now.Add(-time.Hour)}
	data, err := json.Marshal(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(l.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.Dir(), big.ID+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if recs, err := l.List(); err != nil || len(recs) != 0 {
		t.Errorf("an oversized record was listed: %d, %v", len(recs), err)
	}
	if err := os.Remove(filepath.Join(l.Dir(), big.ID+".json")); err != nil {
		t.Fatal(err)
	}

	future := Record{ID: "ffffffffffff", Tag: "future:v1", StartedAt: now.AddDate(10, 0, 0), Status: StatusRunning}
	if err := l.Write(future); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		r := Record{ID: fmt.Sprintf("%012x", i+1), Tag: "t:v1", StartedAt: now.Add(time.Duration(i-3) * time.Minute), Status: StatusSucceeded}
		if err := l.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := l.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || recs[0].ID != "000000000003" {
		t.Fatalf("list = %+v, want the three dated records, newest first", recs)
	}
	for _, r := range recs {
		if r.ID == future.ID {
			t.Error("the future-dated record survived the prune")
		}
	}
}
