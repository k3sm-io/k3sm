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
