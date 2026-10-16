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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLedgerGetCancelRemove(t *testing.T) {
	l, now := testLedger(t)
	r, err := l.Start(Record{Tag: "a:v1"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := l.Get(r.ID)
	if err != nil || got.ID != r.ID || got.Status != StatusRunning {
		t.Fatalf("get = %+v, %v", got, err)
	}
	*now = now.Add(4 * time.Second)
	c, err := l.Cancel(got)
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != StatusCancelled || c.FinishedAt == nil || c.Duration(time.Time{}) != 4*time.Second {
		t.Errorf("cancelled = %+v", c)
	}
	w, err := l.CreateLog(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "out\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.CreateLog(r.ID); err == nil {
		t.Error("a second log over an existing one was created")
	}
	if fi, err := os.Stat(l.LogPath(r.ID)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("log mode = %v, %v; want 0600", fi, err)
	}
	if err := l.Remove(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(r.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after remove = %v, want ErrNotFound", err)
	}
	if _, err := l.OpenLog(r.ID); !errors.Is(err, ErrNoLog) {
		t.Errorf("open log after remove = %v, want ErrNoLog", err)
	}
	if err := l.Remove(r.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a second remove = %v, want ErrNotFound", err)
	}
	for _, bad := range []string{"", "../etc", "ABCDEFABCDEF", "aaaaaaaaaaaa/"} {
		if _, err := l.Get(bad); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("get %q = %v, want an invalid-id error", bad, err)
		}
	}
}

func TestLedgerOpenLogRefusesALink(t *testing.T) {
	l, _ := testLedger(t)
	r, err := l.Start(Record{Tag: "a:v1"})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, l.LogPath(r.ID)); err != nil {
		t.Fatal(err)
	}
	if f, err := l.OpenLog(r.ID); err == nil {
		f.Close()
		t.Error("a symlinked log was opened")
	}
	if _, err := l.CreateLog(r.ID); err == nil {
		t.Error("a log was created through a symlink")
	}
}

func TestLogWriterIsBoundedAndNeverFails(t *testing.T) {
	l, _ := testLedger(t)
	r, err := l.Start(Record{Tag: "a:v1"})
	if err != nil {
		t.Fatal(err)
	}
	w, err := l.CreateLog(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	w.max = 10
	for _, chunk := range []string{"12345", "67890abc", "more"} {
		if n, err := w.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Errorf("write %q = %d, %v; want all of it, no error", chunk, n, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := w.Write([]byte("after close")); err != nil || n != 11 {
		t.Errorf("write after close = %d, %v", n, err)
	}
	data, err := os.ReadFile(l.LogPath(r.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "1234567890\n[k3sm: log truncated at 10 bytes]") || strings.Contains(string(data), "more") {
		t.Errorf("log = %q", data)
	}
}

func TestLedgerPruneTakesTheLog(t *testing.T) {
	l, now := testLedger(t)
	l.max = 1
	var ids []string
	for i := range 2 {
		*now = now.Add(time.Minute)
		r, err := l.Start(Record{Tag: fmt.Sprintf("t:%d", i)})
		if err != nil {
			t.Fatal(err)
		}
		w, err := l.CreateLog(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		ids = append(ids, r.ID)
	}
	// The prune ran on the second Start, before the second log existed; the
	// next write prunes again with both logs present.
	*now = now.Add(time.Minute)
	if _, err := l.Start(Record{Tag: "t:2"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if _, err := os.Stat(l.LogPath(id)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the log of pruned record %s survived: %v", id, err)
		}
	}
}
