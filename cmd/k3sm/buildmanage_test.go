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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/builder"
	"k3sm.io/k3sm/pkg/buildledger"
)

// shortLedger is a ledger in a directory short enough to hold a cancel socket
// (darwin's sun_path is 104 bytes, and t.TempDir() can be longer).
func shortLedger(t *testing.T) *buildledger.Ledger {
	t.Helper()
	dir, err := os.MkdirTemp("", "bl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return buildledger.New(filepath.Join(dir, "builds"))
}

// TestBuildCancelStopsARunningEngineBuild drives `build cancel` against a real
// build in flight: an engine build that prints to both streams and then blocks
// until its context ends. The cancel returns once the build has recorded
// itself cancelled, the build returns ErrCancelled, and the stored log holds
// what the build printed on both streams.
func TestBuildCancelStopsARunningEngineBuild(t *testing.T) {
	l := shortLedger(t)
	ctxDir := writeCtx(t, "FROM scratch\nRUN make\n")
	o := buildOptions{dockerfile: filepath.Join(ctxDir, "Dockerfile"), tag: "app:v1", format: "docker", contextDir: ctxDir, platforms: []string{"darwin/arm64"}}
	engineFor := func(storeRecorder) engineBuilder {
		return func(ctx context.Context, _ buildOptions, out io.Writer) error {
			fmt.Fprintln(out, "stdout line")
			fmt.Fprintln(stderrOf(out), "#1 [internal] load build definition")
			<-ctx.Done()
			return fmt.Errorf("exec buildx: %w", ctx.Err())
		}
	}
	var terminal syncBuffer
	done := make(chan error, 1)
	go func() { done <- buildRecorded(t.Context(), l, o, &terminal, engineFor, noStore, noPush) }()

	var id string
	deadline := time.Now().Add(5 * time.Second)
	for {
		if recs, _ := l.List(); len(recs) == 1 && builder.BuildAlive(t.Context(), l.CancelPath(recs[0].ID)) {
			id = recs[0].ID
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the build never started listening for a cancel")
		}
		time.Sleep(5 * time.Millisecond)
	}

	var out bytes.Buffer
	if err := cancelBuild(t.Context(), &out, l, id, builder.RequestCancel); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if !strings.Contains(out.String(), "cancelled build "+id) {
		t.Errorf("cancel printed %q", out.String())
	}
	if err := <-done; !errors.Is(err, builder.ErrCancelled) {
		t.Errorf("the build returned %v, want ErrCancelled", err)
	}
	r, err := l.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != buildledger.StatusCancelled || r.FinishedAt == nil || r.Error != "" {
		t.Errorf("record = %+v, want cancelled with a finish time", r)
	}
	if !strings.Contains(terminal.String(), "stdout line") {
		t.Errorf("the terminal lost the build's output: %q", terminal.String())
	}
	var logOut bytes.Buffer
	if err := showBuildLog(t.Context(), &logOut, io.Discard, l, id, false, time.Millisecond, builder.BuildAlive); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"stdout line", "#1 [internal] load build definition"} {
		if !strings.Contains(logOut.String(), want) {
			t.Errorf("the stored log lacks %q:\n%s", want, logOut.String())
		}
	}
	if err := cancelBuild(t.Context(), io.Discard, l, id, builder.RequestCancel); err == nil || !strings.Contains(err.Error(), "already finished (cancelled)") {
		t.Errorf("a second cancel = %v, want the finished refusal", err)
	}
}

// writeBuildRecord installs a record with a log for the verb tests.
func writeBuildRecord(t *testing.T, l *buildledger.Ledger, id string, st buildledger.Status, log string) buildledger.Record {
	t.Helper()
	r := buildledger.Record{ID: id, Tag: "a:v1", StartedAt: time.Now().Add(-time.Minute).UTC(), Status: st}
	if st != buildledger.StatusRunning {
		f := time.Now().UTC()
		r.FinishedAt = &f
	}
	if err := l.Write(r); err != nil {
		t.Fatal(err)
	}
	w, err := l.CreateLog(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, log); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestBuildCancelOfAnOrphanedRecord(t *testing.T) {
	l := buildledger.New(filepath.Join(t.TempDir(), "builds"))
	writeBuildRecord(t, l, "aaaaaaaaaaaa", buildledger.StatusRunning, "")
	calls := 0
	gone := func(context.Context, string) error { calls++; return builder.ErrNoBuildProcess }
	var out bytes.Buffer
	if err := cancelBuild(t.Context(), &out, l, "aaaaaaaaaaaa", gone); err != nil {
		t.Fatal(err)
	}
	if calls != cancelRetries {
		t.Errorf("asked %d times, want %d", calls, cancelRetries)
	}
	r, err := l.Get("aaaaaaaaaaaa")
	if err != nil || r.Status != buildledger.StatusCancelled || r.FinishedAt == nil {
		t.Errorf("record = %+v, %v; want cancelled", r, err)
	}
	if !strings.Contains(out.String(), "no running process") {
		t.Errorf("cancel printed %q", out.String())
	}
	if err := cancelBuild(t.Context(), io.Discard, l, "bbbbbbbbbbbb", gone); !errors.Is(err, buildledger.ErrNotFound) {
		t.Errorf("an unknown id = %v, want ErrNotFound", err)
	}
	if err := cancelBuild(t.Context(), io.Discard, l, "../x", gone); err == nil {
		t.Error("a malformed id was accepted")
	}
}

func TestBuildRm(t *testing.T) {
	l := buildledger.New(filepath.Join(t.TempDir(), "builds"))
	writeBuildRecord(t, l, "aaaaaaaaaaaa", buildledger.StatusRunning, "x")
	writeBuildRecord(t, l, "bbbbbbbbbbbb", buildledger.StatusFailed, "y")
	if err := removeBuild(io.Discard, l, "aaaaaaaaaaaa"); err == nil || !strings.Contains(err.Error(), "k3sm build cancel aaaaaaaaaaaa") {
		t.Errorf("rm of a running build = %v, want the refusal naming cancel", err)
	}
	var out bytes.Buffer
	if err := removeBuild(&out, l, "bbbbbbbbbbbb"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get("bbbbbbbbbbbb"); !errors.Is(err, buildledger.ErrNotFound) {
		t.Errorf("the record survived rm: %v", err)
	}
	if _, err := os.Stat(l.LogPath("bbbbbbbbbbbb")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the log survived rm: %v", err)
	}
	if _, err := l.Get("aaaaaaaaaaaa"); err != nil {
		t.Errorf("rm touched another record: %v", err)
	}
	if err := removeBuild(io.Discard, l, "bbbbbbbbbbbb"); !errors.Is(err, buildledger.ErrNotFound) {
		t.Errorf("a second rm = %v, want ErrNotFound", err)
	}
}

func TestBuildLogs(t *testing.T) {
	alive := func(context.Context, string) bool { return true }

	t.Run("prints the stored log", func(t *testing.T) {
		l := buildledger.New(filepath.Join(t.TempDir(), "builds"))
		writeBuildRecord(t, l, "aaaaaaaaaaaa", buildledger.StatusSucceeded, "step 1\nstep 2\n")
		var out bytes.Buffer
		if err := showBuildLog(t.Context(), &out, io.Discard, l, "aaaaaaaaaaaa", true, time.Millisecond, alive); err != nil {
			t.Fatal(err)
		}
		if out.String() != "step 1\nstep 2\n" {
			t.Errorf("logs = %q", out.String())
		}
	})

	t.Run("follows a running build until it finishes", func(t *testing.T) {
		l := buildledger.New(filepath.Join(t.TempDir(), "builds"))
		r := writeBuildRecord(t, l, "aaaaaaaaaaaa", buildledger.StatusRunning, "")
		f, err := os.OpenFile(l.LogPath(r.ID), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		var out syncBuffer
		done := make(chan error, 1)
		go func() {
			done <- showBuildLog(t.Context(), &out, io.Discard, l, r.ID, true, 5*time.Millisecond, alive)
		}()
		for i := range 3 {
			fmt.Fprintf(f, "line %d\n", i)
			time.Sleep(20 * time.Millisecond)
		}
		select {
		case err := <-done:
			t.Fatalf("follow returned while the build ran: %v", err)
		default:
		}
		fmt.Fprintln(f, "last")
		if _, err := l.Finish(r, "sha256:abc", nil); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("follow did not return when the build finished")
		}
		if out.String() != "line 0\nline 1\nline 2\nlast\n" {
			t.Errorf("followed log = %q", out.String())
		}
	})

	t.Run("stops following an orphaned record", func(t *testing.T) {
		l := buildledger.New(filepath.Join(t.TempDir(), "builds"))
		writeBuildRecord(t, l, "aaaaaaaaaaaa", buildledger.StatusRunning, "partial\n")
		var out, errOut bytes.Buffer
		dead := func(context.Context, string) bool { return false }
		if err := showBuildLog(t.Context(), &out, &errOut, l, "aaaaaaaaaaaa", true, time.Millisecond, dead); err != nil {
			t.Fatal(err)
		}
		if out.String() != "partial\n" || !strings.Contains(errOut.String(), "no running process") {
			t.Errorf("out %q, err %q", out.String(), errOut.String())
		}
	})

	t.Run("a record without a log", func(t *testing.T) {
		l := buildledger.New(filepath.Join(t.TempDir(), "builds"))
		if err := l.Write(buildledger.Record{ID: "aaaaaaaaaaaa", StartedAt: time.Now().UTC(), Status: buildledger.StatusFailed}); err != nil {
			t.Fatal(err)
		}
		if err := showBuildLog(t.Context(), io.Discard, io.Discard, l, "aaaaaaaaaaaa", false, time.Millisecond, alive); !errors.Is(err, buildledger.ErrNoLog) {
			t.Errorf("logs = %v, want ErrNoLog", err)
		}
	})
}

// fakePruner records which prune was asked for.
type fakePruner struct {
	planned, pruned []bool
	rep             builder.CacheReport
}

func (f *fakePruner) PlanPrune(_ context.Context, all bool) (builder.CacheReport, error) {
	f.planned = append(f.planned, all)
	return f.rep, nil
}

func (f *fakePruner) PruneCache(_ context.Context, all bool) (builder.CacheReport, error) {
	f.pruned = append(f.pruned, all)
	return f.rep, nil
}

func TestBuildPruneIsADryRunUnlessForced(t *testing.T) {
	p := &fakePruner{rep: builder.CacheReport{Records: 3, Bytes: 3 << 20}}
	var out bytes.Buffer
	if err := pruneBuildCache(t.Context(), &out, p, true, false); err != nil {
		t.Fatal(err)
	}
	if len(p.pruned) != 0 || len(p.planned) != 1 || !p.planned[0] {
		t.Errorf("dry run: planned %v pruned %v", p.planned, p.pruned)
	}
	if !strings.Contains(out.String(), "would reclaim 3.0 MiB (3145728 bytes) from 3 cache record(s)") || !strings.Contains(out.String(), "--force") {
		t.Errorf("dry run printed %q", out.String())
	}
	out.Reset()
	if err := pruneBuildCache(t.Context(), &out, p, false, true); err != nil {
		t.Fatal(err)
	}
	if len(p.pruned) != 1 || p.pruned[0] {
		t.Errorf("force: pruned %v", p.pruned)
	}
	if !strings.Contains(out.String(), "reclaimed 3.0 MiB (3145728 bytes)") {
		t.Errorf("force printed %q", out.String())
	}
	if err := runBuildPrune(t.Context(), []string{"extra"}, io.Discard); err == nil {
		t.Error("a positional argument was accepted")
	}
}

func TestBuildVerbsTakeOneID(t *testing.T) {
	for _, args := range [][]string{nil, {"a", "b"}} {
		if err := runBuildManage("rm", args); err == nil || !strings.Contains(err.Error(), "exactly one build id") {
			t.Errorf("rm %v = %v", args, err)
		}
	}
}
