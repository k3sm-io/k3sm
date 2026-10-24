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
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/buildledger"
)

// TestBuildLsListsTheLedgerAsJSON pins the listing contract: `build ls -o json`
// prints every record newest first with every field, verbatim, and `build ls`
// prints the same order as a table.
func TestBuildLsListsTheLedgerAsJSON(t *testing.T) {
	l := buildledger.New(filepath.Join(t.TempDir(), "builds"))
	t0 := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	fin := func(d time.Duration) *time.Time { v := t0.Add(d); return &v }

	failed := buildledger.Record{
		ID: "aaaaaaaaaaaa", Dockerfile: "/src/a/Dockerfile", Context: "/src/a", Tag: "a:v1",
		Platform: "darwin/arm64", Engine: buildledger.EngineNative,
		StartedAt: t0, FinishedAt: fin(3 * time.Second),
		Status: buildledger.StatusFailed, Error: "COPY app: no such file",
	}
	succeeded := buildledger.Record{
		ID: "bbbbbbbbbbbb", Dockerfile: "/src/b/Dockerfile", Context: "/src/b", Tag: "b:v1",
		Platform: "linux/arm64,linux/amd64", Engine: buildledger.EngineBuildEngine,
		StartedAt: t0.Add(time.Minute), FinishedAt: fin(time.Minute + 95*time.Second),
		Status: buildledger.StatusSucceeded, ImageDigest: "sha256:" + strings.Repeat("ab", 32),
	}
	running := buildledger.Record{
		ID: "cccccccccccc", Dockerfile: "/src/c/Dockerfile", Context: "/src/c", Tag: "c:v1",
		Platform: "linux/arm64", Engine: buildledger.EngineBuildEngine,
		StartedAt: t0.Add(2 * time.Minute), Status: buildledger.StatusRunning,
	}
	// Written out of order, so the listing's order is the ledger's, not the
	// write order's.
	for _, r := range []buildledger.Record{succeeded, running, failed} {
		if err := l.Write(r); err != nil {
			t.Fatalf("write %s: %v", r.ID, err)
		}
	}
	want := []buildledger.Record{running, succeeded, failed}

	var js bytes.Buffer
	if err := listBuilds(&js, l, "json", t0.Add(3*time.Minute)); err != nil {
		t.Fatalf("build ls -o json: %v", err)
	}
	var got []buildledger.Record
	if err := json.Unmarshal(js.Bytes(), &got); err != nil {
		t.Fatalf("decode %s: %v", js.String(), err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("build ls -o json =\n%+v\nwant\n%+v", got, want)
	}
	// Every field reaches the wire under its documented key.
	var raw []map[string]any
	if err := json.Unmarshal(js.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	common := []string{"id", "dockerfile", "context", "tag", "platform", "engine", "startedAt", "status"}
	wantKeys := [][]string{
		common,
		append(append([]string{}, common...), "finishedAt", "imageDigest"),
		append(append([]string{}, common...), "finishedAt", "error"),
	}
	for i, keys := range wantKeys {
		for _, k := range keys {
			if _, ok := raw[i][k]; !ok {
				t.Errorf("record %d has no %q key: %v", i, k, raw[i])
			}
		}
		if len(raw[i]) != len(keys) {
			t.Errorf("record %d keys = %v, want exactly %v", i, raw[i], keys)
		}
	}

	var text bytes.Buffer
	if err := listBuilds(&text, l, "text", t0.Add(3*time.Minute)); err != nil {
		t.Fatalf("build ls: %v", err)
	}
	lines := strings.Split(strings.TrimRight(text.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("build ls printed %d lines, want a header and 3 rows:\n%s", len(lines), text.String())
	}
	if f := strings.Fields(lines[0]); !reflect.DeepEqual(f, []string{"ID", "STATUS", "TAG", "PLATFORM", "ENGINE", "STARTED", "DURATION"}) {
		t.Errorf("header = %q", lines[0])
	}
	rows := [][]string{
		{"cccccccccccc", "running", "c:v1", "linux/arm64", "engine", "2026-10-15T09:02:00Z", "1m0s"},
		{"bbbbbbbbbbbb", "succeeded", "b:v1", "linux/arm64,linux/amd64", "engine", "2026-10-15T09:01:00Z", "1m35s"},
		{"aaaaaaaaaaaa", "failed", "a:v1", "darwin/arm64", "native", "2026-10-15T09:00:00Z", "3s"},
	}
	for i, want := range rows {
		if got := strings.Fields(lines[i+1]); !reflect.DeepEqual(got, want) {
			t.Errorf("row %d = %q, want %q", i, got, want)
		}
	}
}

// TestBuildLsEmptyAndBadFormat pins the edges: an empty ledger is "[]" in JSON
// and a sentence in text, and an unknown -o is refused.
func TestBuildLsEmptyAndBadFormat(t *testing.T) {
	l := buildledger.New(filepath.Join(t.TempDir(), "absent"))
	var js bytes.Buffer
	if err := listBuilds(&js, l, "json", time.Now()); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(js.String()) != "[]" {
		t.Errorf("empty ledger as JSON = %q, want []", js.String())
	}
	var text bytes.Buffer
	if err := listBuilds(&text, l, "text", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "No builds recorded") {
		t.Errorf("empty ledger as text = %q", text.String())
	}
	if err := listBuilds(io.Discard, l, "yaml", time.Now()); err == nil {
		t.Error("-o yaml was accepted")
	}
	if err := runBuildLs([]string{"extra"}, io.Discard); err == nil {
		t.Error("a positional argument was accepted")
	}
}

// TestBuildRecordsItsOutcome drives a real native build and fake engine builds
// through the ledger: the route, the platform, the digest on success and the
// error on failure each land in the record, and the build's own result is
// untouched by the ledger.
func TestBuildRecordsItsOutcome(t *testing.T) {
	noEngine := func(storeRecorder) engineBuilder {
		return func(context.Context, buildOptions, io.Writer) error {
			t.Fatal("the engine ran for a native build")
			return nil
		}
	}
	native := func(t *testing.T) buildOptions {
		ctxDir := writeCtx(t, "FROM scratch\nCOPY app /app")
		return buildOptions{dockerfile: filepath.Join(ctxDir, "Dockerfile"), tag: "app:v1", format: "docker", contextDir: ctxDir}
	}
	only := func(t *testing.T, l *buildledger.Ledger) buildledger.Record {
		t.Helper()
		recs, err := l.List()
		if err != nil || len(recs) != 1 {
			t.Fatalf("ledger = %v, %v; want one record", recs, err)
		}
		return recs[0]
	}

	t.Run("a native success records the store digest", func(t *testing.T) {
		l := buildledger.New(filepath.Join(t.TempDir(), "builds"))
		o := native(t)
		var log bytes.Buffer
		if err := buildRecorded(t.Context(), l, o, &log, noEngine, noStore, noPush); err != nil {
			t.Fatalf("build: %v", err)
		}
		r := only(t, l)
		if r.Status != buildledger.StatusSucceeded || r.Engine != buildledger.EngineNative || r.Platform != "darwin/arm64" || r.Tag != "app:v1" || r.Error != "" || r.FinishedAt == nil {
			t.Errorf("record = %+v", r)
		}
		if r.ImageDigest == "" || !strings.Contains(log.String(), r.ImageDigest) {
			t.Errorf("record digest %q is not the summary's:\n%s", r.ImageDigest, log.String())
		}
		if r.Dockerfile != o.dockerfile || r.Context != o.contextDir || !filepath.IsAbs(r.Context) {
			t.Errorf("paths = %q, %q; want %q, %q", r.Dockerfile, r.Context, o.dockerfile, o.contextDir)
		}
	})

	t.Run("an engine route is recorded as the engine with its platform", func(t *testing.T) {
		l := buildledger.New(filepath.Join(t.TempDir(), "builds"))
		ctxDir := writeCtx(t, "FROM scratch\nRUN make\n")
		o := buildOptions{dockerfile: filepath.Join(ctxDir, "Dockerfile"), tag: "app:v1", format: "docker", contextDir: ctxDir, platforms: []string{"darwin/arm64"}}
		var during buildledger.Record
		engineFor := func(storeRecorder) engineBuilder {
			return func(context.Context, buildOptions, io.Writer) error {
				during = only(t, l)
				return errors.New("buildx: exit status 1")
			}
		}
		err := buildRecorded(t.Context(), l, o, io.Discard, engineFor, noStore, noPush)
		if err == nil || err.Error() != "buildx: exit status 1" {
			t.Fatalf("build error = %v, want the engine's own", err)
		}
		if during.Status != buildledger.StatusRunning || during.Engine != buildledger.EngineBuildEngine || during.Platform != enginePlatform {
			t.Errorf("record while the engine ran = %+v", during)
		}
		r := only(t, l)
		if r.Status != buildledger.StatusFailed || r.Error != "buildx: exit status 1" || r.ImageDigest != "" || r.ID != during.ID {
			t.Errorf("record = %+v", r)
		}
	})

	t.Run("an unwritable ledger does not fail the build", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		l := buildledger.New(filepath.Join(blocker, "builds"))
		if err := buildRecorded(t.Context(), l, native(t), io.Discard, noEngine, noStore, noPush); err != nil {
			t.Fatalf("a ledger failure failed the build: %v", err)
		}
	})

	t.Run("no ledger records nothing", func(t *testing.T) {
		if err := buildRecorded(t.Context(), nil, native(t), io.Discard, noEngine, noStore, noPush); err != nil {
			t.Fatalf("build: %v", err)
		}
	})
}
