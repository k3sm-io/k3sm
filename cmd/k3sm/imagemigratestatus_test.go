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
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"

	"k3sm.io/k3sm/pkg/status"
)

// TestStoreMigrationUnreachableRegistryLeavesJournalPending: a registry that
// cannot be reached, or refuses the upload, stops the run with the journal
// written as pending with the reason, and the node store exactly as it was.
// The next run then retries, and a run that reaches every entry clears the
// reason.
func TestStoreMigrationUnreachableRegistryLeavesJournalPending(t *testing.T) {
	cases := []struct {
		name string
		// breakIt makes the rig's registry unreachable one way.
		breakIt func(m *imageMigrator, rig *migrationRig)
		want    string
	}{
		{
			name: "the registry does not answer",
			breakIt: func(m *imageMigrator, _ *migrationRig) {
				m.digestAt = func(context.Context, name.Tag, pushDest) (string, bool, error) {
					return "", false, errors.New("dial tcp: connection refused")
				}
			},
			want: "connection refused",
		},
		{
			name: "the registry refuses the upload",
			breakIt: func(_ *imageMigrator, rig *migrationRig) {
				rig.pusher.fail = func(name.Reference) bool { return true }
			},
			want: "the registry went away",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newMigrationRig(t)
			rig.store.add(t, "docker.io/library/app:dev", "darwin/arm64", randomImage(t))
			rig.store.add(t, "example.test/svc:v1", "darwin/arm64", randomImage(t))
			before := append([]storeEntry(nil), rig.store.entries...)

			m := rig.migrator()
			tc.breakIt(&m, rig)
			if _, err := m.run(t.Context()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run = %v, want an error naming %q", err, tc.want)
			}

			raw, err := os.ReadFile(migrationJournalPath(rig.workDir))
			if err != nil {
				t.Fatalf("the failed run left no journal: %v", err)
			}
			var j map[string]any
			if err := json.Unmarshal(raw, &j); err != nil {
				t.Fatal(err)
			}
			if j["complete"] != false {
				t.Errorf("journal complete = %v, want false", j["complete"])
			}
			if reason, _ := j["lastError"].(string); !strings.Contains(reason, tc.want) {
				t.Errorf("journal lastError = %q, want the reason %q", reason, tc.want)
			}
			if !reflect.DeepEqual(rig.store.entries, before) {
				t.Errorf("the node store changed: %v, want %v", rig.store.entries, before)
			}

			// The registry is back: the retry finishes and clears the reason.
			rig.pusher.fail = nil
			got, err := rig.migrator().run(t.Context())
			if err != nil {
				t.Fatalf("retry: %v", err)
			}
			if !got.Complete || got.LastError != "" {
				t.Errorf("retry: complete=%v lastError=%q, want complete with no reason", got.Complete, got.LastError)
			}
		})
	}
}

// TestRecordMigrationFailureMarksJournalPending: a run that could not start
// (this node's runtime is down) still leaves a pending journal with the
// reason, keeping what an earlier run recorded.
func TestRecordMigrationFailureMarksJournalPending(t *testing.T) {
	wd := t.TempDir()
	prior := migrationJournal{Schema: migrationSchema, Complete: true, Images: []migrationRecord{{Reference: "a", Outcome: migrationMigrated}}}
	if err := writeMigrationJournal(wd, prior); err != nil {
		t.Fatal(err)
	}
	if err := recordMigrationFailure(wd, errors.New("this node's runtime is not reachable")); err != nil {
		t.Fatal(err)
	}
	j, err := readMigrationJournal(wd)
	if err != nil {
		t.Fatal(err)
	}
	if j.Complete || j.LastError != "this node's runtime is not reachable" || len(j.Images) != 1 {
		t.Errorf("journal = %+v, want pending with the reason and the earlier record kept", j)
	}
}

// TestStatusReadsTheMigrationJournal pins the status row's reader to the
// journal this package writes: the same path, and the field names it reads.
func TestStatusReadsTheMigrationJournal(t *testing.T) {
	wd := t.TempDir()
	if got, want := status.ImageMigrationJournalPath(wd), migrationJournalPath(wd); got != want {
		t.Fatalf("status reads %s, the migration writes %s", got, want)
	}
	j := migrationJournal{Schema: migrationSchema, LastError: "x", Images: []migrationRecord{{Reference: "a", Outcome: migrationRenamed}}}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"schema":1`, `"complete":false`, `"lastError":"x"`, `"outcome":"renamed"`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("journal %s lacks %s, which the status row reads", b, field)
		}
	}
}

// TestMigrationPublishesItsSummary: every journal write also publishes a
// 0644 summary in the status directory beside the work dir, which the status
// row reads without root: the state, the counts and the pending reason, and
// no image name. A Mac with no status directory gets the journal only.
func TestMigrationPublishesItsSummary(t *testing.T) {
	cases := []struct {
		name    string
		journal migrationJournal
		want    status.ImageMigrationSummary
	}{
		{
			name: "complete",
			journal: migrationJournal{Schema: migrationSchema, Complete: true, Images: []migrationRecord{
				{Reference: "docker.io/library/secret-app:dev", Outcome: migrationMigrated, Target: "registry-k3sm:6450/secret-app:dev"},
				{Reference: "ghcr.io/org/tool:1", Outcome: migrationCached},
				{Reference: "example.test/old:v1", Outcome: migrationRenamed},
				{Reference: "example.test/broken:v1", Outcome: migrationUnexportable},
			}},
			want: status.ImageMigrationSummary{Schema: 1, State: "complete", InRegistry: 2, CacheEntries: 1, Held: 1},
		},
		{
			name: "pending, with the reason that names no image",
			journal: migrationJournal{Schema: migrationSchema,
				LastError:     "migrate docker.io/library/secret-app:dev to the cluster registry: connection refused",
				PendingReason: "an image could not be copied into the cluster registry: the registry could not be reached",
				Images:        []migrationRecord{{Reference: "docker.io/library/secret-app:dev", Outcome: migrationPresent}},
			},
			want: status.ImageMigrationSummary{Schema: 1, State: "pending", InRegistry: 1,
				LastError: "an image could not be copied into the cluster registry: the registry could not be reached"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			workDir := filepath.Join(root, "server")
			if err := os.MkdirAll(filepath.Join(root, "status"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := writeMigrationJournal(workDir, tc.journal); err != nil {
				t.Fatal(err)
			}
			path := status.ImageMigrationSummaryPath(workDir)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("no summary published: %v", err)
			}
			if info.Mode().Perm() != 0o644 {
				t.Errorf("summary mode = %v, want 0644", info.Mode().Perm())
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "secret-app") || strings.Contains(string(raw), "registry-k3sm:6450/") {
				t.Errorf("the summary names an image: %s", raw)
			}
			var got status.ImageMigrationSummary
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("summary = %+v, want %+v", got, tc.want)
			}
		})
	}

	t.Run("no status directory, no summary", func(t *testing.T) {
		workDir := filepath.Join(t.TempDir(), "server")
		if err := writeMigrationJournal(workDir, migrationJournal{Schema: migrationSchema}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(status.ImageMigrationSummaryPath(workDir)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("summary without a status directory: %v", err)
		}
	})
}

// TestStoppedRunPublishesAReasonWithoutImageNames: a run that stops on one
// image records the full error in the journal and a reason naming no image in
// the summary.
func TestStoppedRunPublishesAReasonWithoutImageNames(t *testing.T) {
	rig := newMigrationRig(t)
	rig.store.add(t, "docker.io/library/secret-app:dev", "darwin/arm64", randomImage(t))
	statusDir := filepath.Join(filepath.Dir(rig.workDir), "status")
	if err := os.MkdirAll(statusDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rig.pusher.fail = func(name.Reference) bool { return true }
	if _, err := rig.migrator().run(t.Context()); err == nil {
		t.Fatal("run succeeded with a failing registry")
	}
	j, err := readMigrationJournal(rig.workDir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(j.LastError, "secret-app") {
		t.Errorf("journal lastError %q does not name the image", j.LastError)
	}
	raw, err := os.ReadFile(status.ImageMigrationSummaryPath(rig.workDir))
	if err != nil {
		t.Fatal(err)
	}
	var s status.ImageMigrationSummary
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if s.State != status.ImageMigrationPending || !strings.Contains(s.LastError, "an image could not be copied") || strings.Contains(string(raw), "secret-app") {
		t.Errorf("summary = %s, want pending with a reason that names no image", raw)
	}
}

// TestMigrationJournalKeepsTheServerAccountsOwner: a root run of `k3sm image
// migrate` on the installed server's work dir hands the journal's directory,
// lock, journal and summary to the work dir's owner, so the server's daemon,
// which runs as that account, can still write its own journal. Any other run
// re-owns nothing. The summary stays 0644 either way.
func TestMigrationJournalKeepsTheServerAccountsOwner(t *testing.T) {
	owner := os.Getuid()
	if owner == 0 {
		t.Skip("needs a work dir owned by a uid other than root")
	}
	cases := []struct {
		name      string
		euid      int
		installed bool
		wantChown bool
	}{
		{name: "root on the installed server's work dir owned by another uid", euid: 0, installed: true, wantChown: true},
		{name: "a non-root run re-owns nothing", euid: owner + 1, installed: true},
		{name: "root on a work dir that is not the installed server's", euid: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			workDir := filepath.Join(root, "server")
			for _, d := range []string{workDir, filepath.Join(root, "status")} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			prevEUID, prevChown, prevInstalled := migrateGeteuid, migrateChown, installedServerWorkDir
			t.Cleanup(func() { migrateGeteuid, migrateChown, installedServerWorkDir = prevEUID, prevChown, prevInstalled })
			migrateGeteuid = func() int { return tc.euid }
			if tc.installed {
				installedServerWorkDir = workDir
			}
			chowned := map[string]int{}
			migrateChown = func(path string, uid, _ int) error {
				chowned[path] = uid
				return nil
			}

			unlock, err := lockImageMigration(workDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeMigrationJournal(workDir, migrationJournal{Schema: migrationSchema}); err != nil {
				t.Fatal(err)
			}
			unlock()

			paths := []string{
				migrationDir(workDir),
				filepath.Join(migrationDir(workDir), "lock"),
				migrationJournalPath(workDir),
				status.ImageMigrationSummaryPath(workDir),
			}
			for _, p := range paths {
				uid, ok := chowned[p]
				switch {
				case tc.wantChown && (!ok || uid != owner):
					t.Errorf("%s: chowned to %d (%v), want the work dir's owner %d", p, uid, ok, owner)
				case !tc.wantChown && ok:
					t.Errorf("%s: chowned to %d, want no re-own", p, uid)
				}
			}
			info, err := os.Stat(status.ImageMigrationSummaryPath(workDir))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o644 {
				t.Errorf("summary mode = %v, want 0644", info.Mode().Perm())
			}
		})
	}
}

// TestMigrationProgressClearsLastError: a run that follows a failed one and
// gets as far as copying images publishes no stale reason while its counts
// climb. The summary written after the first image of the new run carries no
// lastError; a run that then stops again publishes its own reason, never the
// earlier one.
func TestMigrationProgressClearsLastError(t *testing.T) {
	const stale = "this node's image store could not be listed"
	cases := []struct {
		name string
		// failSecond makes the second image's upload fail.
		failSecond   bool
		wantComplete bool
		// wantFinal is a substring of the final summary's lastError, empty
		// for none.
		wantFinal string
	}{
		{name: "the run completes", wantComplete: true},
		{name: "the run stops on a later image", failSecond: true, wantFinal: "an image could not be copied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newMigrationRig(t)
			rig.store.add(t, "docker.io/library/app:dev", "darwin/arm64", randomImage(t))
			rig.store.add(t, "example.test/svc:v1", "darwin/arm64", randomImage(t))
			if err := os.MkdirAll(filepath.Join(filepath.Dir(rig.workDir), "status"), 0o755); err != nil {
				t.Fatal(err)
			}
			// The first attempt stopped before it listed anything.
			if err := writeMigrationJournal(rig.workDir, migrationJournal{Schema: migrationSchema,
				LastError: "list this node's image store: rpc error", PendingReason: stale}); err != nil {
				t.Fatal(err)
			}
			readSummary := func() status.ImageMigrationSummary {
				t.Helper()
				raw, err := os.ReadFile(status.ImageMigrationSummaryPath(rig.workDir))
				if err != nil {
					t.Fatal(err)
				}
				var s status.ImageMigrationSummary
				if err := json.Unmarshal(raw, &s); err != nil {
					t.Fatal(err)
				}
				return s
			}
			if s := readSummary(); s.LastError != stale {
				t.Fatalf("seeded summary lastError = %q, want %q", s.LastError, stale)
			}

			// The second upload observes what the first image's journal write
			// published.
			var mid []status.ImageMigrationSummary
			rig.pusher.fail = func(ref name.Reference) bool {
				if len(rig.pusher.calls) < 2 {
					return false
				}
				mid = append(mid, readSummary())
				return tc.failSecond
			}
			_, err := rig.migrator().run(t.Context())
			if tc.wantComplete != (err == nil) {
				t.Fatalf("run = %v, want complete %v", err, tc.wantComplete)
			}
			if len(mid) != 1 {
				t.Fatalf("observed %d mid-run summaries, want 1", len(mid))
			}
			if mid[0].InRegistry != 1 || mid[0].LastError != "" {
				t.Errorf("summary after the first image = %+v, want 1 in the registry and no lastError", mid[0])
			}
			final := readSummary()
			switch {
			case tc.wantFinal == "" && final.LastError != "":
				t.Errorf("final summary lastError = %q, want none", final.LastError)
			case tc.wantFinal != "" && !strings.Contains(final.LastError, tc.wantFinal):
				t.Errorf("final summary lastError = %q, want one naming %q", final.LastError, tc.wantFinal)
			case final.LastError == stale:
				t.Errorf("final summary kept the earlier run's reason %q", stale)
			}
		})
	}
}
