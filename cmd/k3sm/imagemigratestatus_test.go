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
				m.digestAt = func(context.Context, name.Tag) (string, bool, error) {
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
