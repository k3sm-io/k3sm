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

package status

import (
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// TestImageMigrationRowRendersEachState: the row says not started, done with
// the count, or pending with the reason, from the journal alone.
func TestImageMigrationRowRendersEachState(t *testing.T) {
	const path = "/var/lib/k3sm/server/image-migration/journal.json"
	cases := []struct {
		name     string
		raw      string
		err      error
		state    RowState
		severity Severity
		detail   []string
	}{
		{name: "no journal", err: fs.ErrNotExist, state: StateWaiting, severity: SeveritySkip,
			detail: []string{"not started"}},
		{name: "done", raw: `{"schema":1,"complete":true,"images":[{"outcome":"migrated"},{"outcome":"present"},{"outcome":"renamed"},{"outcome":"cached"}]}`,
			state: StateOK, severity: SeverityOK, detail: []string{"done: 3 images in the cluster registry", "1 pull-cache image left"}},
		{name: "done with a held image", raw: `{"schema":1,"complete":true,"images":[{"outcome":"migrated"},{"outcome":"unexportable"}]}`,
			state: StateOK, severity: SeverityWarn, detail: []string{"done: 1 image in the cluster registry", "1 held in the node store"}},
		{name: "failed with a reason", raw: `{"schema":1,"complete":false,"lastError":"ask the cluster registry for registry-k3sm:6450/app:dev: connection refused\nsecond line","images":[{"outcome":"migrated"}]}`,
			state: StateFailed, severity: SeverityWarn, detail: []string{"pending: ask the cluster registry", "connection refused", "so far 1 image", "nothing was removed"}},
		{name: "interrupted", raw: `{"schema":1,"complete":false,"images":[]}`,
			state: StateWaiting, severity: SeverityWarn, detail: []string{"pending: the copy has not finished"}},
		{name: "unreadable", err: fs.ErrPermission, state: StateNeedsAdmin, severity: SeveritySkip,
			detail: []string{"needs sudo"}},
		{name: "unknown schema", raw: `{"schema":9}`, state: StateUnknown, severity: SeverityUnknown,
			detail: []string{"does not parse"}},
		{name: "read error", err: errors.New("i/o error"), state: StateUnknown, severity: SeverityUnknown,
			detail: []string{"could not read"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := imageMigrationRowFrom(path, []byte(tc.raw), tc.err)
			if row.Name != ImageMigrationRow || row.State != tc.state || row.Severity != tc.severity {
				t.Fatalf("row = %s %s %s, want %s %s %s", row.Name, row.State, row.Severity, ImageMigrationRow, tc.state, tc.severity)
			}
			for _, want := range tc.detail {
				if !strings.Contains(row.Detail, want) {
					t.Errorf("detail %q lacks %q", row.Detail, want)
				}
			}
			if strings.Contains(row.Detail, "second line") {
				t.Errorf("detail %q carries more than the reason's first line", row.Detail)
			}
		})
	}
}

// TestImageMigrationRowIsTextOnly: the row renders on the overview screen and
// is absent from the JSON encoding and from the rows the verdict reads.
func TestImageMigrationRowIsTextOnly(t *testing.T) {
	row := imageMigrationRowFrom("/w/image-migration/journal.json", []byte(`{"schema":1,"complete":false,"lastError":"registry unreachable"}`), nil)
	r := Report{Rows: []Row{{Name: RowInstall, State: StateOK, Severity: SeverityOK, Detail: "installed"}}, ImageMigration: &row}

	screen := Render(r, Style{})
	if !strings.Contains(screen, ImageMigrationRow) || !strings.Contains(screen, "pending: registry unreachable") {
		t.Errorf("overview screen lacks the migration row:\n%s", screen)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), ImageMigrationRow) || strings.Contains(string(b), "registry unreachable") {
		t.Errorf("the JSON encoding carries the migration row: %s", b)
	}
	if _, ok := r.Row(ImageMigrationRow); ok {
		t.Error("the migration row is in Rows, where the verdict would read it")
	}
}

// TestImageMigrationRowReadsThePublishedSummary: an ordinary account, which
// cannot read the root-only journal, gets the row from the summary the
// migration publishes in the status directory: its state, counts and reason.
// With no summary, a status directory that exists means no run of this
// release has written a journal (it publishes beside every write), so the
// row says not started rather than needs sudo.
func TestImageMigrationRowReadsThePublishedSummary(t *testing.T) {
	const (
		workDir   = "/var/lib/k3sm/server"
		statusDir = "/var/lib/k3sm/status"
		summary   = statusDir + "/image-migration.json"
		journal   = workDir + "/image-migration/journal.json"
	)
	cases := []struct {
		name     string
		fsys     fakeFS
		state    RowState
		severity Severity
		detail   []string
	}{
		{
			name: "done, from the summary, with the journal root-only",
			fsys: fakeFS{
				present:    map[string]bool{statusDir: true},
				contents:   map[string][]byte{summary: []byte(`{"schema":1,"state":"complete","inRegistry":3,"cacheEntries":1,"held":0}`)},
				unreadable: map[string]bool{journal: true},
			},
			state: StateOK, severity: SeverityOK,
			detail: []string{"done: 3 images in the cluster registry", "1 pull-cache image left"},
		},
		{
			name: "pending with the published reason",
			fsys: fakeFS{
				present:    map[string]bool{statusDir: true},
				contents:   map[string][]byte{summary: []byte(`{"schema":1,"state":"pending","inRegistry":1,"cacheEntries":0,"held":0,"lastError":"an image could not be copied into the cluster registry: the registry could not be reached"}`)},
				unreadable: map[string]bool{journal: true},
			},
			state: StateFailed, severity: SeverityWarn,
			detail: []string{"pending: an image could not be copied", "so far 1 image", "nothing was removed"},
		},
		{
			name: "no summary in an existing status directory is not started",
			fsys: fakeFS{
				present:    map[string]bool{statusDir: true},
				unreadable: map[string]bool{journal: true},
			},
			state: StateWaiting, severity: SeveritySkip,
			detail: []string{"not started"},
		},
		{
			name: "no status directory and a root-only journal needs sudo",
			fsys: fakeFS{
				unreadable: map[string]bool{journal: true},
			},
			state: StateNeedsAdmin, severity: SeveritySkip,
			detail: []string{"needs sudo"},
		},
		{
			name: "root with no summary reads the journal",
			fsys: fakeFS{
				contents: map[string][]byte{journal: []byte(`{"schema":1,"complete":true,"images":[{"outcome":"migrated"}]}`)},
			},
			state: StateOK, severity: SeverityOK,
			detail: []string{"done: 1 image in the cluster registry"},
		},
		{
			name: "a summary that does not parse",
			fsys: fakeFS{
				present:  map[string]bool{statusDir: true},
				contents: map[string][]byte{summary: []byte(`{"schema":7}`)},
			},
			state: StateUnknown, severity: SeverityUnknown,
			detail: []string{"does not parse"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Collector{Paths: Paths{WorkDir: workDir}, FS: tc.fsys}
			row, ok := c.imageMigrationRow()
			if !ok {
				t.Fatal("no row")
			}
			if row.Name != ImageMigrationRow || row.State != tc.state || row.Severity != tc.severity {
				t.Fatalf("row = %s %s %s (%s), want %s %s", row.Name, row.State, row.Severity, row.Detail, tc.state, tc.severity)
			}
			for _, want := range tc.detail {
				if !strings.Contains(row.Detail, want) {
					t.Errorf("detail %q lacks %q", row.Detail, want)
				}
			}
		})
	}
}
