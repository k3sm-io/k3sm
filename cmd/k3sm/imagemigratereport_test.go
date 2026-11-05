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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	runtimed "k3sm.io/runtimed/pkg/runtime"

	"k3sm.io/k3sm/pkg/install"
)

// TestImageMigrateReportUnprivilegedOnServer: an ordinary account's --report
// on a server never presents a journal that was never written as a result.
// Its own work dir holds no journal, so the text report is the summary the
// server publishes for `k3sm status` plus the sudo line, -o json is refused,
// and with no summary published the report is refused. Root on a server and
// an ordinary account on a worker keep their report and refusal.
func TestImageMigrateReportUnprivilegedOnServer(t *testing.T) {
	journal := migrationJournal{Schema: migrationSchema, Complete: true, Images: []migrationRecord{
		{Reference: "docker.io/library/app:dev", Outcome: migrationMigrated, Target: "registry-k3sm:6450/app:dev"},
		{Reference: "example.test/old:v1", Outcome: migrationRenamed, Target: "registry-k3sm:6450/old:v1-k3sm-migrated-0123456789ab", Detail: "tag held at another digest"},
		{Reference: "ghcr.io/org/tool:1", Outcome: migrationCached, Detail: "the upstream serves it"},
	}}
	var rootReport bytes.Buffer
	renderMigrationReport(&rootReport, journal)

	cases := []struct {
		name       string
		role       install.Role
		euid       int
		published  bool // the installed server has published its summary
		ownWorkDir bool // the run names the account's own (empty) work dir
		output     string
		wantErr    bool
		wantOut    []string
		wantNot    []string
		wantExact  string
	}{
		{
			name: "an ordinary account's report on a server shows the published summary",
			role: install.RoleServer, euid: 501, published: true, ownWorkDir: true,
			wantOut: []string{"image migration done: 2 images in the cluster registry, 1 pull-cache image left as cached", "sudo k3sm image migrate --report"},
			wantNot: []string{"incomplete", "0 migrated", "app:dev"},
		},
		{
			name: "an ordinary account's report on a server, naming the installed work dir it cannot read",
			role: install.RoleServer, euid: 501, published: true,
			wantOut: []string{"image migration done: 2 images in the cluster registry", "sudo k3sm image migrate --report"},
			wantNot: []string{"incomplete", "app:dev"},
		},
		{
			name: "an ordinary account's json report on a server is refused",
			role: install.RoleServer, euid: 501, published: true, ownWorkDir: true, output: "json",
			wantErr: true,
		},
		{
			name: "an ordinary account's report on a server with no published summary is refused",
			role: install.RoleServer, euid: 501, ownWorkDir: true,
			wantErr: true,
		},
		{
			name: "root's report on a server is the journal's",
			role: install.RoleServer, euid: 0, published: true,
			wantExact: rootReport.String(),
		},
		{
			name: "root's report of a server work dir with no journal is unchanged",
			role: install.RoleServer, euid: 0, ownWorkDir: true,
			wantExact: "image migration incomplete, re-run k3sm image migrate: 0 migrated, 0 already present, 0 renamed, 0 cache entries left, 0 held (unexportable)\n",
		},
		{
			name: "an ordinary account's report on a worker is refused",
			role: install.RoleAgent, euid: 501, published: true, ownWorkDir: true,
			wantErr: true,
		},
	}
	prevEUID, prevSvc, prevRole, prevInstalled := migrateGeteuid, migrateServiceUID, migrateRole, installedServerWorkDir
	t.Cleanup(func() {
		migrateGeteuid, migrateServiceUID, migrateRole, installedServerWorkDir = prevEUID, prevSvc, prevRole, prevInstalled
	})
	migrateServiceUID = func() int { return 270 }
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			installed := filepath.Join(root, "var", "server")
			installedServerWorkDir = installed
			if tc.published {
				if err := os.MkdirAll(filepath.Join(root, "var", "status"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// The fixture is written as the work dir's own account, so no
			// hand-off to another owner is attempted.
			migrateGeteuid = func() int { return os.Geteuid() }
			if err := writeMigrationJournal(installed, journal); err != nil {
				t.Fatal(err)
			}
			workDir := installed
			if tc.ownWorkDir {
				workDir = filepath.Join(root, "home", "server")
			} else if tc.euid != 0 {
				// The installed work dir is root's: an ordinary account
				// cannot read the journal in it.
				if err := os.Chmod(filepath.Join(installed, "image-migration"), 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(filepath.Join(installed, "image-migration"), 0o700) })
			}
			migrateGeteuid = func() int { return tc.euid }
			migrateRole = func() (install.Role, bool) { return tc.role, true }
			dial := func(context.Context, string) (grpc.ClientConnInterface, io.Closer, error) {
				t.Fatal("a report dialled the runtime")
				return nil, nil, nil
			}
			var out bytes.Buffer
			err := imageMigrateCommand(t.Context(), imageMigrateOptions{
				socket: runtimed.DefaultSocketPath, workDir: workDir, report: true, output: tc.output,
			}, &out, dial)
			if tc.wantErr {
				if !errors.Is(err, errMigrateNeedsSudo) || !strings.Contains(err.Error(), "sudo k3sm image migrate") {
					t.Fatalf("imageMigrateCommand = %v, want the refusal naming sudo", err)
				}
				if out.Len() != 0 {
					t.Errorf("a refused report printed %q, want nothing", out.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("imageMigrateCommand = %v", err)
			}
			got := out.String()
			if tc.wantExact != "" && got != tc.wantExact {
				t.Errorf("report = %q, want %q", got, tc.wantExact)
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(got, w) {
					t.Errorf("report %q lacks %q", got, w)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(got, w) {
					t.Errorf("report %q contains %q", got, w)
				}
			}
		})
	}
}
