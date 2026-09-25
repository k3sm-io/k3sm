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
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

func TestClassifyStagedControlPlane(t *testing.T) {
	t.Parallel()
	pin := executor.DefaultKubeVersion
	tests := []struct {
		name        string
		marker      string
		err         error
		wantPosture StagedPosture
		wantIn      []string
		wantRemedy  string
	}{
		{"matching marker", pin + "\n", nil, StagedMatch, []string{pin + " staged", "pinned " + pin}, ""},
		{"absent marker is unknown-staged, no remedy", "", os.ErrNotExist, StagedUnvouched, []string{"unknown-staged", "pinned " + pin}, ""},
		{"malformed marker is unknown-staged", "v1 v2\n", nil, StagedUnvouched, []string{"unknown-staged"}, ""},
		{"older marker is stale with the re-stage remedy", "v1.35.0\n", nil, StagedStale, []string{"v1.35.0", pin, "still serving"}, executor.StaleControlPlaneRemedy},
		{"unparseable marker reads as stale, never newer", "latest\n", nil, StagedStale, []string{"latest", pin}, executor.StaleControlPlaneRemedy},
		{"newer marker names the refused downgrade", "v1.99.0\n", nil, StagedNewer, []string{"v1.99.0", "NEWER", pin}, executor.NewerControlPlaneRemedy},
		{"permission denied is unreadable", "", os.ErrPermission, StagedUnreadable, []string{"unknown-staged", "run as root"}, ""},
		{"other read errors are unreadable", "", errors.New("i/o error"), StagedUnreadable, []string{"unknown-staged", "i/o error"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := ClassifyStagedControlPlane([]byte(tc.marker), tc.err, pin)
			if v.Posture != tc.wantPosture {
				t.Errorf("posture = %v, want %v (%+v)", v.Posture, tc.wantPosture, v)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(v.Detail, want) {
					t.Errorf("detail %q lacks %q", v.Detail, want)
				}
			}
			if v.Remedy != tc.wantRemedy {
				t.Errorf("remedy = %q, want %q", v.Remedy, tc.wantRemedy)
			}
		})
	}
}

func TestApplyStagedControlPlaneOnTheServerRow(t *testing.T) {
	t.Parallel()
	running := func() Row {
		return Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Detail: "pid 42", Wide: map[string]string{}}
	}
	stale := ClassifyStagedControlPlane([]byte("v1.35.0\n"), nil, executor.DefaultKubeVersion)
	t.Run("a mismatch is a WARN over a running row, with the remedy", func(t *testing.T) {
		row := running()
		applyStagedControlPlane(&row, stale)
		if row.Severity != SeverityWarn || row.State != StateRunning || row.Remedy != executor.StaleControlPlaneRemedy ||
			!strings.Contains(row.Detail, "v1.35.0") || !strings.Contains(row.Wide["cp-binaries"], "v1.35.0") {
			t.Fatalf("%+v", row)
		}
	})
	t.Run("a mismatch never softens or re-remedies a parked row", func(t *testing.T) {
		row := Row{Name: RowServer, State: StateCrashLoop, Severity: SeverityFail, Detail: "parked", Remedy: "clear", Wide: map[string]string{}}
		applyStagedControlPlane(&row, stale)
		if row.Severity != SeverityFail || row.Detail != "parked" || row.Remedy != "clear" || row.Wide["cp-binaries"] == "" {
			t.Fatalf("%+v", row)
		}
	})
	t.Run("an unmarked set is a wide note, never a severity", func(t *testing.T) {
		row := running()
		applyStagedControlPlane(&row, ClassifyStagedControlPlane(nil, os.ErrNotExist, executor.DefaultKubeVersion))
		if row.Severity != SeverityOK || row.Detail != "pid 42" || !strings.Contains(row.Wide["cp-binaries"], "unknown-staged") {
			t.Fatalf("%+v", row)
		}
	})
}

// TestCollectorStagedVsPinnedMismatch is the status half of B395: a healthy
// cluster whose work dir staged an older control plane than this binary pins is
// DEGRADED, and the server row names both versions and the remedy. The same
// cluster with no marker at all (every install before markers) stays RUNNING.
func TestCollectorStagedVsPinnedMismatch(t *testing.T) {
	t.Parallel()
	collect := func(t *testing.T, marker []byte) Report {
		t.Helper()
		p := testPaths(walDB(t))
		fsys := installedFS(p)
		if marker != nil {
			fsys.contents = map[string][]byte{executor.KubeMarkerPath(p.WorkDir): marker}
		}
		c := Collector{
			Launchd: fakeLaunchd{out: map[string][]byte{
				p.NetdLabel:   fixture(t, "launchctl_netd_running.txt"),
				p.ServerLabel: fixture(t, "launchctl_netd_running.txt"),
			}},
			FS:         fsys,
			Kube:       healthyKube(),
			KubeSource: "~/.kube/config context \"k3sm\"",
			Procs:      fakeProcs{live: LivenessRunning, vmHosts: 2},
			DataRoot:   fakeDataRootFS{dir: p.DataRoot, mode: 0o750, uid: 250, mounted: true},
			Paths:      p,
			EUID:       501,
			ServiceUID: 250,
			Now:        func() time.Time { return goldenTime },
			Version:    goldenVersion,
			Host:       goldenHost,
		}
		return c.Collect(context.Background())
	}

	t.Run("stale staged set degrades the report and names the fix", func(t *testing.T) {
		t.Parallel()
		rep := collect(t, []byte("v1.35.0\n"))
		if rep.Verdict != VerdictDegraded {
			t.Fatalf("verdict = %v (%s), want degraded\n%s", rep.Verdict, rep.Summary, Render(rep, Style{}))
		}
		server, _ := rep.Row(RowServer)
		for _, want := range []string{"v1.35.0", executor.DefaultKubeVersion} {
			if !strings.Contains(server.Detail, want) || !strings.Contains(rep.Summary, want) {
				t.Errorf("server detail %q / summary %q lacks %q", server.Detail, rep.Summary, want)
			}
		}
		if !strings.Contains(server.Remedy, "sudo k3sm install") {
			t.Errorf("server remedy = %q, want the re-stage", server.Remedy)
		}
	})

	t.Run("matching staged set stays running with the pair in the wide view", func(t *testing.T) {
		t.Parallel()
		rep := collect(t, []byte(executor.DefaultKubeVersion+"\n"))
		if rep.Verdict != VerdictRunning {
			t.Fatalf("verdict = %v (%s), want running", rep.Verdict, rep.Summary)
		}
		server, _ := rep.Row(RowServer)
		if !strings.Contains(server.Wide["cp-binaries"], executor.DefaultKubeVersion+" staged") {
			t.Errorf("cp-binaries = %q", server.Wide["cp-binaries"])
		}
	})

	t.Run("unmarked staged set is grandfathered quietly", func(t *testing.T) {
		t.Parallel()
		rep := collect(t, nil)
		if rep.Verdict != VerdictRunning {
			t.Fatalf("verdict = %v (%s), want running — an unmarked install must not alarm", rep.Verdict, rep.Summary)
		}
		server, _ := rep.Row(RowServer)
		if !strings.Contains(server.Wide["cp-binaries"], "unknown-staged") {
			t.Errorf("cp-binaries = %q, want unknown-staged", server.Wide["cp-binaries"])
		}
	})
}
