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
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// TestCrashLoopReadsOnlyThroughTheSeam pins that the server row's crash record
// is read through Collector.ReadCrashRecord and nothing else: a set seam is
// asked for the work dir's record and its answer judges the row, and a nil
// seam (every fake-FS collector in this package) reads nothing, so no test
// pointed at a real work dir path picks up the host's own record.
func TestCrashLoopReadsOnlyThroughTheSeam(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	tripped := now.Add(-time.Minute)
	const wd = "/var/lib/k3sm/server"

	t.Run("set seam is asked for the record", func(t *testing.T) {
		var asked []string
		c := Collector{FS: fakeFS{}, Paths: Paths{WorkDir: wd}, Now: func() time.Time { return now },
			ReadCrashRecord: func(path string) (executor.CrashRecord, error) {
				asked = append(asked, path)
				return executor.CrashRecord{Crashes: []executor.Crash{{At: tripped, Component: "kine"}}, TrippedAt: &tripped}, nil
			}}
		row := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Wide: map[string]string{}}
		c.crashLoop(&row)
		if len(asked) != 1 || asked[0] != executor.CrashLoopPath(wd) {
			t.Fatalf("seam asked for %v, want [%s]", asked, executor.CrashLoopPath(wd))
		}
		if row.Severity != SeverityFail {
			t.Fatalf("the seam's tripped record did not judge the row: %+v", row)
		}
	})
	t.Run("nil seam reads nothing", func(t *testing.T) {
		c := Collector{FS: fakeFS{}, Paths: Paths{WorkDir: wd}, Now: func() time.Time { return now }}
		row := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Wide: map[string]string{}}
		c.crashLoop(&row)
		if row.Severity != SeverityOK || len(row.Wide) != 0 {
			t.Fatalf("a nil seam changed the row: %+v", row)
		}
	})
}
