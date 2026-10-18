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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// TestReapServerOrphansRecordingDecision: a reap error is recorded on the
// crash-loop breaker the ordinary way, except ErrWorkDirLocked, which means a
// second server was started beside a live one and must never count toward the
// live server's breaker. No real process is involved.
func TestReapServerOrphansRecordingDecision(t *testing.T) {
	origReap, origStart := reapOrphanedControlPlane, daemonStartTime
	t.Cleanup(func() { reapOrphanedControlPlane, daemonStartTime = origReap, origStart })
	daemonStartTime = func() (time.Time, error) { return time.Now(), nil }

	cases := []struct {
		name       string
		err        error
		wantRecord int
	}{
		{"another live holder of the work dir is not recorded", fmt.Errorf("provision: %w: /wd/server.lock", executor.ErrWorkDirLocked), 0},
		{"a leftover that survived its SIGKILL is recorded", errors.New("the previous run's kine (pid 4711) is still running 5s after SIGKILL"), 1},
		{"no error records nothing", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The work dir exists by the time the reap fails (the reap's lock lives in it).
			wd := filepath.Join(t.TempDir(), "server")
			if err := os.MkdirAll(wd, 0o700); err != nil {
				t.Fatal(err)
			}
			reapOrphanedControlPlane = func(context.Context, executor.Config, time.Time) (executor.OrphanReap, error) {
				return executor.OrphanReap{}, tc.err
			}
			_, err := reapServerOrphans(t.Context(), serverOptions{workDir: wd}, newCrashBreaker(wd, quietLogger()), quietLogger())
			if !errors.Is(err, tc.err) {
				t.Fatalf("reapServerOrphans = %v, want it to carry %v", err, tc.err)
			}
			rec, rerr := executor.ReadCrashRecord(executor.CrashLoopPath(wd))
			if tc.wantRecord == 0 {
				if _, serr := os.Stat(executor.CrashLoopPath(wd)); !os.IsNotExist(serr) && len(rec.Crashes) != 0 {
					t.Fatalf("crash-loop record has %d entries, want none", len(rec.Crashes))
				}
				return
			}
			if rerr != nil || len(rec.Crashes) != tc.wantRecord {
				t.Fatalf("crash-loop record = %+v (%v), want %d entry", rec.Crashes, rerr, tc.wantRecord)
			}
		})
	}
}
