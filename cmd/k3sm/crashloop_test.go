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
	"errors"
	"fmt"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// TestPermanentBringUpFailureParksImmediately is the two-tier breaker's gate
// (B393). A kine pin bump on a daemon whose launchd PATH has no `go` used to
// burn CrashLoopThreshold identical bring-up failures before parking, though
// the fault could not heal on any lap. A failure carrying
// executor.ErrNoGoToolchain through BringUpError's chain must park on the
// first; any other bring-up failure must still take the full threshold.
func TestPermanentBringUpFailureParksImmediately(t *testing.T) {
	permanent := &executor.BringUpError{Component: "provision/kine", Phase: executor.PhaseProvision,
		Err: fmt.Errorf("build kine v0.17.1: %w; re-run `sudo k3sm install`", executor.ErrNoGoToolchain)}
	transient := &executor.BringUpError{Component: "provision/kine", Phase: executor.PhaseProvision,
		Err: errors.New("build kine v0.17.1 (CGO_ENABLED=0): exit status 1: dial tcp: i/o timeout")}

	cases := []struct {
		name      string
		err       error
		tripAfter int
	}{
		{"a missing toolchain parks on the first failure", permanent, 1},
		{"the sentinel is classified through extra wrapping", fmt.Errorf("start control plane: %w", permanent), 1},
		{"an unclassified bring-up failure takes the threshold", transient, executor.CrashLoopThreshold},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for i := 1; i <= tc.tripAfter; i++ {
				noteBringUpFailure(newCrashBreaker(dir, quietLogger()), quietLogger(), tc.err)
				rec, err := executor.ReadCrashRecord(executor.CrashLoopPath(dir))
				if err != nil {
					t.Fatal(err)
				}
				if got, want := rec.Tripped(), i == tc.tripAfter; got != want {
					t.Fatalf("after %d failure(s): tripped = %v, want %v", i, got, want)
				}
			}
			rec, _ := executor.ReadCrashRecord(executor.CrashLoopPath(dir))
			last, _ := rec.Last()
			if last.Origin != executor.CrashOriginBringUp || last.Component != "provision/kine" {
				t.Errorf("last entry %+v, want a provision/kine bring-up failure", last)
			}
			wantPermanent := tc.tripAfter == 1
			if last.Permanent != wantPermanent {
				t.Errorf("Permanent = %v, want %v", last.Permanent, wantPermanent)
			}
			if wantPermanent && last.Remedy != executor.NoGoToolchainRemedy {
				t.Errorf("Remedy = %q, want %q", last.Remedy, executor.NoGoToolchainRemedy)
			}
			if !wantPermanent && last.Remedy != "" {
				t.Errorf("an unclassified failure carries a remedy %q", last.Remedy)
			}
		})
	}
}
