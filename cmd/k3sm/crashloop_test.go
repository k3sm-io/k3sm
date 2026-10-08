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
	"strings"
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

// TestSupersededEtcdMemberParksImmediately: a member whose cluster was restored on
// another server finds the same data dir on every restart, so its bring-up refusal
// parks on the first failure and names the wipe-and-re-join remedy.
func TestSupersededEtcdMemberParksImmediately(t *testing.T) {
	dir := t.TempDir()
	se := &executor.EtcdSupersededError{Peer: "etcd-a", PeerURL: "https://192.0.2.10:2380", PeerCluster: 2, OwnCluster: 1, PeerRevision: 1_000_000_002}
	err := &executor.BringUpError{Component: "etcd", Phase: executor.PhaseBringUp, Err: fmt.Errorf("await quorum: %w", se)}
	noteBringUpFailure(newCrashBreaker(dir, quietLogger()), quietLogger(), err)
	rec, rerr := executor.ReadCrashRecord(executor.CrashLoopPath(dir))
	if rerr != nil {
		t.Fatal(rerr)
	}
	last, _ := rec.Last()
	if !rec.Tripped() || !last.Permanent || last.Remedy != se.Remedy() ||
		!strings.Contains(last.Remedy, "confirm etcd-a (https://192.0.2.10:2380, cluster 2) is the server you restored; then wipe <work-dir>/etcd and re-join") {
		t.Fatalf("record tripped=%v last=%+v, want a permanent entry naming the superseded remedy", rec.Tripped(), last)
	}
}

// TestEtcdDeathRecordedOnce: one etcd death during its promotion or quorum wait is
// ONE crash record. The member is supervised before those waits, so the exit
// callback records the death (breaker.record, the OnComponentExit path) and the
// bring-up error that follows wraps executor.ErrEtcdChildExited, which
// noteBringUpFailure must not count again. A bring-up error that does NOT carry
// the sentinel (the wait claimed the report itself) is still counted.
func TestEtcdDeathRecordedOnce(t *testing.T) {
	reported := &executor.BringUpError{Component: "etcd", Phase: executor.PhaseBringUp,
		Err: fmt.Errorf("%w: etcd exited while waiting for quorum: exit status 3", executor.ErrEtcdChildExited)}
	claimed := &executor.BringUpError{Component: "etcd", Phase: executor.PhaseBringUp,
		Err: errors.New("etcd exited while waiting for quorum: exit status 3")}
	for _, tc := range []struct {
		name       string
		callback   bool
		bringUpErr error
		wantOrigin string
	}{
		{"the exit callback took the report", true, fmt.Errorf("start control plane: %w", reported), executor.CrashOriginCrash},
		{"the wait claimed the report", false, claimed, executor.CrashOriginBringUp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			b := newCrashBreaker(dir, quietLogger())
			if tc.callback {
				b.record("etcd", "etcd: fatal")
			}
			noteBringUpFailure(b, quietLogger(), tc.bringUpErr)
			rec, err := executor.ReadCrashRecord(executor.CrashLoopPath(dir))
			if err != nil {
				t.Fatal(err)
			}
			if len(rec.Crashes) != 1 {
				t.Fatalf("one etcd death left %d records, want exactly 1: %+v", len(rec.Crashes), rec.Crashes)
			}
			if c := rec.Crashes[0]; c.Component != "etcd" || c.Origin != tc.wantOrigin || c.Permanent {
				t.Errorf("record = %+v, want one non-permanent etcd %s", c, tc.wantOrigin)
			}
		})
	}
}
