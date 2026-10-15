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
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// TestStaleKinePayloadParksWithTheInstallRemedy: a binary replaced without its
// payload (executor.ErrKinePayloadStale, which also wraps ErrNoGoToolchain) parks on
// the first failure, and the record names the install as the fix rather than a
// missing toolchain.
func TestStaleKinePayloadParksWithTheInstallRemedy(t *testing.T) {
	err := fmt.Errorf("start control plane: %w", &executor.BringUpError{Component: "provision/kine", Phase: executor.PhaseProvision,
		Err: fmt.Errorf("stage kine: %w (%w)", executor.ErrKinePayloadStale, executor.ErrNoGoToolchain)})
	dir := t.TempDir()
	noteBringUpFailure(context.Background(), newCrashBreaker(dir, quietLogger()), quietLogger(), err)
	rec, rerr := executor.ReadCrashRecord(executor.CrashLoopPath(dir))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !rec.Tripped() {
		t.Fatal("a stale payload did not park on its first failure")
	}
	last, _ := rec.Last()
	if !last.Permanent || last.Remedy != executor.KinePayloadStaleRemedy {
		t.Errorf("last entry %+v, want permanent with remedy %q", last, executor.KinePayloadStaleRemedy)
	}
}

// TestPayloadSignatureRefusalParksImmediately: a release-path boot that refuses its
// payload (a binary not signed with the daemon's Developer ID, a binary not built at
// its pins) or cannot read its own signature fails the same way on every lap, so it
// parks on the first failure, classified through BringUpError and extra wrapping,
// and the record names the reinstall remedy. A codesign that failed to run while
// verifying (no sentinel) still takes the full threshold.
func TestPayloadSignatureRefusalParksImmediately(t *testing.T) {
	bringUp := func(err error) error {
		return fmt.Errorf("start control plane: %w", &executor.BringUpError{Component: "provision/kine", Phase: executor.PhaseProvision, Err: err})
	}
	for _, tc := range []struct {
		name      string
		err       error
		tripAfter int
		remedy    string
	}{
		{"an unverified payload binary", bringUp(fmt.Errorf("%w: /Library/k3sm/bin/kine is not signed with team ABCDE12345's Developer ID Application certificate", executor.ErrPayloadSignature)), 1, executor.PayloadSignatureRemedy},
		{"a payload binary at another pin", bringUp(fmt.Errorf("%w: /Library/k3sm/bin/kine is v0.16.0 nocgo+p1", executor.ErrPayloadStamp)), 1, executor.PayloadSignatureRemedy},
		{"an unreadable own signature", bringUp(fmt.Errorf("%w: inspect /Library/k3sm/k3sm: exit 1", executor.ErrSelfSignatureUnreadable)), 1, executor.SelfSignatureRemedy},
		{"codesign could not run while verifying", bringUp(errors.New("verify the signature of /Library/k3sm/bin/kine: signal: killed")), executor.CrashLoopThreshold, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for i := 1; i <= tc.tripAfter; i++ {
				noteBringUpFailure(context.Background(), newCrashBreaker(dir, quietLogger()), quietLogger(), tc.err)
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
			if last.Permanent != (tc.remedy != "") || last.Remedy != tc.remedy {
				t.Errorf("last entry %+v, want permanent=%v with remedy %q", last, tc.remedy != "", tc.remedy)
			}
			if tc.remedy != "" && !strings.Contains(last.Remedy, "reinstall k3sm from a correctly signed release") {
				t.Errorf("remedy %q does not name the reinstall", last.Remedy)
			}
		})
	}
}

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
				noteBringUpFailure(context.Background(), newCrashBreaker(dir, quietLogger()), quietLogger(), tc.err)
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
	noteBringUpFailure(context.Background(), newCrashBreaker(dir, quietLogger()), quietLogger(), err)
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
			noteBringUpFailure(context.Background(), b, quietLogger(), tc.bringUpErr)
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

// TestStopDuringBringUpRecordsNoCrash is the daemon half of B577. An in-place
// install booted the running server out while its apiserver was still in its
// health wait; the stop cancelled the wait, the daemon recorded "apiserver not
// healthy: context canceled" as a bring-up failure, and the install counted that
// entry as its new daemon's fault. A bring-up this daemon's own stop cut short
// is not a failure and leaves no record. Everything else still records: a
// cancellation while the stop context is live, a deadline, a permanent class.
func TestStopDuringBringUpRecordsNoCrash(t *testing.T) {
	stopped, stop := context.WithCancel(context.Background())
	stop()
	live := context.Background()
	healthWait := func(err error) error {
		return fmt.Errorf("start control plane: %w", &executor.BringUpError{Component: "kube-apiserver", Phase: executor.PhaseBringUp,
			Err: fmt.Errorf("apiserver not healthy: %w", err)})
	}
	for _, tc := range []struct {
		name          string
		ctx           context.Context
		err           error
		agent         bool
		wantRecord    bool
		wantPermanent bool
	}{
		{name: "a stop cancelled the apiserver health wait", ctx: stopped, err: healthWait(context.Canceled)},
		{name: "a stop cancelled the agent's start", ctx: stopped, err: fmt.Errorf("join: %w", context.Canceled), agent: true},
		{name: "a bring-up failure that is not a cancellation", ctx: live, err: healthWait(errors.New("kube-apiserver exited during bring-up: exit status 1")), wantRecord: true},
		{name: "context.Canceled while the stop context is live", ctx: live, err: healthWait(context.Canceled), wantRecord: true},
		{name: "the agent: context.Canceled while the stop context is live", ctx: live, err: fmt.Errorf("join: %w", context.Canceled), agent: true, wantRecord: true},
		{name: "a deadline is a real failure even during a stop", ctx: stopped, err: healthWait(context.DeadlineExceeded), wantRecord: true},
		{name: "a permanent class during a stop still parks", ctx: stopped,
			err: &executor.BringUpError{Component: "provision/kine", Phase: executor.PhaseProvision,
				Err: fmt.Errorf("build kine: %w (%w)", executor.ErrNoGoToolchain, context.Canceled)},
			wantRecord: true, wantPermanent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			b := newCrashBreaker(dir, quietLogger())
			if tc.agent {
				noteAgentStartFailure(tc.ctx, b, quietLogger(), tc.err)
			} else {
				noteBringUpFailure(tc.ctx, b, quietLogger(), tc.err)
			}
			path := executor.CrashLoopPath(dir)
			_, statErr := os.Stat(path)
			if !tc.wantRecord {
				if !errors.Is(statErr, os.ErrNotExist) {
					rec, _ := executor.ReadCrashRecord(path)
					t.Fatalf("a bring-up cancelled by the daemon's own stop left a record at %s (stat err %v): %+v", path, statErr, rec.Crashes)
				}
				if b.noted() {
					t.Error("the breaker counts the cancelled bring-up as this process's failure")
				}
				return
			}
			rec, err := executor.ReadCrashRecord(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if len(rec.Crashes) != 1 {
				t.Fatalf("got %d entries, want exactly 1: %+v", len(rec.Crashes), rec.Crashes)
			}
			if c := rec.Crashes[0]; c.Origin != executor.CrashOriginBringUp || c.Permanent != tc.wantPermanent {
				t.Errorf("entry %+v, want a bring-up entry with Permanent=%v", c, tc.wantPermanent)
			}
		})
	}
}
