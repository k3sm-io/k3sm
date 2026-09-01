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

package executor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// stubBootPhases replaces Start's two boot phases for the duration of the test,
// so the concurrency below is exercised without spawning kine or an apiserver.
// provision runs the caller's fn; bringUp is a no-op success.
func stubBootPhases(t *testing.T, provision func(*Supervised, context.Context) error) {
	t.Helper()
	origProvision, origBringUp := supervisedProvision, supervisedBringUp
	t.Cleanup(func() { supervisedProvision, supervisedBringUp = origProvision, origBringUp })
	supervisedProvision = provision
	supervisedBringUp = func(*Supervised, context.Context) error { return nil }
}

// TestStartClaimsTheBootExactlyOnce pins the check-and-set that keeps two
// concurrent Starts from each booting a control plane over the same work-dir —
// two kine children on one SQLite file and two apiservers fighting for the port.
//
// The claim is what is under test, not a timing window: with the check and the
// set in separate critical sections, started is not set until bring-up has
// finished, so EVERY concurrent caller passes the check and enters provision.
// This test is therefore red on the unguarded code on every run, not on a loaded
// one.
//
// It runs concurrent Ready/RESTConfigToken pollers alongside, because those read
// the token Start mints; under -race an unguarded token read/write pair fails
// here rather than in production. Ready probes a loopback port nothing is
// listening on (refused immediately) — no network leaves the host.
func TestStartClaimsTheBootExactlyOnce(t *testing.T) {
	const starters = 8

	var boots atomic.Int64
	release := make(chan struct{})
	entered := make(chan struct{}, starters)
	stubBootPhases(t, func(*Supervised, context.Context) error {
		boots.Add(1)
		entered <- struct{}{}
		// Hold the boot open so every other Start races the claim while this one
		// owns it — the interleaving a real (slow) provision makes routine.
		<-release
		return nil
	})

	s := NewSupervised(Config{WorkDir: t.TempDir(), APIServerPort: freePort(t)})

	ctx := context.Background()
	pollersDone := make(chan struct{})
	var pollers sync.WaitGroup
	for range 4 {
		pollers.Add(1)
		go func() {
			defer pollers.Done()
			for {
				select {
				case <-pollersDone:
					return
				default:
				}
				_ = s.Ready(ctx)
				if _, tok := s.RESTConfigToken(); tok == "" {
					continue
				}
			}
		}()
	}

	var gate sync.WaitGroup
	gate.Add(1)
	var starts sync.WaitGroup
	errs := make([]error, starters)
	for i := range starters {
		starts.Add(1)
		go func() {
			defer starts.Done()
			gate.Wait()
			errs[i] = s.Start(ctx)
		}()
	}
	gate.Done()

	// The winner is inside provision; let the losers finish, then let it out.
	<-entered
	close(release)
	starts.Wait()
	close(pollersDone)
	pollers.Wait()

	if got := boots.Load(); got != 1 {
		t.Errorf("provision ran %d times across %d concurrent Starts, want exactly 1 — the boot claim is not atomic", got, starters)
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("Start #%d = %v, want nil", i, err)
		}
	}
	if _, tok := s.RESTConfigToken(); tok == "" {
		t.Error("RESTConfigToken returned an empty token after Start minted one")
	}
	if err := s.Start(ctx); err != nil {
		t.Errorf("a Start after the boot must be the idempotent nil, got %v", err)
	}
	if got := boots.Load(); got != 1 {
		t.Errorf("a Start after the boot re-provisioned (boots = %d)", got)
	}
}

// TestStartReleasesTheClaimAfterAFailedBoot pins the other half of the claim: a
// boot that fails must give the claim back, or the first transient provision
// error would leave the executor permanently "started" and unstartable — a
// server that can never retry its own bring-up.
func TestStartReleasesTheClaimAfterAFailedBoot(t *testing.T) {
	boom := errors.New("provision blew up")
	var attempts atomic.Int64
	stubBootPhases(t, func(*Supervised, context.Context) error {
		if attempts.Add(1) == 1 {
			return boom
		}
		return nil
	})

	s := NewSupervised(Config{WorkDir: t.TempDir(), APIServerPort: freePort(t)})

	if err := s.Start(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("first Start = %v, want the provision error", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("retry after a failed boot = %v, want nil (the claim was not released)", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("provision ran %d times, want 2 (the retry must actually boot)", got)
	}
}
