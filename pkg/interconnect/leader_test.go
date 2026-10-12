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

package interconnect

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// TestResolverStartRetriesTheCRDEnsure pins that a CRD the apiserver will not
// take yet is retried with backoff, warned once per distinct error, and never
// disables the resolver.
func TestResolverStartRetriesTheCRDEnsure(t *testing.T) {
	logs := &countingHandler{}
	r := NewResolver(ResolverConfig{Log: slog.New(logs)})
	r.startBackoff = time.Millisecond
	calls := 0
	r.ensureCRD = func(context.Context) error {
		calls++
		if calls <= 2 {
			return errors.New("the server could not find the requested resource")
		}
		return nil
	}
	if err := r.start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if calls != 3 {
		t.Errorf("ensure called %d times, want 3 (two failures, then success)", calls)
	}
	if w := logs.warns.Load(); w != 1 {
		t.Errorf("the same failure warned %d times, want once", w)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.ensureCRD = func(context.Context) error { return errors.New("down") }
	if err := r.start(ctx); err == nil {
		t.Error("start returned nil after its context ended with the CRD still failing")
	}
}

// recordingLock is a resourcelock.Interface that records the order of a
// release update relative to the drain.
type recordingLock struct {
	resourcelock.Interface
	events *[]string
}

func (l recordingLock) Update(_ context.Context, ler resourcelock.LeaderElectionRecord) error {
	if ler.HolderIdentity == "" {
		*l.events = append(*l.events, "release")
	} else {
		*l.events = append(*l.events, "renew")
	}
	return nil
}

// TestReleaseDrainsTheLeadFirst pins that a Lease release (client-go sends it
// from its renew loop before it cancels the leading callback) waits until the
// leading work has stopped, so no reconcile overlaps the next leader; a renew
// does not drain.
func TestReleaseDrainsTheLeadFirst(t *testing.T) {
	var events []string
	lock := drainOnRelease{
		Interface: recordingLock{events: &events},
		drain:     func() { events = append(events, "drained") },
	}
	ctx := context.Background()
	if err := lock.Update(ctx, resourcelock.LeaderElectionRecord{HolderIdentity: "studio"}); err != nil {
		t.Fatal(err)
	}
	if err := lock.Update(ctx, resourcelock.LeaderElectionRecord{}); err != nil {
		t.Fatal(err)
	}
	want := []string{"renew", "drained", "release"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
}
