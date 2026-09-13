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
	"strings"
	"testing"
	"time"
)

// TestMeshEndpointRefresherRepublishesOnChange is B283's B2 leg: the debounce and
// retry policy of the endpoint refresher, driven tick by tick.
//
// Every row encodes a failure this loop must not have. Publishing on the FIRST
// differing derivation would let a single transient sample during a Wi-Fi
// transition point every peer at an address that is about to disappear — and a
// peer cannot tell a dead endpoint from a live one, it just never completes a
// handshake. Publishing the value the node joined with would write on every start.
// Not retrying a failed publish would leave the CR stale until the address changed
// AGAIN. Replacing the published value when the derivation itself fails would
// trade a possibly-stale endpoint for a certainly-wrong one.
func TestMeshEndpointRefresherRepublishesOnChange(t *testing.T) {
	const (
		joined = "192.168.0.206:51820"
		moved  = "192.168.0.111:51820"
		other  = "192.168.0.222:51820"
	)
	errDerive := errors.New("no route to the control plane")

	cases := []struct {
		name string
		// derived is the value each tick's derivation returns; "" is a failure.
		derived []string
		// failPublish names the publish attempts (0-based) that fail.
		failPublish map[int]bool
		// want is the sequence of values handed to publish.
		want []string
	}{
		{
			name:    "the joined value is never republished",
			derived: []string{joined, joined, joined, joined},
		},
		{
			name:    "a change is published on the SECOND consecutive sighting",
			derived: []string{moved, moved, moved},
			want:    []string{moved},
		},
		{
			name:    "a single-tick flap is never published",
			derived: []string{joined, other, joined, joined},
		},
		{
			name:    "an oscillation never settles and never publishes",
			derived: []string{moved, other, moved, other},
		},
		{
			name:        "a failed publish is retried on the next tick",
			derived:     []string{moved, moved, moved},
			failPublish: map[int]bool{0: true},
			want:        []string{moved, moved},
		},
		{
			name:    "a derivation failure keeps the published value",
			derived: []string{"", "", "", joined},
		},
		{
			name:    "a derivation failure does not lose a pending sighting",
			derived: []string{moved, "", moved, moved},
			want:    []string{moved},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				tick      int
				published []string
				attempts  int
			)
			r := &meshEndpointRefresher{
				derive: func(context.Context) (string, error) {
					v := tc.derived[tick]
					tick++
					if v == "" {
						return "", errDerive
					}
					return v, nil
				},
				publish: func(_ context.Context, endpoint string) error {
					attempts++
					if tc.failPublish[attempts-1] {
						published = append(published, endpoint)
						return errors.New("supervisor unreachable")
					}
					published = append(published, endpoint)
					return nil
				},
				log:       quietLogger(),
				published: joined,
				announced: joined,
			}
			for range tc.derived {
				r.tickOnce(context.Background())
			}
			if strings.Join(published, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("published %v, want %v", published, tc.want)
			}
			// The remembered value must be the last SUCCESSFUL publish, so a
			// later unchanged derivation produces no further write.
			want := joined
			if n := len(tc.want); n > 0 && !tc.failPublish[n-1] {
				want = tc.want[n-1]
			}
			if r.published != want {
				t.Errorf("remembered endpoint = %q, want %q", r.published, want)
			}
		})
	}

	t.Run("Run publishes on ticks and stops with ctx", func(t *testing.T) {
		// The tick channel is UNBUFFERED, so a successful send proves the loop
		// received the previous one and finished its cycle — no sleeps, no polling.
		ticks := make(chan time.Time)
		done := make(chan struct{})
		var published []string
		r := &meshEndpointRefresher{
			derive:    func(context.Context) (string, error) { return moved, nil },
			publish:   func(_ context.Context, e string) error { published = append(published, e); return nil },
			log:       quietLogger(),
			tick:      ticks,
			published: joined,
			announced: joined,
		}
		ctx, cancel := context.WithCancel(context.Background())
		var runErr error
		go func() {
			runErr = r.Run(ctx)
			close(done)
		}()
		ticks <- time.Now() // first sighting: debounced
		ticks <- time.Now() // second: published
		ticks <- time.Now() // a third send proves the second cycle completed
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after its context was cancelled")
		}
		if !errors.Is(runErr, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", runErr)
		}
		if len(published) != 1 || published[0] != moved {
			t.Errorf("published %v, want exactly one %q", published, moved)
		}
	})

	t.Run("the refresh interval matches the mesh resync period", func(t *testing.T) {
		// A refresher slower than darwin-net's resync would let a peer re-program
		// the stale endpoint from the CR between the move and the republish.
		if meshRefreshInterval != 30*time.Second {
			t.Errorf("meshRefreshInterval = %s, want 30s (darwin-net's meshResyncPeriod)", meshRefreshInterval)
		}
	})
}
