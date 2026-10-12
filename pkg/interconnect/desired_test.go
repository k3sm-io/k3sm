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
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// fakeNetd is the root helper: it holds the slot-0 alias, can lose it, and can
// fail every call with a set error.
type fakeNetd struct {
	mu      sync.Mutex
	alias   bool
	err     error
	ensures int
	removes int
}

func (f *fakeNetd) EnsureInterconnectAlias(_ context.Context, slot int) (netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensures++
	if f.err != nil {
		return netip.Addr{}, f.err
	}
	if slot != 0 {
		return netip.Addr{}, fmt.Errorf("unexpected slot %d", slot)
	}
	f.alias = true
	return netip.MustParseAddr("169.254.0.1"), nil
}

func (f *fakeNetd) RemoveInterconnectAlias(_ context.Context, slot int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removes++
	if f.err != nil {
		return f.err
	}
	f.alias = false
	return nil
}

func (f *fakeNetd) state() (alias bool, ensures, removes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alias, f.ensures, f.removes
}

func (f *fakeNetd) lose() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alias = false
}

// countingHandler counts slog records at Warn and above.
type countingHandler struct{ warns atomic.Int32 }

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		h.warns.Add(1)
	}
	return nil
}
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

const desiredValue = `{"schema":1,"interconnect":"thunderbolt","fallback":"network"}`

// TestDesiredHandlerLevelTriggered is the B524 desired-handler gate: ensure on
// add, remove on drop, re-ensure after the helper loses the alias and after a
// reconnect, no hot retry on any named error, and the reason carried into the
// report.
func TestDesiredHandlerLevelTriggered(t *testing.T) {
	ctx := context.Background()

	t.Run("ensure on add, remove on drop, re-ensure after loss", func(t *testing.T) {
		netd := &fakeNetd{}
		ann := &fakeAnnotation{synced: true}
		h := NewDesiredHandler(DesiredConfig{Node: "a", Desired: ann, Client: netd, Log: slog.New(slog.DiscardHandler), Metrics: NewMetrics()})

		ann.value = desiredValue
		h.Reconcile(ctx)
		if alias, ensures, _ := netd.state(); !alias || ensures != 1 {
			t.Fatalf("after add: alias=%v ensures=%d, want the alias ensured once", alias, ensures)
		}
		netd.lose()
		h.Reconcile(ctx) // the next tick, with nothing changed on the Node
		if alias, ensures, _ := netd.state(); !alias || ensures != 2 {
			t.Fatalf("after the helper lost the alias: alias=%v ensures=%d, want it re-ensured on the tick", alias, ensures)
		}
		ann.value = ""
		h.Reconcile(ctx)
		if alias, _, removes := netd.state(); alias || removes != 1 {
			t.Fatalf("after drop: alias=%v removes=%d, want removed", alias, removes)
		}
		ann.value = "thunderbolt;fallback=network" // unreadable: treated as absent
		h.Reconcile(ctx)
		if alias, _, removes := netd.state(); alias || removes != 2 {
			t.Fatalf("unreadable desired: alias=%v removes=%d, want removed", alias, removes)
		}
	})

	t.Run("an unsynced cache does nothing", func(t *testing.T) {
		netd := &fakeNetd{alias: true}
		h := NewDesiredHandler(DesiredConfig{Desired: &fakeAnnotation{}, Client: netd, Log: slog.New(slog.DiscardHandler)})
		h.Reconcile(ctx)
		if alias, ensures, removes := netd.state(); !alias || ensures+removes != 0 {
			t.Fatalf("unsynced: alias=%v calls=%d, want nothing touched", alias, ensures+removes)
		}
	})

	t.Run("re-ensure on reconnect", func(t *testing.T) {
		netd := &fakeNetd{}
		ann := &fakeAnnotation{synced: true, value: desiredValue}
		var down atomic.Bool
		down.Store(true)
		h := NewDesiredHandler(DesiredConfig{
			Desired: ann, Client: netd, Log: slog.New(slog.DiscardHandler),
			Interval:    time.Hour, // no tick inside the test: only the reconnect may re-ensure
			HealthEvery: 2 * time.Millisecond,
			Reachable: func(context.Context) error {
				if down.Load() {
					return errors.New("dial: connection refused")
				}
				return nil
			},
		})
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); h.Run(runCtx, nil) }()
		defer func() { cancel(); <-done }()

		waitFor(t, func() bool { _, e, _ := netd.state(); return e == 1 }, "the start-up ensure")
		netd.lose() // the helper restarted and came back empty
		time.Sleep(20 * time.Millisecond)
		if _, e, _ := netd.state(); e != 1 {
			t.Fatalf("ensures = %d while the helper is down, want no retries", e)
		}
		down.Store(false)
		waitFor(t, func() bool { a, e, _ := netd.state(); return a && e == 2 }, "the reconnect re-ensure")
	})

	t.Run("named errors: no hot retry, one warn per state, reason reported", func(t *testing.T) {
		cases := []struct {
			err    error
			reason string
		}{
			{fmt.Errorf("%w: needs minor 2", wire.ErrHelperTooOld), ReasonHelperTooOld},
			{fmt.Errorf("netd: %w", wire.ErrInterconnectIndexOutOfRange), wire.ReasonInterconnectIndexOutOfRange},
			{fmt.Errorf("netd: %w", wire.ErrInterconnectNoBridge), wire.ReasonInterconnectNoBridge},
			{fmt.Errorf("netd: %w", wire.ErrInterconnectIdentityUnadopted), wire.ReasonInterconnectIdentityUnadopted},
		}
		for _, tc := range cases {
			t.Run(tc.reason, func(t *testing.T) {
				netd := &fakeNetd{err: tc.err}
				logs := &countingHandler{}
				rep, _, ann, _ := newTestReporter(t)
				if _, err := rep.Sync(ctx, t0); err != nil {
					t.Fatal(err)
				}
				m := NewMetrics()
				h := NewDesiredHandler(DesiredConfig{
					Desired: &fakeAnnotation{synced: true, value: desiredValue}, Client: netd,
					OnReason: rep.SetHelperReason, Metrics: m, Log: slog.New(logs),
				})
				h.Reconcile(ctx)
				if _, ensures, _ := netd.state(); ensures != 1 {
					t.Fatalf("one reconcile made %d calls; a named error must not be retried in place", ensures)
				}
				h.Reconcile(ctx)
				if _, ensures, _ := netd.state(); ensures != 2 {
					t.Fatalf("two reconciles made %d calls", ensures)
				}
				if w := logs.warns.Load(); w != 1 {
					t.Errorf("the same error warned %d times, want once per state change", w)
				}
				if got := rep.HelperReason(); got != tc.reason {
					t.Errorf("reporter reason = %q, want %q", got, tc.reason)
				}
				if tc.reason == ReasonHelperTooOld {
					if _, err := rep.Sync(ctx, t0.Add(time.Minute)); err != nil {
						t.Fatal(err)
					}
					if ann.value != "" {
						t.Errorf("a helper too old left the report %q; the node must report no interconnect", ann.value)
					}
				}
				var seen bool
				for _, f := range m.Families() {
					if f.GetName() != metricNetdVerbResults {
						continue
					}
					for _, s := range f.Metric {
						if s.GetLabel()[1].GetValue() == tc.reason && s.GetCounter().GetValue() == 2 {
							seen = true
						}
					}
				}
				if !seen {
					t.Errorf("the netd result counter does not carry %s twice", tc.reason)
				}
				// Recovery clears the reason and logs the new state once.
				netd.mu.Lock()
				netd.err = nil
				netd.mu.Unlock()
				h.Reconcile(ctx)
				if got := rep.HelperReason(); got != "" {
					t.Errorf("reason after recovery = %q, want empty", got)
				}
			})
		}
	})
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
