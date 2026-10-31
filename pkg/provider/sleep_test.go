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

package provider

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
)

// fakePowerHost is the PowerHost of the sleep tests: it records the assertion
// and lets a test deliver notices.
type fakePowerHost struct {
	mu       sync.Mutex
	held     int
	taken    int
	released int
	name     string
	holdErr  error
	notices  chan PowerNotice
	watching chan struct{}
}

func newFakePowerHost() *fakePowerHost {
	return &fakePowerHost{notices: make(chan PowerNotice), watching: make(chan struct{})}
}

func (f *fakePowerHost) PreventSleep(name string) (func() error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.holdErr != nil {
		return nil, f.holdErr
	}
	f.held++
	f.taken++
	f.name = name
	return func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.held--
		f.released++
		return nil
	}, nil
}

func (f *fakePowerHost) WatchSleep(ctx context.Context) (<-chan PowerNotice, error) {
	out := make(chan PowerNotice)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case n := <-f.notices:
				select {
				case out <- n:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	close(f.watching)
	return out, nil
}

func (f *fakePowerHost) state() (held, taken, released int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held, f.taken, f.released
}

// deliver sends one notice and waits for its acknowledgement.
func (f *fakePowerHost) deliver(t *testing.T, kind PowerNoticeKind) {
	t.Helper()
	acked := make(chan struct{})
	n := PowerNotice{Kind: kind, Ack: func() { close(acked) }}
	select {
	case f.notices <- n:
	case <-time.After(5 * time.Second):
		t.Fatal("notice not taken")
	}
	select {
	case <-acked:
	case <-time.After(10 * time.Second):
		t.Fatal("notice not acknowledged")
	}
}

type sleepHarness struct {
	host     *fakePowerHost
	rec      *record.FakeRecorder
	r        *SleepReporter
	cancel   context.CancelFunc
	done     chan error
	mu       sync.Mutex
	clock    time.Time
	publishd int
}

func startSleepHarness(t *testing.T, host *fakePowerHost) *sleepHarness {
	t.Helper()
	h := &sleepHarness{host: host, rec: record.NewFakeRecorder(16), done: make(chan error, 1),
		clock: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)}
	r, err := NewSleepReporter(SleepReporterConfig{NodeName: "mac-a", Recorder: h.rec, Host: host, Log: discardLog()})
	if err != nil {
		t.Fatalf("NewSleepReporter: %v", err)
	}
	r.now = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.clock }
	r.publish = func(context.Context) error { h.mu.Lock(); defer h.mu.Unlock(); h.publishd++; return nil }
	h.r = r
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- r.Run(ctx) }()
	select {
	case <-host.watching:
	case <-time.After(5 * time.Second):
		t.Fatal("reporter never watched for sleep")
	}
	t.Cleanup(func() { cancel(); <-h.done })
	return h
}

func (h *sleepHarness) advance(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clock = h.clock.Add(d)
}

func (h *sleepHarness) publishes() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.publishd
}

func nextEvent(t *testing.T, rec *record.FakeRecorder) string {
	t.Helper()
	select {
	case e := <-rec.Events:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no Event recorded")
		return ""
	}
}

// TestSleepAssertionHeldWhileJoined pins the assertion's span: taken when the
// node starts, held while it runs, released when the node's context ends (the
// leave and stop paths).
func TestSleepAssertionHeldWhileJoined(t *testing.T) {
	t.Run("held while the node runs", func(t *testing.T) {
		host := newFakePowerHost()
		h := startSleepHarness(t, host)
		if held, taken, _ := host.state(); held != 1 || taken != 1 {
			t.Fatalf("held=%d taken=%d, want one assertion held", held, taken)
		}
		if !h.r.Held() {
			t.Fatal("Held() = false while running")
		}
		if host.name != sleepAssertionName {
			t.Fatalf("assertion name %q", host.name)
		}
		c := h.r.condition(metav1.Now())
		if c.Type != nodeSleeping || c.Status != corev1.ConditionFalse || !strings.Contains(c.Message, "PreventSystemSleep") {
			t.Fatalf("awake condition = %+v", c)
		}
	})
	t.Run("released when the node stops", func(t *testing.T) {
		host := newFakePowerHost()
		h := startSleepHarness(t, host)
		h.cancel()
		select {
		case err := <-h.done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Run = %v", err)
			}
			h.done <- err // for the cleanup
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return on stop")
		}
		if held, _, released := host.state(); held != 0 || released != 1 {
			t.Fatalf("held=%d released=%d after stop, want released once", held, released)
		}
		if h.r.Held() {
			t.Fatal("Held() = true after stop")
		}
	})
	t.Run("a refused assertion is reported, the node still runs", func(t *testing.T) {
		host := newFakePowerHost()
		host.holdErr = errors.New("IOReturn 0xe00002c2")
		h := startSleepHarness(t, host)
		c := h.r.condition(metav1.Now())
		if h.r.Held() || !strings.Contains(c.Message, "no sleep assertion is held") {
			t.Fatalf("condition = %+v held=%v", c, h.r.Held())
		}
	})
}

// TestSleepAndWakeAreReported pins the report: a will-sleep notice raises
// Sleeping=True, records SystemSleep and publishes BEFORE it is acknowledged;
// a wake lowers it, records SystemWake with the wall-clock sleep length and
// publishes.
func TestSleepAndWakeAreReported(t *testing.T) {
	host := newFakePowerHost()
	h := startSleepHarness(t, host)

	host.deliver(t, PowerWillSleep)
	if e := nextEvent(t, h.rec); !strings.HasPrefix(e, "Normal "+sleepEventReason+" ") {
		t.Fatalf("sleep Event = %q", e)
	}
	if h.publishes() != 1 {
		t.Fatalf("publishes = %d before the will-sleep ack, want 1", h.publishes())
	}
	c := h.r.condition(metav1.Now())
	if c.Status != corev1.ConditionTrue || c.Reason != sleepWillReason {
		t.Fatalf("asleep condition = %+v", c)
	}

	h.advance(90 * time.Minute)
	host.deliver(t, PowerDidWake)
	e := nextEvent(t, h.rec)
	if !strings.HasPrefix(e, "Normal "+wakeEventReason+" ") || !strings.Contains(e, "after 1h30m0s") {
		t.Fatalf("wake Event = %q", e)
	}
	if h.publishes() != 2 {
		t.Fatalf("publishes = %d after wake, want 2", h.publishes())
	}
	c = h.r.condition(metav1.Now())
	if c.Status != corev1.ConditionFalse || c.Reason != sleepWokeReason || !strings.Contains(c.Message, "after 1h30m0s") {
		t.Fatalf("woken condition = %+v", c)
	}
}

// TestNodeStatusPublishesSleeping pins the status side: the published node
// carries the reporter's Sleeping condition, and a reporter's publish request
// is served by Run at once.
func TestNodeStatusPublishesSleeping(t *testing.T) {
	r, err := NewSleepReporter(SleepReporterConfig{NodeName: "mac-a", Host: newFakePowerHost(), Log: discardLog()})
	if err != nil {
		t.Fatal(err)
	}
	h := &nodeStatusHarness{t: t, stats: healthyStats(), healthy: true, clock: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)}
	p, err := NewNodeStatusProvider(NodeStatusConfig{
		Node: bootstrapNode(), DataRoot: "/var/lib/k3sm", RuntimeHealthy: h.runtimeHealthy,
		Interval: time.Hour, Log: discardLog(), Sleep: r,
	})
	if err != nil {
		t.Fatal(err)
	}
	p.sample, p.now, p.publish = h.sample, h.nowFn, h.publishFn
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Run(ctx) }()
	defer func() { cancel(); <-done }()

	r.mu.Lock()
	r.asleep, r.sleptAt = true, time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	r.mu.Unlock()
	pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
	defer pcancel()
	if err := r.publish(pctx); err != nil {
		t.Fatalf("publish request: %v", err)
	}
	h.mu.Lock()
	last := h.published[len(h.published)-1]
	h.mu.Unlock()
	c := findNodeCondition(last.Status.Conditions, nodeSleeping)
	if c == nil || c.Status != corev1.ConditionTrue || c.Reason != sleepWillReason {
		t.Fatalf("published Sleeping = %+v", c)
	}
}
