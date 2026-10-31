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
	"log/slog"
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
	source   PowerSource
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

func (f *fakePowerHost) PowerSource() PowerSource {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.source
}

func (f *fakePowerHost) setSource(src PowerSource) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.source = src
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
	// promote is the fake dark-wake timer; afterD records the armed bound.
	promote chan time.Time
	afterD  time.Duration
	log     *lockedBuffer
}

// lockedBuffer is a log sink safe to read while the reporter writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func startSleepHarness(t *testing.T, host *fakePowerHost) *sleepHarness {
	t.Helper()
	h := &sleepHarness{host: host, rec: record.NewFakeRecorder(16), done: make(chan error, 1),
		clock: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC), promote: make(chan time.Time, 1), log: &lockedBuffer{}}
	r, err := NewSleepReporter(SleepReporterConfig{NodeName: "mac-a", Recorder: h.rec, Host: host, Log: slog.New(slog.NewTextHandler(h.log, nil))})
	if err != nil {
		t.Fatalf("NewSleepReporter: %v", err)
	}
	r.now = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.clock }
	r.publish = func(context.Context) error { h.mu.Lock(); defer h.mu.Unlock(); h.publishd++; return nil }
	r.after = func(d time.Duration) <-chan time.Time {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.afterD = d
		return h.promote
	}
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
		if c.Type != nodeSleeping || c.Status != corev1.ConditionFalse || !strings.Contains(c.Message, "PreventSystemSleep assertion") {
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

// TestSleepRepeatedWillSleepIsAcknowledgedOnly pins the dark-wake path: the
// host reports no wake for a dark wake, so the will-sleep that ends one finds
// the node asleep. It is acknowledged without a second Event or publication,
// and the condition keeps the first sleep's time.
func TestSleepRepeatedWillSleepIsAcknowledgedOnly(t *testing.T) {
	host := newFakePowerHost()
	h := startSleepHarness(t, host)
	host.deliver(t, PowerWillSleep)
	_ = nextEvent(t, h.rec)
	first := h.r.condition(metav1.Now())

	h.advance(10 * time.Minute)
	start := time.Now()
	host.deliver(t, PowerWillSleep)
	if d := time.Since(start); d >= willSleepFlushGrace {
		t.Fatalf("repeated will-sleep held for %s, want an immediate ack", d)
	}
	select {
	case e := <-h.rec.Events:
		t.Fatalf("repeated will-sleep recorded %q", e)
	default:
	}
	if h.publishes() != 1 {
		t.Fatalf("publishes = %d, want 1", h.publishes())
	}
	again := h.r.condition(metav1.Now())
	if again.Status != corev1.ConditionTrue || !again.LastTransitionTime.Equal(&first.LastTransitionTime) || again.Message != first.Message {
		t.Fatalf("condition moved on a repeated will-sleep: %+v then %+v", first, again)
	}
}

// TestSleepConditionReportsPowerSource pins the message's honesty: the held
// assertion is described by what macOS does with it on the current source.
func TestSleepConditionReportsPowerSource(t *testing.T) {
	cases := []struct {
		name string
		src  PowerSource
		want string
	}{
		{"on AC power the assertion holds", PowerSourceAC, "is on external power, so it does not idle-sleep"},
		{"on a UPS the assertion holds", PowerSourceUPS, "is on external power, so it does not idle-sleep"},
		{"on battery the assertion is ignored", PowerSourceBattery, "ignores on battery power: the Mac is on battery and can idle-sleep"},
		{"an unread source claims nothing", PowerSourceUnknown, "the power source could not be read"},
	}
	host := newFakePowerHost()
	h := startSleepHarness(t, host)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host.setSource(tc.src)
			c := h.r.condition(metav1.Now())
			if !strings.Contains(c.Message, tc.want) {
				t.Fatalf("message %q, want it to contain %q", c.Message, tc.want)
			}
		})
	}
}

// TestSleepConditionTransitionTimes pins LastTransitionTime to the flips: the
// reporter's start while awake, the sleep, then the wake, and never the time
// of the call.
func TestSleepConditionTransitionTimes(t *testing.T) {
	host := newFakePowerHost()
	h := startSleepHarness(t, host)
	start := h.r.condition(metav1.Now()).LastTransitionTime
	later := metav1.NewTime(time.Now().Add(time.Hour))
	if got := h.r.condition(later).LastTransitionTime; !got.Equal(&start) {
		t.Fatalf("awake LastTransitionTime moved from %v to %v", start, got)
	}

	h.advance(time.Minute)
	sleptAt := metav1.NewTime(h.r.now())
	host.deliver(t, PowerWillSleep)
	_ = nextEvent(t, h.rec)
	if got := h.r.condition(later).LastTransitionTime; !got.Equal(&sleptAt) {
		t.Fatalf("asleep LastTransitionTime = %v, want the sleep time %v", got, sleptAt)
	}

	h.advance(time.Hour)
	wokeAt := metav1.NewTime(h.r.now())
	host.deliver(t, PowerDidWake)
	_ = nextEvent(t, h.rec)
	if got := h.r.condition(later).LastTransitionTime; !got.Equal(&wokeAt) {
		t.Fatalf("woken LastTransitionTime = %v, want the wake time %v", got, wokeAt)
	}
}

// waitPublishes waits until the harness has seen n publications.
func (h *sleepHarness) waitPublishes(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for h.publishes() < n {
		if time.Now().After(deadline) {
			t.Fatalf("publishes = %d, want %d", h.publishes(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestSleepLongDarkWakeIsServing pins the promotion with a fake clock: a dark
// wake keeps Sleeping=True until it has lasted 60 s, then publishes
// Sleeping=False with reason DarkWake; the next will-sleep is a real sleep
// again, with its Event and publication.
func TestSleepLongDarkWakeIsServing(t *testing.T) {
	host := newFakePowerHost()
	h := startSleepHarness(t, host)
	host.deliver(t, PowerWillSleep)
	_ = nextEvent(t, h.rec)

	h.advance(30 * time.Minute)
	host.deliver(t, PowerDarkWake)
	if c := h.r.condition(metav1.Now()); c.Status != corev1.ConditionTrue {
		t.Fatalf("a fresh dark wake changed Sleeping: %+v", c)
	}
	h.mu.Lock()
	armed := h.afterD
	h.mu.Unlock()
	if armed != darkWakePromoteAfter || darkWakePromoteAfter != 60*time.Second {
		t.Fatalf("promotion armed for %s, want 60s", armed)
	}
	if h.publishes() != 1 {
		t.Fatalf("a dark wake published: publishes = %d, want 1", h.publishes())
	}

	h.advance(61 * time.Second)
	h.promote <- time.Now()
	h.waitPublishes(t, 2)
	c := h.r.condition(metav1.Now())
	if c.Status != corev1.ConditionFalse || c.Reason != sleepDarkReason || !strings.Contains(c.Message, "maintenance (dark) wake") || !strings.Contains(c.Message, "serving") {
		t.Fatalf("long dark wake condition = %+v", c)
	}

	host.deliver(t, PowerWillSleep)
	if e := nextEvent(t, h.rec); !strings.HasPrefix(e, "Normal "+sleepEventReason+" ") {
		t.Fatalf("sleep after a serving dark wake recorded %q", e)
	}
	if h.publishes() != 3 {
		t.Fatalf("publishes = %d after the next sleep, want 3", h.publishes())
	}
	if c := h.r.condition(metav1.Now()); c.Status != corev1.ConditionTrue || c.Reason != sleepWillReason {
		t.Fatalf("condition after the next sleep = %+v", c)
	}
}

// TestSleepShortDarkWakeIsNotPromoted pins the other side: a dark wake that
// ends in sleep before 60 s leaves Sleeping=True, and the timer firing late
// changes nothing.
func TestSleepShortDarkWakeIsNotPromoted(t *testing.T) {
	host := newFakePowerHost()
	h := startSleepHarness(t, host)
	host.deliver(t, PowerWillSleep)
	_ = nextEvent(t, h.rec)
	host.deliver(t, PowerDarkWake)
	h.advance(20 * time.Second)
	host.deliver(t, PowerWillSleep)
	h.promote <- time.Now()
	host.deliver(t, PowerWillSleep) // a round trip through Run after the firing
	if h.publishes() != 1 {
		t.Fatalf("publishes = %d, want 1", h.publishes())
	}
	if c := h.r.condition(metav1.Now()); c.Status != corev1.ConditionTrue || c.Reason != sleepWillReason {
		t.Fatalf("condition = %+v, want still asleep", c)
	}
}

// TestSleepUnclassifiedWakeWarnsOnce pins the visible fail-open: a host that
// cannot classify wakes makes the reporter warn once, not per notice.
func TestSleepUnclassifiedWakeWarnsOnce(t *testing.T) {
	host := newFakePowerHost()
	h := startSleepHarness(t, host)
	host.deliver(t, PowerWakeUnclassified)
	host.deliver(t, PowerWakeUnclassified)
	if n := strings.Count(h.log.String(), "dark wakes (Power Nap, maintenance wakes) will be counted as full wakes"); n != 1 {
		t.Fatalf("warned %d times, want once:\n%s", n, h.log.String())
	}
	if !strings.Contains(h.log.String(), "level=WARN") {
		t.Fatalf("not logged at Warn:\n%s", h.log.String())
	}
}
