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
	"fmt"
	"log/slog"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
)

// System sleep on a joined node.
//
// A Mac that sleeps stops posting node status and renewing its Lease, so the
// node-lifecycle controller marks it NotReady (Ready=Unknown, "Kubelet stopped
// posting node status") with nothing to say why. Two things here address it:
//
//   - While the node runs, it holds a PreventSystemSleep power assertion, so a
//     Mac on AC power does not idle-sleep under its pods. macOS ignores this
//     assertion class on battery power and it never stops a forced sleep (the
//     Apple menu's Sleep, a closed lid without an external display), so the
//     node can still sleep, and the condition says which power source the Mac
//     is on, so it never claims a protection macOS is not giving. When it does
//     sleep:
//   - The node reports it. On the system's will-sleep notice it publishes a
//     Sleeping=True condition and a SystemSleep Event BEFORE acknowledging the
//     notice, so the NotReady that follows carries a reason on the Node. On
//     wake it publishes Sleeping=False and a SystemWake Event naming how long
//     the Mac slept. A dark wake (Power Nap, a maintenance wake) is not a
//     full wake: Sleeping stays True through a short one, the reporter
//     publishes nothing for it (the regular status heartbeat may still land),
//     and the will-sleep that ends it is acknowledged at once. A dark wake
//     that lasts past darkWakePromoteAfter, which a headless Mac on AC power
//     holding the assertion can stay in indefinitely while it serves, is
//     published as Sleeping=False with reason DarkWake.
//
// The assertion and the notices come through PowerHost, the seam over IOKit's
// power-management API (sleep_darwin.go); tests use a fake.

// nodeSleeping is the condition type reporting system sleep. It is k3sm's own,
// like SoftPressure: nothing taints a node on it.
const nodeSleeping corev1.NodeConditionType = "Sleeping"

// The Sleeping condition's Reason vocabulary and the Event reasons.
const (
	sleepAwakeReason   = "SystemAwake"
	sleepWillReason    = "SystemWillSleep"
	sleepWokeReason    = "SystemWoke"
	sleepDarkReason    = "DarkWake"
	sleepEventReason   = "SystemSleep"
	wakeEventReason    = "SystemWake"
	sleepAssertionName = "k3sm node: pods are scheduled on this Mac"
)

// willSleepPublishTimeout bounds the publication of Sleeping=True on a
// will-sleep notice, and willSleepFlushGrace is the extra time the notice is
// held so the queued status write and Event reach the apiserver before the Mac
// sleeps. Their sum stays well under the bound the darwin host holds a notice
// for (sleepAckTimeoutMillis), and under the system's own 30 s limit.
const (
	willSleepPublishTimeout = 3 * time.Second
	willSleepFlushGrace     = 2 * time.Second
)

// darkWakePromoteAfter is how long a dark wake lasts before the node reports
// itself as serving rather than sleeping.
const darkWakePromoteAfter = 60 * time.Second

// PowerNoticeKind names a system power transition.
type PowerNoticeKind int

const (
	// PowerWillSleep is delivered before the system sleeps. The system waits
	// for its Ack (or a bound) before it goes on.
	PowerWillSleep PowerNoticeKind = iota + 1
	// PowerDidWake is delivered after a full (user) wake.
	PowerDidWake
	// PowerDarkWake is delivered once when a sleep turns into a dark wake.
	PowerDarkWake
	// PowerWakeUnclassified is delivered once when the host cannot tell a
	// dark wake from a full one, and will count every wake as full.
	PowerWakeUnclassified
)

// PowerNotice is one system power transition. Ack, when non-nil, lets the
// system proceed; every receiver of a PowerWillSleep calls it exactly once.
type PowerNotice struct {
	Kind PowerNoticeKind
	Ack  func()
}

// PowerSource names the power source the Mac draws from.
type PowerSource int

const (
	// PowerSourceUnknown is a source the host could not read.
	PowerSourceUnknown PowerSource = iota
	// PowerSourceAC is external power: the sleep assertion is honoured.
	PowerSourceAC
	// PowerSourceBattery is the internal battery: macOS ignores the assertion.
	PowerSourceBattery
	// PowerSourceUPS is a UPS reporting itself as one: external power.
	PowerSourceUPS
)

// PowerHost is the host power-management seam the sleep reporter consumes.
type PowerHost interface {
	// PreventSleep takes a PreventSystemSleep assertion named name and returns
	// the function that releases it.
	PreventSleep(name string) (release func() error, err error)
	// PowerSource reports the power source the Mac draws from now.
	PowerSource() PowerSource
	// WatchSleep delivers the system's sleep notices, its full wakes and the
	// start of each dark wake until ctx is done, then closes the channel.
	WatchSleep(ctx context.Context) (<-chan PowerNotice, error)
}

// SleepReporterConfig is the input to NewSleepReporter.
type SleepReporterConfig struct {
	// NodeName names the Node the Events are recorded on. Required.
	NodeName string
	// Recorder receives the SystemSleep and SystemWake Events; nil records none.
	Recorder record.EventRecorder
	// Host is the power seam; nil uses this build's host (IOKit on darwin).
	Host PowerHost
	// Log receives the diagnostics; nil uses slog.Default().
	Log *slog.Logger
}

// SleepReporter holds the node's sleep assertion for its lifetime and turns
// the system's sleep and wake notices into the Sleeping condition and Events.
//
// mu guards the state fields; it is never held across a publish, an Event or
// a host call.
type SleepReporter struct {
	nodeName string
	recorder record.EventRecorder
	host     PowerHost
	log      *slog.Logger
	now      func() time.Time
	// after is the dark-wake promotion timer; tests substitute a fake.
	after func(time.Duration) <-chan time.Time

	// publish asks the status loop for an immediate publication; set by
	// NewNodeStatusProvider. nil until a status provider adopts the reporter.
	publish func(ctx context.Context) error

	mu        sync.Mutex
	startedAt time.Time
	held      bool
	holdErr   error
	asleep    bool
	sleptAt   time.Time
	wokeAt    time.Time
	sleptFor  time.Duration
	everWoken bool
	// darkAt is when the current sleep turned into a dark wake (zero if it
	// has not); darkServing is set, at darkServingAt, once that dark wake has
	// lasted darkWakePromoteAfter. asleep stays true through both.
	darkAt        time.Time
	darkServing   bool
	darkServingAt time.Time
	// warnedUnclassified records the one-time Warn for PowerWakeUnclassified.
	warnedUnclassified bool
}

// NewSleepReporter returns a reporter for the named node.
func NewSleepReporter(cfg SleepReporterConfig) (*SleepReporter, error) {
	if cfg.NodeName == "" {
		return nil, errors.New("provider: SleepReporterConfig.NodeName is required")
	}
	host := cfg.Host
	if host == nil {
		host = newPowerHost()
	}
	rec := cfg.Recorder
	if rec == nil {
		rec = nopRecorder{}
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	r := &SleepReporter{nodeName: cfg.NodeName, recorder: rec, host: host, log: log, now: time.Now, after: time.After}
	r.startedAt = r.now().Round(0)
	return r, nil
}

// Run holds the sleep assertion and handles power notices until ctx is done,
// then releases the assertion. ctx ends when the node leaves the cluster or
// the daemon stops, which is exactly the span the assertion covers; process
// exit releases it too, since IOKit ties an assertion to its process. A host
// that cannot take the assertion or watch notices is logged and reported on
// the condition; Run then waits out ctx, because a node runs without either.
func (r *SleepReporter) Run(ctx context.Context) error {
	release, err := r.host.PreventSleep(sleepAssertionName)
	r.mu.Lock()
	r.held, r.holdErr = err == nil, err
	r.mu.Unlock()
	if err != nil {
		r.log.Warn("could not hold a sleep assertion; this Mac may idle-sleep while joined", "error", err)
	} else {
		defer func() {
			if rerr := release(); rerr != nil {
				r.log.Warn("could not release the sleep assertion", "error", rerr)
			}
			r.mu.Lock()
			r.held = false
			r.mu.Unlock()
		}()
	}
	notices, err := r.host.WatchSleep(ctx)
	if err != nil {
		r.log.Warn("could not watch for system sleep; a sleeping node reports no reason", "error", err)
		<-ctx.Done()
		return ctx.Err()
	}
	// promote fires darkWakePromoteAfter into a dark wake; only this loop
	// touches it. A stale firing (the dark wake already ended) is a no-op.
	var promote <-chan time.Time
	for {
		select {
		case <-promote:
			promote = nil
			r.promoteDark(ctx)
		case <-ctx.Done():
			// Drain so a host blocked on a will-sleep is acknowledged.
			for n := range notices {
				if n.Ack != nil {
					n.Ack()
				}
			}
			return ctx.Err()
		case n, ok := <-notices:
			if !ok {
				<-ctx.Done()
				return ctx.Err()
			}
			if r.handle(ctx, n) {
				promote = r.after(darkWakePromoteAfter)
			}
		}
	}
}

// Held reports whether the sleep assertion is currently held.
func (r *SleepReporter) Held() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.held
}

// handle applies one notice: state first, then the Event and the publication,
// then the acknowledgement, so the condition is on its way before the Mac
// sleeps. It reports whether a dark wake began, arming the promotion timer.
func (r *SleepReporter) handle(ctx context.Context, n PowerNotice) (darkBegan bool) {
	ref := &corev1.ObjectReference{Kind: "Node", Name: r.nodeName, UID: types.UID(r.nodeName)}
	switch n.Kind {
	case PowerWillSleep:
		r.mu.Lock()
		if r.asleep && !r.darkServing {
			// The end of a short dark wake: the node never reported waking,
			// so there is nothing to publish and the original sleep time
			// stands. The dark wake is over, so its promotion is void.
			r.darkAt = time.Time{}
			r.mu.Unlock()
			break
		}
		r.asleep, r.darkAt, r.darkServing = true, time.Time{}, false
		// Wall clock, monotonic reading stripped: the monotonic clock does not
		// advance while a Mac sleeps, so only the wall clock measures the sleep.
		r.sleptAt = r.now().Round(0)
		r.mu.Unlock()
		r.recorder.Event(ref, corev1.EventTypeNormal, sleepEventReason, "Node is going to system sleep; it posts no status while the Mac sleeps")
		r.publishNow(ctx, willSleepPublishTimeout)
		select {
		case <-ctx.Done():
		case <-time.After(willSleepFlushGrace):
		}
	case PowerDidWake:
		r.mu.Lock()
		now := r.now().Round(0)
		var slept time.Duration
		if r.asleep && !r.sleptAt.IsZero() {
			slept = now.Sub(r.sleptAt)
		}
		r.asleep, r.wokeAt, r.sleptFor, r.everWoken = false, now, slept, true
		r.darkAt, r.darkServing = time.Time{}, false
		r.mu.Unlock()
		msg := "Node woke from system sleep"
		if slept > 0 {
			msg = fmt.Sprintf("Node woke from system sleep after %s", slept.Round(time.Second))
		}
		r.recorder.Event(ref, corev1.EventTypeNormal, wakeEventReason, msg)
		r.publishNow(ctx, willSleepPublishTimeout)
	case PowerDarkWake:
		r.mu.Lock()
		if r.asleep && r.darkAt.IsZero() {
			r.darkAt = r.now().Round(0)
			darkBegan = true
		}
		r.mu.Unlock()
	case PowerWakeUnclassified:
		r.mu.Lock()
		first := !r.warnedUnclassified
		r.warnedUnclassified = true
		r.mu.Unlock()
		if first {
			r.log.Warn("cannot read the system's wake capabilities; dark wakes (Power Nap, maintenance wakes) will be counted as full wakes")
		}
	}
	if n.Ack != nil {
		n.Ack()
	}
	return darkBegan
}

// promoteDark reports a dark wake that has outlasted darkWakePromoteAfter as
// serving: the Mac is awake enough to run pods, so Sleeping=True would
// misreport it. A firing after the dark wake ended does nothing.
func (r *SleepReporter) promoteDark(ctx context.Context) {
	r.mu.Lock()
	if !r.asleep || r.darkAt.IsZero() || r.darkServing {
		r.mu.Unlock()
		return
	}
	r.darkServing, r.darkServingAt = true, r.now().Round(0)
	r.mu.Unlock()
	r.publishNow(ctx, willSleepPublishTimeout)
}

// publishNow asks the status loop for an immediate publication, bounded.
func (r *SleepReporter) publishNow(ctx context.Context, bound time.Duration) {
	if r.publish == nil {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	if err := r.publish(pctx); err != nil && ctx.Err() == nil {
		r.log.Warn("could not publish the node's sleep state", "error", err)
	}
}

// condition renders the Sleeping condition at now. LastTransitionTime is the
// moment the state last flipped (the sleep, the wake, or the reporter's start),
// never now, so it holds still across publications.
func (r *SleepReporter) condition(now metav1.Time) corev1.NodeCondition {
	// Read before taking mu: the host call is IPC to the power daemon.
	src := r.host.PowerSource()
	r.mu.Lock()
	defer r.mu.Unlock()
	c := corev1.NodeCondition{
		Type:               nodeSleeping,
		Status:             corev1.ConditionFalse,
		Reason:             sleepAwakeReason,
		LastHeartbeatTime:  now,
		LastTransitionTime: metav1.NewTime(r.startedAt),
	}
	switch {
	case r.asleep && r.darkServing:
		c.Reason = sleepDarkReason
		c.LastTransitionTime = metav1.NewTime(r.darkServingAt)
		c.Message = fmt.Sprintf("the Mac has been in a maintenance (dark) wake since %s and the node is serving; the display and user session stay asleep", r.darkAt.UTC().Format(time.RFC3339))
	case r.asleep:
		c.Status = corev1.ConditionTrue
		c.Reason = sleepWillReason
		c.LastTransitionTime = metav1.NewTime(r.sleptAt)
		c.Message = fmt.Sprintf("the Mac began system sleep at %s; the node posts no status while it sleeps, and may post status during a short dark wake (Power Nap, maintenance) without this condition changing", r.sleptAt.UTC().Format(time.RFC3339))
		return c
	case r.everWoken:
		c.Reason = sleepWokeReason
		c.LastTransitionTime = metav1.NewTime(r.wokeAt)
		c.Message = fmt.Sprintf("the Mac woke from system sleep at %s", r.wokeAt.UTC().Format(time.RFC3339))
		if r.sleptFor > 0 {
			c.Message += fmt.Sprintf(" after %s", r.sleptFor.Round(time.Second))
		}
	default:
		c.Message = "the Mac is awake"
	}
	if r.held {
		c.Message += "; the node holds a PreventSystemSleep assertion, " + assertionEffect(src)
	} else if r.holdErr != nil {
		c.Message += fmt.Sprintf("; no sleep assertion is held: %v", r.holdErr)
	}
	return c
}

// assertionEffect says what the held assertion does on the given source:
// macOS honours PreventSystemSleep on external power only.
func assertionEffect(src PowerSource) string {
	switch src {
	case PowerSourceAC, PowerSourceUPS:
		return "and the Mac is on external power, so it does not idle-sleep"
	case PowerSourceBattery:
		return "which macOS ignores on battery power: the Mac is on battery and can idle-sleep"
	}
	return "which macOS honours only on external power; the power source could not be read"
}
