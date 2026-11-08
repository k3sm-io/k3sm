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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/install"
)

// lanFakeClock is a settable clock.
type lanFakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *lanFakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *lanFakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// setsFamily records every set it is prepared with, and refuses the next
// failNext prepares.
type setsFamily struct {
	mu       sync.Mutex
	prepared []lanSets
	failNext int
}

func (*setsFamily) name() string { return install.LANFamilyNodePorts }

func (f *setsFamily) prepare(_ context.Context, sets lanSets) (lanStep, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext > 0 {
		f.failNext--
		return lanStep{}, errors.New("bind 127.0.0.1: address already in use")
	}
	f.prepared = append(f.prepared, sets)
	return lanStep{commit: func() error { return nil }, abort: func() {}}, nil
}

func (f *setsFamily) sets() []lanSets {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.prepared)
}

// lanT0 is the fake clock's start.
var lanT0 = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

// expiryRig is a daemon-side switch on a fake clock over a fake filesystem,
// with one recording family attached.
type expiryRig struct {
	sys     *lanFakeSys
	clock   *lanFakeClock
	sw      *lanSwitch
	fam     *setsFamily
	record  string
	reports chan install.NetworkApplied
}

// newExpiryRig writes rec (when non-nil) and starts a switch on it at now.
func newExpiryRig(t *testing.T, rec *install.NetworkRecord, now time.Time) *expiryRig {
	t.Helper()
	r := &expiryRig{
		sys:     newLANFakeSys(),
		clock:   &lanFakeClock{t: now},
		fam:     &setsFamily{},
		record:  "/Library/Preferences/io.k3sm.network.json",
		reports: make(chan install.NetworkApplied, 16),
	}
	if rec != nil {
		r.write(t, *rec)
	}
	applied := install.NetworkAppliedPath("/var/lib/k3sm", install.RoleServer)
	r.sw = &lanSwitch{
		recordPath:  r.record,
		appliedPath: applied,
		readRecord:  install.SystemNetworkRecordReader(r.sys),
		writeFile: func(p string, b []byte) error {
			r.sys.put(p, b)
			if a, err := install.DecodeNetworkApplied(b); err == nil {
				r.reports <- a
			}
			return nil
		},
		hostAddrs: lanRigHost,
		now:       r.clock.now,
		log:       slog.New(slog.DiscardHandler),
		node:      lanNode,
	}
	r.sw.load()
	if err := r.sw.attach("", "", func(lanSets) (lanFamily, error) { return r.fam, nil }); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *expiryRig) write(t *testing.T, rec install.NetworkRecord) {
	t.Helper()
	data, err := install.EncodeNetworkRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	r.sys.put(r.record, data)
}

func (r *expiryRig) applied(t *testing.T) install.NetworkApplied {
	t.Helper()
	data, err := r.sys.ReadFile(r.sw.appliedPath)
	if err != nil {
		t.Fatalf("read the applied report: %v", err)
	}
	a, err := install.DecodeNetworkApplied(data)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// onUntil is a record of LAN access on that lapses at exp.
func onUntil(exp time.Time) install.NetworkRecord {
	rec := install.NewNetworkRecord(install.LANOn, "test")
	rec.ExpiresAt = &exp
	return rec
}

// TestLanOnForRevertsAtExpiry is the gate for `k3sm network lan on --for`:
// the node daemon turns LAN access off by itself on the first tick past the
// expiry (moving the families to the local set), a start past the expiry
// reads off, a later permanent on is not reverted, a failed revert retries on
// the next tick, a clock stepped back after a revert does not reopen it,
// Effective judges nil, future and past expiries, and the
// record schema is version 2 with an expiry and version 1 without.
func TestLanOnForRevertsAtExpiry(t *testing.T) {
	exp := lanT0.Add(10 * time.Minute)

	t.Run("the expiry passes on a tick and the families get the local set", func(t *testing.T) {
		r := newExpiryRig(t, ptr(onUntil(exp)), lanT0)
		if got := r.sw.state(); got != install.LANOn {
			t.Fatalf("state at start = %s, want on (the expiry is ahead)", got)
		}
		before, _ := r.sys.ReadFile(r.record)

		r.clock.set(exp.Add(-time.Second))
		if did, err := r.sw.expireTick(context.Background()); did || err != nil {
			t.Fatalf("tick before the expiry = (%v, %v), want nothing done", did, err)
		}
		if len(r.fam.sets()) != 0 {
			t.Fatalf("family moved before the expiry: %+v", r.fam.sets())
		}

		r.clock.set(exp)
		if did, err := r.sw.expireTick(context.Background()); !did || err != nil {
			t.Fatalf("tick at the expiry = (%v, %v), want a revert", did, err)
		}
		sets := r.fam.sets()
		if len(sets) != 1 || sets[0].lan != install.LANOff || !slices.Equal(sets[0].nodePorts, lanLocal) || !slices.Equal(sets[0].listeners, lanLocal) {
			t.Fatalf("family prepared with %+v, want one move to the local set %v", sets, lanLocal)
		}
		if got := r.sw.state(); got != install.LANOff {
			t.Errorf("state = %s, want off", got)
		}
		if a := r.applied(t); a.LAN != install.LANOff || a.Error != "" || !a.At.Equal(exp) {
			t.Errorf("applied report = %+v, want off with no error at the fake clock", a)
		}
		after, _ := r.sys.ReadFile(r.record)
		if !bytes.Equal(before, after) {
			t.Errorf("the daemon rewrote the record:\n%s\nwant it untouched:\n%s", after, before)
		}

		if did, err := r.sw.expireTick(context.Background()); did || err != nil {
			t.Errorf("tick after the revert = (%v, %v), want nothing done", did, err)
		}
	})

	t.Run("watch reverts on a tick from its tick seam", func(t *testing.T) {
		r := newExpiryRig(t, ptr(onUntil(exp)), lanT0)
		ticks := make(chan time.Time)
		stopped := make(chan struct{})
		r.sw.tick = func() (<-chan time.Time, func()) { return ticks, func() { close(stopped) } }
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); r.sw.watch(ctx, nil) }()

		r.clock.set(exp.Add(time.Hour)) // the Mac slept through the expiry
		ticks <- exp.Add(time.Hour)
		select {
		case a := <-r.reports:
			if a.LAN != install.LANOff || a.Error != "" {
				t.Errorf("report = %+v, want off", a)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no report after a tick past the expiry")
		}
		cancel()
		<-done
		select {
		case <-stopped:
		default:
			t.Error("watch did not stop its ticker")
		}
		if got := r.sw.state(); got != install.LANOff {
			t.Errorf("state = %s, want off", got)
		}
	})

	t.Run("a start past the expiry reads off", func(t *testing.T) {
		r := newExpiryRig(t, ptr(onUntil(exp)), exp.Add(time.Minute))
		if got := r.sw.state(); got != install.LANOff {
			t.Fatalf("state at start = %s, want off", got)
		}
		sets := r.fam.sets()
		if len(sets) != 0 {
			t.Fatalf("attach prepared %+v, want nothing (attach builds, it does not prepare)", sets)
		}
		if did, err := r.sw.expireTick(context.Background()); did || err != nil {
			t.Errorf("tick = (%v, %v), want nothing to do", did, err)
		}
	})

	t.Run("a later on without --for stays on past the old expiry", func(t *testing.T) {
		r := newExpiryRig(t, ptr(onUntil(exp)), lanT0)
		r.write(t, install.NewNetworkRecord(install.LANOn, "test"))
		if err := r.sw.apply(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.clock.set(exp.Add(time.Hour))
		if did, err := r.sw.expireTick(context.Background()); did || err != nil {
			t.Fatalf("tick past the old expiry = (%v, %v), want nothing done", did, err)
		}
		if got := r.sw.state(); got != install.LANOn {
			t.Errorf("state = %s, want on", got)
		}
		for _, s := range r.fam.sets() {
			if s.lan != install.LANOn {
				t.Errorf("family moved to %s, want only on", s.lan)
			}
		}
	})

	t.Run("a clock stepped back after the revert does not reopen the window", func(t *testing.T) {
		r := newExpiryRig(t, ptr(onUntil(exp)), lanT0)
		r.clock.set(exp)
		if did, err := r.sw.expireTick(context.Background()); !did || err != nil {
			t.Fatalf("tick at the expiry = (%v, %v), want a revert", did, err)
		}
		r.clock.set(exp.Add(-5 * time.Minute)) // an NTP correction steps the wall clock back
		if did, err := r.sw.expireTick(context.Background()); did || err != nil {
			t.Fatalf("tick after the step back = (%v, %v), want nothing done", did, err)
		}
		if got := r.sw.state(); got != install.LANOff {
			t.Errorf("state = %s, want off (the lapse is latched)", got)
		}
		r.write(t, onUntil(exp.Add(time.Hour))) // a fresh --for is a new serial and opens again
		if err := r.sw.apply(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := r.sw.state(); got != install.LANOn {
			t.Errorf("state after a new timed on = %s, want on", got)
		}
	})

	t.Run("a failed revert retries and succeeds on the next tick", func(t *testing.T) {
		r := newExpiryRig(t, ptr(onUntil(exp)), lanT0)
		r.fam.failNext = 1
		r.clock.set(exp.Add(time.Minute))
		did, err := r.sw.expireTick(context.Background())
		if !did || err == nil {
			t.Fatalf("first tick = (%v, %v), want a failed revert", did, err)
		}
		if got := r.sw.state(); got != install.LANOn {
			t.Errorf("state after the failed revert = %s, want on (the previous state stays in force)", got)
		}
		if a := r.applied(t); a.LAN != install.LANOn || !strings.Contains(a.Error, "address already in use") {
			t.Errorf("applied report = %+v, want on with the failure", a)
		}
		r.clock.set(exp.Add(time.Minute + lanExpiryTick))
		if did, err := r.sw.expireTick(context.Background()); !did || err != nil {
			t.Fatalf("next tick = (%v, %v), want a revert", did, err)
		}
		if got := r.sw.state(); got != install.LANOff {
			t.Errorf("state = %s, want off", got)
		}
		if a := r.applied(t); a.LAN != install.LANOff || a.Error != "" {
			t.Errorf("applied report = %+v, want off with no error", a)
		}
	})

	t.Run("Effective judges nil, future and past expiries", func(t *testing.T) {
		future, past := lanT0.Add(time.Minute), lanT0.Add(-time.Minute)
		cases := []struct {
			name string
			lan  install.LAN
			exp  *time.Time
			want install.LAN
		}{
			{"on with no expiry", install.LANOn, nil, install.LANOn},
			{"on until the future", install.LANOn, &future, install.LANOn},
			{"on until the past", install.LANOn, &past, install.LANOff},
			{"on until exactly now", install.LANOn, &lanT0, install.LANOff},
			{"off with no expiry", install.LANOff, nil, install.LANOff},
		}
		for _, tc := range cases {
			rec := install.NetworkRecord{LAN: tc.lan, ExpiresAt: tc.exp}
			if got := rec.Effective(lanT0); got != tc.want {
				t.Errorf("%s: Effective = %s, want %s", tc.name, got, tc.want)
			}
		}
	})

	t.Run("v2 round-trips, v1 still decodes, an unknown version is refused", func(t *testing.T) {
		local := exp.In(time.FixedZone("UTC-8", -8*3600))
		data, err := install.EncodeNetworkRecord(onUntil(local))
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		if raw["version"] != float64(install.NetworkRecordVersionExpiry) || raw["expiresAt"] != exp.Format(time.RFC3339) {
			t.Errorf("encoded %s, want version 2 and the expiry in UTC", data)
		}
		got, err := install.DecodeNetworkRecord(data)
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != 2 || got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) || got.LAN != install.LANOn {
			t.Errorf("decoded %+v, want on version 2 until %s", got, exp)
		}

		perm, err := install.EncodeNetworkRecord(install.NewNetworkRecord(install.LANOn, "test"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(perm, []byte(`"version": 1`)) || bytes.Contains(perm, []byte("expiresAt")) {
			t.Errorf("a permanent record encoded as %s, want version 1 with no expiry", perm)
		}

		cases := []struct {
			name string
			data string
			ok   bool
		}{
			{"v1", `{"version":1,"lan":"on","serial":"x"}`, true},
			{"v2", `{"version":2,"lan":"on","serial":"x","expiresAt":"2026-11-08T12:10:00Z"}`, true},
			{"unknown version", `{"version":3,"lan":"on","serial":"x"}`, false},
			{"v1 with an expiry", `{"version":1,"lan":"on","serial":"x","expiresAt":"2026-11-08T12:10:00Z"}`, false},
			{"v2 without an expiry", `{"version":2,"lan":"on","serial":"x"}`, false},
			{"v2 off with an expiry", `{"version":2,"lan":"off","serial":"x","expiresAt":"2026-11-08T12:10:00Z"}`, false},
		}
		for _, tc := range cases {
			_, err := install.DecodeNetworkRecord([]byte(tc.data))
			if tc.ok && err != nil {
				t.Errorf("%s: %v, want it decoded", tc.name, err)
			}
			if !tc.ok && !errors.Is(err, install.ErrNetworkRecord) {
				t.Errorf("%s: %v, want ErrNetworkRecord", tc.name, err)
			}
		}
		if _, err := install.EncodeNetworkRecord(install.NetworkRecord{LAN: install.LANOff, ExpiresAt: &exp}); !errors.Is(err, install.ErrNetworkRecord) {
			t.Errorf("encoding off with an expiry = %v, want ErrNetworkRecord", err)
		}
	})
}

func ptr[T any](v T) *T { return &v }

// TestLanOnForCLI pins `k3sm network lan on --for`: the duration is checked
// before anything is written, the record carries now+d as version 2, the
// verb says until when, status shows the expiry while it is in force and
// says it lapsed after, and a failed change restores the previous expiry.
func TestLanOnForCLI(t *testing.T) {
	t.Run("--for is validated before anything is written", func(t *testing.T) {
		cases := []struct {
			name string
			args []string
			want string
		}{
			{"zero", []string{"lan", "on", "--for", "0s"}, "longer than zero"},
			{"negative", []string{"lan", "on", "--for=-5m"}, "longer than zero"},
			{"over a day", []string{"lan", "on", "--for", "25h"}, "24h limit"},
			{"not a duration", []string{"lan", "on", "--for", "soon"}, "not a duration"},
			{"no value", []string{"lan", "on", "--for"}, "unexpected arguments"},
			{"with off", []string{"lan", "off", "--for", "10m"}, "only to 'lan on'"},
			{"with status", []string{"lan", "status", "--for", "10m"}, "only to 'lan on'"},
			{"a stray argument", []string{"lan", "on", "now"}, "unexpected arguments"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rig := newLANRig(t, install.RoleServer)
				if code := rig.run(tc.args...); code != exitLifecycleUsage {
					t.Fatalf("exit %d, want %d (usage); stderr %s", code, exitLifecycleUsage, rig.errOut)
				}
				if !strings.Contains(rig.errOut.String(), tc.want) {
					t.Errorf("stderr %q, want it to say %q", rig.errOut, tc.want)
				}
				if _, present := rig.sys.recordedLAN(t, rig.record); present {
					t.Error("a record was written for a refused --for")
				}
			})
		}
	})

	for _, tc := range []struct {
		name string
		args []string
		d    time.Duration
		left string
	}{
		{"--for 30m", []string{"lan", "on", "--for", "30m"}, 30 * time.Minute, "(in 30m)"},
		{"--for=24h", []string{"lan", "on", "--for=24h"}, 24 * time.Hour, "(in 24h)"},
	} {
		t.Run(tc.name+" records now+d as version 2", func(t *testing.T) {
			rig := newLANRig(t, install.RoleServer)
			clock := &lanFakeClock{t: lanT0}
			rig.env.Now, rig.sw.now = clock.now, clock.now
			if code := rig.run(tc.args...); code != 0 {
				t.Fatalf("exit %d: %s", code, rig.errOut)
			}
			data, _ := rig.sys.ReadFile(rig.record)
			rec, err := install.DecodeNetworkRecord(data)
			if err != nil {
				t.Fatal(err)
			}
			if rec.Version != install.NetworkRecordVersionExpiry || rec.LAN != install.LANOn || rec.ExpiresAt == nil || !rec.ExpiresAt.Equal(lanT0.Add(tc.d)) {
				t.Errorf("record %s, want on version 2 until %s", data, lanT0.Add(tc.d))
			}
			wantUntil := "until " + lanT0.Add(tc.d).Local().Format(time.RFC3339) + " " + tc.left
			if !strings.Contains(rig.out.String(), wantUntil) {
				t.Errorf("lan on said %q, want it to name %q", rig.out, wantUntil)
			}
		})
	}

	t.Run("status shows the expiry, then that it lapsed", func(t *testing.T) {
		rig := newLANRig(t, install.RoleServer)
		clock := &lanFakeClock{t: lanT0}
		rig.env.Now, rig.sw.now = clock.now, clock.now
		if code := rig.run("lan", "on", "--for", "12m"); code != 0 {
			t.Fatalf("exit %d: %s", code, rig.errOut)
		}
		rig.env.Geteuid = func() int { return 501 }
		exp := lanT0.Add(12 * time.Minute).Local().Format(time.RFC3339)

		if code := rig.run("lan", "status"); code != 0 {
			t.Fatalf("status exit %d: %s", code, rig.errOut)
		}
		out := rig.out.String()
		if !strings.Contains(out, "Recorded: LAN access is on") || !strings.Contains(out, "on until "+exp+" (in 12m)") {
			t.Errorf("status while in force:\n%s\nwant on until %s (in 12m)", out, exp)
		}

		clock.set(lanT0.Add(13 * time.Minute))
		if code := rig.run("lan", "status"); code != 0 {
			t.Fatalf("status exit %d: %s", code, rig.errOut)
		}
		out = rig.out.String()
		if !strings.Contains(out, "Recorded: LAN access is off") || !strings.Contains(out, "LAN access expired at "+exp) {
			t.Errorf("status after the expiry:\n%s\nwant off and expired at %s", out, exp)
		}
		if strings.Contains(out, "on until") {
			t.Errorf("status after the expiry still names an until:\n%s", out)
		}
	})

	t.Run("a failed change restores the previous expiry", func(t *testing.T) {
		rig := newLANRig(t, install.RoleServer)
		clock := &lanFakeClock{t: lanT0}
		rig.env.Now, rig.sw.now = clock.now, clock.now
		fam := &fakeFamily{fam: "nodeports", failOn: install.LANOff}
		if err := rig.sw.attach("", "", func(lanSets) (lanFamily, error) { return fam, nil }); err != nil {
			t.Fatal(err)
		}
		if code := rig.run("lan", "on", "--for", "1h"); code != 0 {
			t.Fatalf("on --for exit %d: %s", code, rig.errOut)
		}
		if code := rig.run("lan", "off"); code != exitLifecycleFailed {
			t.Fatalf("off exit %d, want %d (refused and restored): %s", code, exitLifecycleFailed, rig.errOut)
		}
		data, _ := rig.sys.ReadFile(rig.record)
		rec, err := install.DecodeNetworkRecord(data)
		if err != nil {
			t.Fatal(err)
		}
		if rec.LAN != install.LANOn || rec.ExpiresAt == nil || !rec.ExpiresAt.Equal(lanT0.Add(time.Hour)) {
			t.Errorf("restored record %s, want on until %s", data, lanT0.Add(time.Hour))
		}
		if !strings.Contains(rig.errOut.String(), "stays on until") {
			t.Errorf("stderr %q, want it to say LAN access stays on until the old expiry", rig.errOut)
		}
		if rig.sw.state() != install.LANOn {
			t.Errorf("daemon state = %s, want on", rig.sw.state())
		}
	})
}
