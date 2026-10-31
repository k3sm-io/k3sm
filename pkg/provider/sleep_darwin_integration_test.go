//go:build integration && darwin && cgo

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
	"os/exec"
	"strings"
	"testing"
	"time"
)

// pmsetHolds reports whether `pmset -g assertions` lists a PreventSystemSleep
// assertion with the given name.
func pmsetHolds(t *testing.T, name string) bool {
	t.Helper()
	out, err := exec.Command("/usr/bin/pmset", "-g", "assertions").CombinedOutput()
	if err != nil {
		t.Fatalf("pmset -g assertions: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "PreventSystemSleep") && strings.Contains(line, name) {
			return true
		}
	}
	return false
}

// TestIOKitSleepAssertionHeldAndReleased takes the real IOKit assertion and
// checks the system lists it while held and drops it on release, and that the
// IOKit sleep watcher registers and stops cleanly. It needs no privilege; it is
// integration-tier because it changes this Mac's power state while it runs.
func TestIOKitSleepAssertionHeldAndReleased(t *testing.T) {
	host := newPowerHost()
	name := "k3sm B1044 test assertion"
	release, err := host.PreventSleep(name)
	if err != nil {
		t.Fatalf("PreventSleep: %v", err)
	}
	if !pmsetHolds(t, name) {
		_ = release()
		t.Fatal("pmset does not list the held assertion")
	}
	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if pmsetHolds(t, name) {
		t.Fatal("pmset still lists the released assertion")
	}

	ctx, cancel := context.WithCancel(context.Background())
	notices, err := host.WatchSleep(ctx)
	if err != nil {
		cancel()
		t.Fatalf("WatchSleep: %v", err)
	}
	cancel()
	select {
	case _, ok := <-notices:
		for ok {
			_, ok = <-notices
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sleep watcher did not stop")
	}
}

// TestIOKitSleepWatcherStopsAtOnce starts the IOKit sleep watcher and stops it
// immediately, 200 times, each stop bounded: a stop that lands before the
// watcher's run loop is running must not be lost, or the node's shutdown
// hangs on the watcher thread.
func TestIOKitSleepWatcherStopsAtOnce(t *testing.T) {
	host := newPowerHost()
	for i := 0; i < 200; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		notices, err := host.WatchSleep(ctx)
		if err != nil {
			cancel()
			t.Fatalf("round %d: WatchSleep: %v", i, err)
		}
		cancel()
		deadline := time.After(5 * time.Second)
	drain:
		for {
			select {
			case _, ok := <-notices:
				if !ok {
					break drain
				}
			case <-deadline:
				t.Fatalf("round %d: the sleep watcher did not stop within 5s", i)
			}
		}
	}
}

// TestIOKitPowerSourceIsRead checks the host reads a power source: every Mac
// draws from AC, battery or a UPS.
func TestIOKitPowerSourceIsRead(t *testing.T) {
	if src := newPowerHost().PowerSource(); src == PowerSourceUnknown {
		t.Fatal("IOPSGetProvidingPowerSourceType returned no source")
	}
}

// TestIOKitSystemCapabilitiesCanary pins the private registry key the dark-wake
// check reads: the root domain's "System Capabilities" must be a CFNumber with
// the CPU bit set on this macOS build. If it goes red, the watcher counts every
// dark wake as a full wake (and warns once at start).
func TestIOKitSystemCapabilitiesCanary(t *testing.T) {
	caps, isNumber := readSystemCapabilities()
	if !isNumber {
		t.Fatal(`IOPMrootDomain "System Capabilities" is absent or not a CFNumber`)
	}
	if caps == ^uint32(0) || caps&0x01 == 0 {
		t.Fatalf(`IOPMrootDomain "System Capabilities" = %#x, want the CPU bit (0x1) set`, caps)
	}
}
