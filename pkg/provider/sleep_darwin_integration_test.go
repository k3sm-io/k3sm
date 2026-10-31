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
