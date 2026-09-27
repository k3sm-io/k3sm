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

package install

import (
	"context"
	"slices"
	"strings"
	"testing"

	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// TestUninstallTearsDownRecordedPodGroups pins that `k3sm uninstall` stops the
// pods it would otherwise leave running. A native pod outlives its node daemon
// by design (a restart re-attaches to it), so booting the daemon out stops
// nothing; the uninstall reads the runtime's reap records AFTER every daemon is
// booted out and stops each recorded group — SIGTERM, one shared 10s grace,
// SIGKILL to the survivors — and signals ONLY a group whose leader is alive
// with exactly the recorded start time. A recycled pgid, a group whose leader
// is gone, and a record naming pgid 1 are never signalled.
func TestUninstallTearsDownRecordedPodGroups(t *testing.T) {
	t.Run("signals the verified groups in order, after the daemons", func(t *testing.T) {
		f := &fakeSystem{
			podReap: []runtimed.PodReapRecord{
				{PodID: "uid-a", Container: "c0", Pgid: 501, StartUnixNano: 111},
				{PodID: "uid-b", Container: "c0", Pgid: 502, StartUnixNano: 222},
				{PodID: "uid-c", Container: "c0", Pgid: 503, StartUnixNano: 333}, // pgid recycled
				{PodID: "uid-d", Container: "c0", Pgid: 504, StartUnixNano: 444}, // leader gone
				{PodID: "uid-e", Container: "c0", Pgid: 1, StartUnixNano: 555},   // never signalled
			},
			podLeaders:   map[int]int64{501: 111, 502: 222, 503: 999, 1: 555},
			podLingering: map[int]bool{502: true},
		}
		if err := Uninstall(context.Background(), f, Config{}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}

		read := slices.Index(f.calls, "ReadPodReapRecords:/var/lib/k3sm")
		if read < 0 {
			t.Fatalf("the reap store was never read: %v", f.calls)
		}
		for i, c := range f.calls {
			if strings.HasPrefix(c, "Bootout:") && i > read {
				t.Errorf("%s ran after the pod teardown began; a live daemon could restart the pods it stops", c)
			}
		}
		var got []string
		for _, c := range f.calls[read+1:] {
			if strings.HasPrefix(c, "Signal:") || strings.HasPrefix(c, "WaitGone:") {
				got = append(got, c)
			}
		}
		want := []string{
			"Signal:501:TERM",
			"Signal:502:TERM",
			"WaitGone:501,502:10s",
			"Signal:502:KILL",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("pod teardown = %v, want %v", got, want)
		}
	})

	t.Run("no records, no signals", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Uninstall(context.Background(), f, Config{}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "Signal:") || strings.HasPrefix(c, "WaitGone:") {
				t.Errorf("unexpected %s on a node with no recorded pods", c)
			}
		}
	})
}
