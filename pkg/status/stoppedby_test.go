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

package status

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/install"
)

func userStopMarker(at time.Time, phase install.StopPhase) install.StopMarker {
	return install.StopMarker{Version: 1, Phase: phase, Actor: install.ActorUser, Reason: "maintenance window", At: at}
}

func fakeStopMarker(m install.StopMarker) func() (install.StopMarker, bool, error) {
	return func() (install.StopMarker, bool, error) { return m, true, nil }
}

// TestStoppedByIsAdditive pins the stoppedBy field: absent without a marker or
// with an unreadable one, present with the marker's values in both shapes and
// both phases, and the stopped-by-user golden matching what is collected.
func TestStoppedByIsAdditive(t *testing.T) {
	t.Parallel()
	base := func(t *testing.T) Collector {
		return contractServer(t, "launchctl_failed_once.txt", "launchctl_stopped_clean.txt", downKube(), nil)
	}
	keys := func(t *testing.T, v any) map[string]any {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	t.Run("absent with no marker", func(t *testing.T) {
		t.Parallel()
		for name, c := range map[string]Collector{
			"nil seam": base(t),
			"no file": func() Collector {
				c := base(t)
				c.StopMarker = func() (install.StopMarker, bool, error) { return install.StopMarker{}, false, nil }
				return c
			}(),
			"unreadable": func() Collector {
				c := base(t)
				c.StopMarker = func() (install.StopMarker, bool, error) {
					return install.StopMarker{}, true, errors.New("parse the stop marker: invalid character")
				}
				return c
			}(),
		} {
			full, probe := c.Collect(context.Background()), c.CollectDaemons()
			if full.StoppedBy != nil || probe.StoppedBy != nil {
				t.Errorf("%s: stoppedBy = %+v / %+v, want absent", name, full.StoppedBy, probe.StoppedBy)
			}
			if _, ok := keys(t, full)["stoppedBy"]; ok {
				t.Errorf("%s: full JSON carries stoppedBy", name)
			}
			if _, ok := keys(t, probe)["stoppedBy"]; ok {
				t.Errorf("%s: daemons JSON carries stoppedBy", name)
			}
			if full.SchemaVersion != 1 || probe.SchemaVersion != 1 {
				t.Errorf("%s: schemaVersion moved", name)
			}
		}
	})

	t.Run("present with both phases and both actors", func(t *testing.T) {
		t.Parallel()
		at := goldenTime.Add(-time.Minute)
		for _, phase := range []install.StopPhase{install.StopPhaseStopping, install.StopPhaseStopped} {
			for _, actor := range []string{install.ActorUser, install.ActorAuto} {
				c := base(t)
				m := userStopMarker(at, phase)
				m.Actor = actor
				c.StopMarker = fakeStopMarker(m)
				want := StoppedBy{Actor: actor, Reason: "maintenance window", At: at, Phase: string(phase)}
				full, probe := c.Collect(context.Background()), c.CollectDaemons()
				if full.StoppedBy == nil || *full.StoppedBy != want {
					t.Errorf("full stoppedBy = %+v, want %+v", full.StoppedBy, want)
				}
				if probe.StoppedBy == nil || *probe.StoppedBy != want {
					t.Errorf("daemons stoppedBy = %+v, want %+v", probe.StoppedBy, want)
				}
				if full.Verdict != VerdictStopped {
					t.Errorf("verdict = %v, want it unchanged by the marker", full.Verdict)
				}
			}
		}
	})

	t.Run("the human view carries one line", func(t *testing.T) {
		t.Parallel()
		c := base(t)
		c.StopMarker = fakeStopMarker(userStopMarker(goldenTime.Add(-90*time.Second), install.StopPhaseStopped))
		out := Render(c.Collect(context.Background()), Style{})
		if !strings.Contains(out, "stopped by user: maintenance window, 1m30s ago\n") {
			t.Errorf("no stopped-by line in:\n%s", out)
		}
		if plain := Render(base(t).Collect(context.Background()), Style{}); strings.Contains(plain, "stopped by") {
			t.Errorf("a stopped-by line without a marker:\n%s", plain)
		}
	})

	t.Run("the stopped-by-user golden matches", func(t *testing.T) {
		t.Parallel()
		fullPath, daemonsPath := goldenPaths("stopped-by-user")
		var full Report
		decodeStrict(t, fullPath, &full)
		var probe DaemonsReport
		decodeStrict(t, daemonsPath, &probe)
		want := StoppedBy{Actor: "user", Reason: "maintenance window", At: goldenTime.Add(-90 * time.Second), Phase: "stopped"}
		if full.StoppedBy == nil || !full.StoppedBy.At.Equal(want.At) || full.StoppedBy.Actor != want.Actor || full.StoppedBy.Reason != want.Reason || full.StoppedBy.Phase != want.Phase {
			t.Errorf("full golden stoppedBy = %+v, want %+v", full.StoppedBy, want)
		}
		if probe.StoppedBy == nil || !probe.StoppedBy.At.Equal(want.At) || probe.StoppedBy.Phase != want.Phase {
			t.Errorf("daemons golden stoppedBy = %+v, want %+v", probe.StoppedBy, want)
		}
	})

	t.Run("every other golden stays free of the field", func(t *testing.T) {
		t.Parallel()
		entries, err := os.ReadDir("testdata")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".json") || strings.Contains(n, "stopped-by-user") {
				continue
			}
			raw, err := os.ReadFile("testdata/" + n)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "stoppedBy") {
				t.Errorf("%s carries stoppedBy", n)
			}
		}
	})
}
