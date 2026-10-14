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
	"io/fs"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// TestStatusNetworkBlock pins the additive network block: an installed Mac
// whose LAN record reads reports lan, the families the switch covers and the
// listeners it never touches, in the JSON and as one line of the human view;
// with no seam, a failed read, or no install the key is absent, so a report
// without it encodes exactly as before.
func TestStatusNetworkBlock(t *testing.T) {
	t.Parallel()
	running := func(t *testing.T) Collector {
		return contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", heartbeatingKube(goldenTime), nil)
	}
	off := func() (install.NetworkRecord, bool, error) {
		return install.NetworkRecord{Version: install.NetworkRecordVersion, LAN: install.LANOff}, true, nil
	}

	t.Run("an installed server reports lan, covers and alwaysOn", func(t *testing.T) {
		t.Parallel()
		c := running(t)
		c.Network = off
		r := c.Collect(context.Background())
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var generic map[string]any
		if err := json.Unmarshal(raw, &generic); err != nil {
			t.Fatal(err)
		}
		nw, ok := generic["network"].(map[string]any)
		if !ok {
			t.Fatalf("report JSON has no network object: %s", raw)
		}
		if nw["lan"] != "off" {
			t.Errorf("network.lan = %v, want off", nw["lan"])
		}
		if nw["recorded"] != true {
			t.Errorf("network.recorded = %v, want true", nw["recorded"])
		}
		want := map[string][]any{
			"covers":   {"nodeports", "loadbalancers", "ingress"},
			"alwaysOn": {"apiserver", "join", "mesh"},
		}
		for k, v := range want {
			if !reflect.DeepEqual(nw[k], v) {
				t.Errorf("network.%s = %v, want %v", k, nw[k], v)
			}
		}
		screen := Render(r, Style{})
		if !strings.Contains(screen, "LAN access off (nodeports, loadbalancers, ingress); always on: apiserver, join, mesh") {
			t.Errorf("the human view does not carry the LAN line:\n%s", screen)
		}
	})

	t.Run("recorded and applied are both shown, and their difference", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name    string
			network func() (install.NetworkRecord, bool, error)
			applied func(install.Role) ([]byte, error)
			json    string
			line    string
		}{
			{"applied agrees", off, func(install.Role) ([]byte, error) { return []byte(`{"lan":"off","serial":"s1"}`), nil },
				`"applied":{"lan":"off","serial":"s1"}`, ""},
			{"applied differs", off, func(install.Role) ([]byte, error) { return []byte(`{"lan":"on","serial":"s0"}`), nil },
				`"applied":{"lan":"on","serial":"s0"}`, "the node daemon still serves LAN access on, not the recorded off"},
			{"applied refused", off, func(install.Role) ([]byte, error) {
				return []byte(`{"lan":"on","serial":"s1","error":"ingress: bind refused"}`), nil
			}, `"error":"ingress: bind refused"`, "its last change was refused: ingress: bind refused"},
			{"applied unknown to a user", off, func(install.Role) ([]byte, error) { return nil, fs.ErrPermission },
				`"recorded":true`, "readable by root only"},
			{"no record reads on, visibly", func() (install.NetworkRecord, bool, error) {
				return install.NetworkRecord{Version: install.NetworkRecordVersion, LAN: install.LANOn}, false, nil
			}, nil, `"lan":"on","recorded":false`, "LAN access is on because no setting is recorded"},
		}
		for _, tc := range cases {
			c := running(t)
			c.Network, c.NetworkApplied = tc.network, tc.applied
			r := c.Collect(context.Background())
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), tc.json) {
				t.Errorf("%s: JSON lacks %s: %s", tc.name, tc.json, raw)
			}
			screen := Render(r, Style{})
			if tc.line != "" && !strings.Contains(screen, tc.line) {
				t.Errorf("%s: the human view lacks %q:\n%s", tc.name, tc.line, screen)
			}
			if tc.line == "" && (strings.Contains(screen, "still serves") || strings.Contains(screen, "refused")) {
				t.Errorf("%s: the human view reports a difference that is not there:\n%s", tc.name, screen)
			}
		}
	})

	t.Run("absent seam and no install leave the key out", func(t *testing.T) {
		t.Parallel()
		c := running(t)
		raw, err := json.Marshal(c.Collect(context.Background()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"network"`) {
			t.Errorf("no seam: the report carries a network key: %s", raw)
		}
		if got := (Collector{Network: off}).network("", false); got != nil {
			t.Errorf("a Mac with no install reported %+v, want no network block", got)
		}
	})
}

// TestNetworkLANInDaemonsProbeAndUnreadableMarker pins the two markers that
// tell the LAN states apart and the probe's copy of the block. A record that
// exists but cannot be used reports lan off (what the node daemon serves),
// recorded true and recordState unreadable, in both shapes and without the
// error text; an absent record carries no recordState; an applied report the
// caller may not read gives appliedReadable false; and the daemons probe
// carries network, from the full report's own method, without applied and
// without ever calling the applied reader.
func TestNetworkLANInDaemonsProbeAndUnreadableMarker(t *testing.T) {
	t.Parallel()
	running := func(t *testing.T) Collector {
		return contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", heartbeatingKube(goldenTime), nil)
	}
	const secret = "/Library/k3sm/network.json: owned by uid 501"
	unreadable := func() (install.NetworkRecord, bool, error) {
		return install.NetworkRecord{}, true, errors.New("network record " + secret + ": " + install.ErrNetworkRecord.Error())
	}
	absent := func() (install.NetworkRecord, bool, error) {
		return install.NetworkRecord{Version: install.NetworkRecordVersion, LAN: install.LANOn}, false, nil
	}
	recordedOn := func() (install.NetworkRecord, bool, error) {
		return install.NetworkRecord{Version: install.NetworkRecordVersion, LAN: install.LANOn}, true, nil
	}
	appliedOff := func(install.Role) ([]byte, error) { return []byte(`{"lan":"off","serial":"s1"}`), nil }
	appliedDenied := func(install.Role) ([]byte, error) { return nil, fs.ErrPermission }
	no := false

	cases := []struct {
		name    string
		record  func() (install.NetworkRecord, bool, error)
		applied func(install.Role) ([]byte, error)
		full    *Network
		line    string
	}{
		{
			name: "an unreadable record reads off, recorded, marked", record: unreadable, applied: appliedOff,
			full: &Network{LAN: "off", Recorded: true, RecordState: NetworkRecordUnreadable,
				Covers: install.LANCovers("server"), AlwaysOn: install.LANAlwaysOn("server"),
				Applied: &NetworkApplied{LAN: "off", Serial: "s1"}},
			line: "the LAN access record cannot be used, so the node daemon serves LAN access off",
		},
		{
			name: "an absent record carries no recordState", record: absent,
			full: &Network{LAN: "on", Recorded: false,
				Covers: install.LANCovers("server"), AlwaysOn: install.LANAlwaysOn("server")},
			line: "LAN access is on because no setting is recorded",
		},
		{
			name: "applied unreadable says so", record: recordedOn, applied: appliedDenied,
			full: &Network{LAN: "on", Recorded: true,
				Covers: install.LANCovers("server"), AlwaysOn: install.LANAlwaysOn("server"), AppliedReadable: &no},
			line: "the applied state is readable by root only",
		},
		{
			name: "a readable applied report leaves appliedReadable out", record: recordedOn, applied: appliedOff,
			full: &Network{LAN: "on", Recorded: true,
				Covers: install.LANCovers("server"), AlwaysOn: install.LANAlwaysOn("server"),
				Applied: &NetworkApplied{LAN: "off", Serial: "s1"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var appliedCalls atomic.Int32
			c := running(t)
			c.Network = tc.record
			if tc.applied != nil {
				c.NetworkApplied = func(r install.Role) ([]byte, error) { appliedCalls.Add(1); return tc.applied(r) }
			}

			full := c.Collect(context.Background())
			if !reflect.DeepEqual(full.Network, tc.full) {
				t.Errorf("full report network = %+v, want %+v", networkOf(full.Network), networkOf(tc.full))
			}
			if tc.line != "" {
				if screen := Render(full, Style{}); !strings.Contains(screen, tc.line) {
					t.Errorf("the human view lacks %q:\n%s", tc.line, screen)
				}
			}

			before := appliedCalls.Load()
			probe := c.CollectDaemons()
			if n := appliedCalls.Load() - before; n != 0 {
				t.Errorf("the daemons probe read the applied report %d times, want 0", n)
			}
			want := *tc.full
			want.Applied, want.AppliedReadable = nil, nil
			if probe.Network == nil || !reflect.DeepEqual(*probe.Network, want) {
				t.Errorf("daemons probe network = %+v, want %+v", networkOf(probe.Network), want)
			}

			for shape, v := range map[string]any{"full": full, "probe": probe} {
				raw, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				var generic map[string]any
				if err := json.Unmarshal(raw, &generic); err != nil {
					t.Fatal(err)
				}
				nw, ok := generic["network"].(map[string]any)
				if !ok {
					t.Fatalf("%s JSON has no network object: %s", shape, raw)
				}
				rs, hasRS := nw["recordState"]
				if tc.full.RecordState == "" && hasRS {
					t.Errorf("%s: recordState = %v, want it absent", shape, rs)
				}
				if tc.full.RecordState != "" && rs != "unreadable" {
					t.Errorf("%s: recordState = %v, want unreadable", shape, rs)
				}
				ar, hasAR := nw["appliedReadable"]
				if shape == "full" && tc.full.AppliedReadable != nil && ar != false {
					t.Errorf("full: appliedReadable = %v, want false", ar)
				}
				if (shape == "probe" || tc.full.AppliedReadable == nil) && hasAR {
					t.Errorf("%s: appliedReadable = %v, want it absent", shape, ar)
				}
				if _, has := nw["applied"]; shape == "probe" && has {
					t.Errorf("probe: carries applied, which is root-only: %s", raw)
				}
				if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "uid 501") {
					t.Errorf("%s: the JSON carries the record's error text: %s", shape, raw)
				}
			}
		})
	}

	t.Run("no install and no seam leave the probe's key out", func(t *testing.T) {
		t.Parallel()
		c := running(t)
		if got := c.CollectDaemons().Network; got != nil {
			t.Errorf("no seam: probe network = %+v, want nil", *got)
		}
		c.Network = unreadable
		c.FS = fakeFS{}
		if got := c.CollectDaemons().Network; got != nil {
			t.Errorf("no install: probe network = %+v, want nil", *got)
		}
	})
}

// networkOf prints a network block, or nil, for a test failure.
func networkOf(n *Network) any {
	if n == nil {
		return nil
	}
	return *n
}
