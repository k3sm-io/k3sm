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

	t.Run("absent seam, failed read and no install leave the key out", func(t *testing.T) {
		t.Parallel()
		for name, mutate := range map[string]func(*Collector){
			"no seam": func(*Collector) {},
			"failed read": func(c *Collector) {
				c.Network = func() (install.NetworkRecord, bool, error) {
					return install.NetworkRecord{}, true, errors.New("bad record")
				}
			},
		} {
			c := running(t)
			mutate(&c)
			raw, err := json.Marshal(c.Collect(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), `"network"`) {
				t.Errorf("%s: the report carries a network key: %s", name, raw)
			}
		}
		if got := (Collector{Network: off}).network("", false); got != nil {
			t.Errorf("a Mac with no install reported %+v, want no network block", got)
		}
	})
}
