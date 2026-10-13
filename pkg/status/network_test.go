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
