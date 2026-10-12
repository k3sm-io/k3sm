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
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"k3sm.io/k3sm/pkg/netdsvc"
)

// bridgeIfconfig is `ifconfig bridge0` on a cabled node holding its slot-0 /24,
// one pod /32, the self-assigned link-local address, and an alias in the
// interconnect range that netd's ledger does not name.
const bridgeIfconfig = `bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=63<RXCSUM,TXCSUM,TSO4,TSO6>
	ether 36:a1:2b:00:00:01
	inet 169.254.9.209 netmask 0xffff0000 broadcast 169.254.255.255
	inet 169.254.0.9 netmask 0xffffff00 broadcast 169.254.0.255
	inet 169.254.0.10 netmask 0xffffffff
	inet 169.254.0.42 netmask 0xffffffff
	Configuration:
		id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
	member: en1 flags=3<LEARNING,DISCOVER>
	        ifmaxaddr 0 port 9 priority 0 path cost 0
	member: en2 flags=3<LEARNING,DISCOVER>
	        ifmaxaddr 0 port 10 priority 0 path cost 0
	status: active
`

func TestParseBridgeIfconfig(t *testing.T) {
	st := ParseBridgeIfconfig([]byte(bridgeIfconfig))
	if want := []string{"en1", "en2"}; !reflect.DeepEqual(st.Members, want) {
		t.Errorf("members = %v, want %v", st.Members, want)
	}
	want := map[netip.Addr]int{
		netip.MustParseAddr("169.254.9.209"): 16,
		netip.MustParseAddr("169.254.0.9"):   24,
		netip.MustParseAddr("169.254.0.10"):  32,
		netip.MustParseAddr("169.254.0.42"):  32,
	}
	if !reflect.DeepEqual(st.Addrs, want) {
		t.Errorf("addrs = %v, want %v", st.Addrs, want)
	}
}

func TestParseInterconnectLedger(t *testing.T) {
	got, err := ParseInterconnectLedger([]byte(`{"aliases":[
		{"slot":0,"address":"169.254.0.9"},
		{"slot":1,"address":"169.254.0.10"},
		{"slot":2,"address":"192.168.0.50"},
		{"slot":9,"address":"169.254.0.11"},
		{"slot":3,"address":"not an address"}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []InterconnectAlias{
		{Slot: 0, Address: netip.MustParseAddr("169.254.0.9")},
		{Slot: 1, Address: netip.MustParseAddr("169.254.0.10")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ledger = %v, want %v (an address outside the interconnect range, a bad slot and a bad address are dropped)", got, want)
	}
	if _, err := ParseInterconnectLedger([]byte("{")); err == nil {
		t.Error("malformed JSON parsed without an error")
	}
}

// TestUninstallFlushesInterconnectAliases is the uninstall half of the
// interconnect cleanup: Uninstall hands the system netd's ledger path after
// netd is booted out, and the removal list is the ledger's aliases that are on
// bridge0, /32s first, and nothing else.
func TestUninstallFlushesInterconnectAliases(t *testing.T) {
	t.Run("uninstall sweeps netd's ledger after netd is gone", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Uninstall(context.Background(), f, Config{}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		flush := slices.Index(f.calls, "FlushInterconnectAliases:"+netdsvc.InterconnectStatePath(MeshKeyDir))
		if flush < 0 {
			t.Fatalf("Uninstall never swept the interconnect ledger %s (calls: %v)", netdsvc.InterconnectStatePath(MeshKeyDir), f.calls)
		}
		bootout := slices.Index(f.calls, "Bootout:"+NetdLabel)
		if bootout < 0 || bootout > flush {
			t.Errorf("the sweep (call %d) must come after netd's bootout (call %d): netd writes the ledger", flush, bootout)
		}
	})

	t.Run("only owned aliases on bridge0, the node /24 last", func(t *testing.T) {
		owned, err := ParseInterconnectLedger([]byte(`{"aliases":[{"slot":0,"address":"169.254.0.9"},{"slot":1,"address":"169.254.0.10"},{"slot":2,"address":"169.254.0.11"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		present := ParseBridgeIfconfig([]byte(bridgeIfconfig)).Addrs
		got := interconnectFlushOrder(owned, present)
		want := []netip.Addr{netip.MustParseAddr("169.254.0.10"), netip.MustParseAddr("169.254.0.9")}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("flush order = %v, want %v: the slot-2 alias is not on bridge0, 169.254.0.42 and the self-assigned address are not netd's", got, want)
		}
	})

	t.Run("an empty ledger removes nothing", func(t *testing.T) {
		if got := interconnectFlushOrder(nil, ParseBridgeIfconfig([]byte(bridgeIfconfig)).Addrs); len(got) != 0 {
			t.Errorf("flush order = %v with no ledger, want nothing", got)
		}
	})
}
