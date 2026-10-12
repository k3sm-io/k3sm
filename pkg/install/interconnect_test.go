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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"k3sm.io/darwin-net/pkg/podnet"

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
		{"slot":2,"address":"192.0.2.50"},
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
		flush := slices.Index(f.calls, "FlushInterconnectAliases:"+netdsvc.InterconnectStatePath(MeshKeyDir)+":-1")
		if flush < 0 {
			t.Fatalf("Uninstall never swept the interconnect ledger %s (calls: %v)", netdsvc.InterconnectStatePath(MeshKeyDir), f.calls)
		}
		bootout := slices.Index(f.calls, "Bootout:"+NetdLabel)
		if bootout < 0 || bootout > flush {
			t.Errorf("the sweep (call %d) must come after netd's bootout (call %d): netd writes the ledger", flush, bootout)
		}
	})

	t.Run("only this node's derived aliases on bridge0, the node /24 last", func(t *testing.T) {
		owned, err := ParseInterconnectLedger([]byte(`{"aliases":[{"slot":0,"address":"169.254.0.9"},{"slot":1,"address":"169.254.0.10"},{"slot":2,"address":"169.254.0.11"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		present := ParseBridgeIfconfig([]byte(bridgeIfconfig)).Addrs
		got, skipped := interconnectFlushOrder(owned, present, 1)
		want := []netip.Addr{netip.MustParseAddr("169.254.0.10"), netip.MustParseAddr("169.254.0.9")}
		if !reflect.DeepEqual(got, want) || len(skipped) != 0 {
			t.Fatalf("flush order = %v (skipped %v), want %v: the slot-2 alias is not on bridge0, 169.254.0.42 and the self-assigned address are not netd's", got, skipped, want)
		}
	})

	t.Run("a crafted entry is not removed", func(t *testing.T) {
		present := ParseBridgeIfconfig([]byte(bridgeIfconfig)).Addrs
		for name, ledger := range map[string]string{
			// Slot 0 naming another in-range address that is on bridge0.
			"slot 0 with another address": `{"aliases":[{"slot":0,"address":"169.254.0.42"}]}`,
			// A real address of this node under the wrong slot.
			"the right address under another slot": `{"aliases":[{"slot":3,"address":"169.254.0.10"}]}`,
			// Another node's slot-0 address.
			"another node's address": `{"aliases":[{"slot":0,"address":"169.254.0.1"}]}`,
		} {
			owned, err := ParseInterconnectLedger([]byte(ledger))
			if err != nil {
				t.Fatal(err)
			}
			if got, skipped := interconnectFlushOrder(owned, present, 1); len(got) != 0 || len(skipped) != 1 {
				t.Errorf("%s: flush order = %v (skipped %v), want nothing removed and the entry reported", name, got, skipped)
			}
		}
		// The right address with the wrong netmask: a /32 where slot 0's /24 belongs.
		st := ParseBridgeIfconfig([]byte(bridgeIfconfig)).Addrs
		st[netip.MustParseAddr("169.254.0.9")] = 32
		owned, _ := ParseInterconnectLedger([]byte(`{"aliases":[{"slot":0,"address":"169.254.0.9"}]}`))
		if got, skipped := interconnectFlushOrder(owned, st, 1); len(got) != 0 || len(skipped) != 1 {
			t.Errorf("slot 0 as a /32 = %v (skipped %v), want nothing removed", got, skipped)
		}
		// An unknown node index derives nothing.
		owned, _ = ParseInterconnectLedger([]byte(`{"aliases":[{"slot":0,"address":"169.254.0.9"}]}`))
		if got, _ := interconnectFlushOrder(owned, present, -1); len(got) != 0 {
			t.Errorf("an unknown node index removed %v", got)
		}
	})

	t.Run("an empty ledger removes nothing", func(t *testing.T) {
		if got, _ := interconnectFlushOrder(nil, ParseBridgeIfconfig([]byte(bridgeIfconfig)).Addrs, 1); len(got) != 0 {
			t.Errorf("flush order = %v with no ledger, want nothing", got)
		}
	})

	t.Run("uninstall hands the sweep this node's cluster index", func(t *testing.T) {
		cidr, err := podnet.NodeCIDR(podnet.ClusterPodCIDR, 1)
		if err != nil {
			t.Fatal(err)
		}
		f := &fakeSystem{}
		f.putFile(netdsvc.NodeIdentityPath(MeshKeyDir), []byte(cidr.String()+"\n"))
		if err := Uninstall(context.Background(), f, Config{}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if want := "FlushInterconnectAliases:" + netdsvc.InterconnectStatePath(MeshKeyDir) + ":1"; !slices.Contains(f.calls, want) {
			t.Errorf("calls %v do not carry %q: the index must be read before the walk removes the identity file", f.calls, want)
		}
	})
}

// TestUninstallRetriesAFailedInterconnectSweep pins the retry contract of the
// interconnect sweep: an alias removal that fails keeps the ledger AND the node
// identity file the aliases are re-derived from, so running uninstall again
// removes the aliases and the ledger, and only that successful run removes the
// identity file.
func TestUninstallRetriesAFailedInterconnectSweep(t *testing.T) {
	cidr, err := podnet.NodeCIDR(podnet.ClusterPodCIDR, 1)
	if err != nil {
		t.Fatal(err)
	}
	identity := netdsvc.NodeIdentityPath(MeshKeyDir)
	ledger := writeLedger(t, 0o600, `{"aliases":[{"slot":0,"address":"169.254.0.9"},{"slot":1,"address":"169.254.0.10"}]}`)
	// bridge0 as ifconfig reports it: this node's slot-0 /24 and slot-1 /32,
	// and an alias in the range that is not netd's.
	bridge := map[netip.Addr]string{
		netip.MustParseAddr("169.254.0.9"):  "0xffffff00",
		netip.MustParseAddr("169.254.0.10"): "0xffffffff",
		netip.MustParseAddr("169.254.0.42"): "0xffffffff",
	}
	failRemoval := true
	ifconfig := func(args ...string) ([]byte, error) {
		if len(args) == 1 {
			var b strings.Builder
			b.WriteString("bridge0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n")
			for ip, mask := range bridge {
				fmt.Fprintf(&b, "\tinet %s netmask %s\n", ip, mask)
			}
			return []byte(b.String()), nil
		}
		ip := netip.MustParseAddr(args[2])
		if failRemoval && ip == netip.MustParseAddr("169.254.0.10") {
			return []byte("ifconfig: ioctl (SIOCDIFADDR): Can't assign requested address"), errors.New("exit status 1")
		}
		delete(bridge, ip)
		return nil, nil
	}
	f := &fakeSystem{}
	f.putFile(identity, []byte(cidr.String()+"\n"))
	f.flushInterconnect = func(nodeIndex int, log *slog.Logger) error {
		return sweepInterconnect(ledger, nodeIndex, uint32(os.Getuid()), ifconfig, log)
	}

	if err := Uninstall(context.Background(), f, Config{}); err == nil {
		t.Fatal("the first Uninstall reported success with an alias removal failing")
	}
	if _, ok := f.files[identity]; !ok {
		t.Fatalf("the failed sweep's uninstall removed the node identity %s: a re-run cannot re-derive the aliases the kept ledger names", identity)
	}
	if _, err := os.Stat(ledger); err != nil {
		t.Fatalf("the failed sweep did not keep the ledger: %v", err)
	}

	failRemoval = false
	f.calls = nil
	if err := Uninstall(context.Background(), f, Config{}); err != nil {
		t.Fatalf("the re-run Uninstall: %v", err)
	}
	if want := "FlushInterconnectAliases:" + netdsvc.InterconnectStatePath(MeshKeyDir) + ":1"; !slices.Contains(f.calls, want) {
		t.Errorf("the re-run calls %v do not carry %q: the re-run lost this node's cluster index", f.calls, want)
	}
	for _, ip := range []string{"169.254.0.9", "169.254.0.10"} {
		if _, ok := bridge[netip.MustParseAddr(ip)]; ok {
			t.Errorf("the re-run left this node's alias %s on bridge0", ip)
		}
	}
	if _, ok := bridge[netip.MustParseAddr("169.254.0.42")]; !ok {
		t.Error("the re-run removed 169.254.0.42, which the ledger does not own")
	}
	if _, err := os.Stat(ledger); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the re-run kept the ledger (stat: %v)", err)
	}
	if _, ok := f.files[identity]; ok {
		t.Errorf("the successful re-run kept the node identity %s", identity)
	}
}

// writeLedger writes a ledger file in a temp dir with mode perm.
func writeLedger(t *testing.T, perm os.FileMode, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "interconnect-aliases")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestInterconnectSweepRefusesUntrustedLedger pins the ledger file checks: the
// sweep acts only on a regular file, not a symlink, owned by the expected uid,
// with no group or other write bit. A refused ledger removes nothing and is
// not an uninstall error.
func TestInterconnectSweepRefusesUntrustedLedger(t *testing.T) {
	const ledger = `{"aliases":[{"slot":0,"address":"169.254.0.9"},{"slot":1,"address":"169.254.0.10"}]}`
	me := uint32(os.Getuid())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sweep := func(t *testing.T, path string, owner uint32) []string {
		t.Helper()
		var removed []string
		err := sweepInterconnect(path, 1, owner, func(args ...string) ([]byte, error) {
			if len(args) == 3 && args[1] == "-alias" {
				removed = append(removed, args[2])
				return nil, nil
			}
			return []byte(bridgeIfconfig), nil
		}, log)
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		return removed
	}

	t.Run("a trusted ledger is swept and removed", func(t *testing.T) {
		p := writeLedger(t, 0o600, ledger)
		if got, want := sweep(t, p, me), []string{"169.254.0.10", "169.254.0.9"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("removed %v, want %v", got, want)
		}
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the ledger survived a complete sweep: %v", err)
		}
	})

	t.Run("a symlinked ledger is refused", func(t *testing.T) {
		target := writeLedger(t, 0o600, ledger)
		link := filepath.Join(t.TempDir(), "interconnect-aliases")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if got := sweep(t, link, me); len(got) != 0 {
			t.Errorf("a symlinked ledger removed %v", got)
		}
		if _, err := os.Lstat(link); err != nil {
			t.Errorf("the refused link was removed: %v", err)
		}
	})

	t.Run("a group- or world-writable ledger is refused", func(t *testing.T) {
		for _, perm := range []os.FileMode{0o620, 0o602, 0o666} {
			p := writeLedger(t, perm, ledger)
			if got := sweep(t, p, me); len(got) != 0 {
				t.Errorf("a %s ledger removed %v", perm, got)
			}
			if _, err := os.Stat(p); err != nil {
				t.Errorf("the refused %s ledger was removed: %v", perm, err)
			}
		}
	})

	t.Run("a ledger owned by another uid is refused", func(t *testing.T) {
		p := writeLedger(t, 0o600, ledger)
		if got := sweep(t, p, me+1); len(got) != 0 {
			t.Errorf("a ledger owned by uid %d removed %v (want owner %d)", me, got, me+1)
		}
	})

	t.Run("a directory is refused", func(t *testing.T) {
		if got := sweep(t, t.TempDir(), me); len(got) != 0 {
			t.Errorf("a directory ledger removed %v", got)
		}
	})
}
