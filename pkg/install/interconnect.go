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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// InterconnectBridge is the interface every interconnect alias lives on: the
// Thunderbolt Bridge macOS puts every Thunderbolt port into.
const InterconnectBridge = "bridge0"

// interconnectCIDR is the one connected subnet every interconnect address lies
// in (netv1alpha1.InterconnectCIDR).
var interconnectCIDR = netip.MustParsePrefix(netv1alpha1.InterconnectCIDR)

// InterconnectAlias is one alias netd's interconnect ownership ledger records:
// the slot and the address netd derived for it.
type InterconnectAlias struct {
	Slot    int
	Address netip.Addr
}

// interconnectLedgerFile is the shape netd persists its owned aliases in (the
// file at netdsvc.InterconnectStatePath). netd is the only writer; this is a
// read of that file's documented fields, nothing more.
type interconnectLedgerFile struct {
	Aliases []struct {
		Slot    int    `json:"slot"`
		Address string `json:"address"`
	} `json:"aliases"`
}

// ParseInterconnectLedger decodes netd's interconnect ownership ledger and
// returns the entries that are interconnect aliases: an address inside
// netv1alpha1.InterconnectCIDR and a slot within 0..MaxInterconnectSlot. Any
// other entry is dropped, so nothing outside the interconnect range can ever be
// treated as k3sm-owned. Only malformed JSON is an error.
func ParseInterconnectLedger(raw []byte) ([]InterconnectAlias, error) {
	var l interconnectLedgerFile
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("parse the interconnect ownership ledger: %w", err)
	}
	out := make([]InterconnectAlias, 0, len(l.Aliases))
	for _, e := range l.Aliases {
		addr, err := netip.ParseAddr(e.Address)
		if err != nil || !interconnectCIDR.Contains(addr) || e.Slot < 0 || e.Slot > netv1alpha1.MaxInterconnectSlot {
			continue
		}
		out = append(out, InterconnectAlias{Slot: e.Slot, Address: addr})
	}
	return out, nil
}

// BridgeState is what `ifconfig bridge0` reports that the interconnect cares
// about: the member interfaces, and each IPv4 address with its prefix length
// (-1 when ifconfig printed no usable netmask).
type BridgeState struct {
	Members []string
	Addrs   map[netip.Addr]int
}

// ParseBridgeIfconfig reads `ifconfig bridge0` output: every "member: enX"
// line and every "inet A netmask M" line.
func ParseBridgeIfconfig(out []byte) BridgeState {
	st := BridgeState{Addrs: map[netip.Addr]int{}}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "member:":
			st.Members = append(st.Members, f[1])
		case "inet":
			ip, err := netip.ParseAddr(f[1])
			if err != nil {
				continue
			}
			st.Addrs[ip] = -1
			if i := slices.Index(f, "netmask"); i > 0 && i+1 < len(f) {
				st.Addrs[ip] = netmaskBits(f[i+1])
			}
		}
	}
	return st
}

// netmaskBits converts an ifconfig netmask, hex ("0xffffff00") or dotted
// ("255.255.255.0"), to its prefix length, or -1 when it is unparsable or not
// contiguous.
func netmaskBits(s string) int {
	var m uint32
	if hex, ok := strings.CutPrefix(s, "0x"); ok {
		v, err := strconv.ParseUint(hex, 16, 32)
		if err != nil {
			return -1
		}
		m = uint32(v)
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			return -1
		}
		b := a.As4()
		m = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	n := bits.LeadingZeros32(^m)
	if n < 32 && m<<n != 0 {
		return -1
	}
	return n
}

// interconnectFlushOrder is the uninstall's removal list: every alias the
// ledger owns that is on bridge0 now and inside the interconnect range, the
// pod /32s first and slot 0 (the node's connected /24, which they ride) last.
// An address the ledger does not name is never on the list, whatever range it
// is in: uninstall removes k3sm's own aliases and nothing else.
func interconnectFlushOrder(owned []InterconnectAlias, present map[netip.Addr]int) []netip.Addr {
	keep := make([]InterconnectAlias, 0, len(owned))
	for _, a := range owned {
		if _, here := present[a.Address]; here && interconnectCIDR.Contains(a.Address) {
			keep = append(keep, a)
		}
	}
	slices.SortStableFunc(keep, func(a, b InterconnectAlias) int { return b.Slot - a.Slot })
	out := make([]netip.Addr, 0, len(keep))
	for _, a := range keep {
		out = append(out, a.Address)
	}
	return out
}
