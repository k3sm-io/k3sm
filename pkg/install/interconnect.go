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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/bits"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/netdsvc"
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

// interconnectFlushOrder is the uninstall's removal list, re-derived rather
// than trusted: an entry is removed only when its address is exactly
// netv1alpha1.InterconnectSlotAddress(nodeIndex, slot) for THIS node's cluster
// index, it is on bridge0 now, and it carries the netmask netd gives that slot
// (/24 for slot 0, /32 for the rest). The pod /32s come first and slot 0 (the
// node's connected /24, which they ride) last. Every entry that fails a check is
// returned in skipped with the reason, and nothing outside the list is ever
// removed, so a ledger edited to name another address removes nothing.
func interconnectFlushOrder(owned []InterconnectAlias, present map[netip.Addr]int, nodeIndex int) (remove []netip.Addr, skipped []string) {
	keep := make([]InterconnectAlias, 0, len(owned))
	for _, a := range owned {
		want, err := netv1alpha1.InterconnectSlotAddress(nodeIndex, a.Slot)
		if err != nil || a.Address != want {
			skipped = append(skipped, fmt.Sprintf("slot %d address %s is not this node's derived address", a.Slot, a.Address))
			continue
		}
		bits, here := present[a.Address]
		if !here {
			continue
		}
		wantBits := 32
		if a.Slot == netv1alpha1.InterconnectSlotNode {
			wantBits = interconnectCIDR.Bits()
		}
		if bits != wantBits {
			skipped = append(skipped, fmt.Sprintf("slot %d address %s is on %s as /%d, not /%d", a.Slot, a.Address, InterconnectBridge, bits, wantBits))
			continue
		}
		keep = append(keep, a)
	}
	slices.SortStableFunc(keep, func(a, b InterconnectAlias) int { return b.Slot - a.Slot })
	remove = make([]netip.Addr, 0, len(keep))
	for _, a := range keep {
		remove = append(remove, a.Address)
	}
	return remove, skipped
}

// errUntrustedLedger reports a ledger file the sweep refuses to act on.
var errUntrustedLedger = errors.New("untrusted interconnect ownership ledger")

// readTrustedLedger reads the ledger at path through one O_NOFOLLOW
// descriptor, and only when that descriptor is a regular file owned by
// ownerUID with no group or other write bit. A symlink (the open fails), a
// file someone else could have written, or any other file kind returns an error
// wrapping errUntrustedLedger. An absent file returns fs.ErrNotExist.
func readTrustedLedger(path string, ownerUID uint32) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", errUntrustedLedger, path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: stat %s: %v", errUntrustedLedger, path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", errUntrustedLedger, path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: %s is writable by group or others (%s)", errUntrustedLedger, path, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != ownerUID {
		return nil, fmt.Errorf("%w: %s is not owned by uid %d", errUntrustedLedger, path, ownerUID)
	}
	return io.ReadAll(f)
}

// sweepInterconnect is FlushInterconnectAliases' body over one seam, ifconfig
// (run with its arguments, returning its combined output). It reads the
// ledger only when readTrustedLedger accepts it, removes the
// interconnectFlushOrder list, and removes the ledger once every removal
// succeeded. An unknown node index (negative), an untrusted ledger, or an
// entry that is not this node's derived alias is skipped with a warning, never
// an error: those leave state in place, which is the safe direction.
func sweepInterconnect(ledgerPath string, nodeIndex int, ownerUID uint32, ifconfig func(args ...string) ([]byte, error), log *slog.Logger) error {
	raw, err := readTrustedLedger(ledgerPath, ownerUID)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case errors.Is(err, errUntrustedLedger):
		log.Warn("interconnect aliases not swept: the ownership ledger is not a root-owned regular file", "err", err,
			"remedy", "sudo ifconfig "+InterconnectBridge+"   # inspect, then remove k3sm's 169.254.0.x aliases by hand")
		return nil
	case err != nil:
		return fmt.Errorf("read the interconnect ownership ledger: %w", err)
	}
	if nodeIndex < 0 {
		log.Warn("interconnect aliases not swept: this node's cluster index is unknown (no adopted pod range), so no alias can be re-derived",
			"ledger", ledgerPath)
		return nil
	}
	owned, err := ParseInterconnectLedger(raw)
	if err != nil {
		return err
	}
	out, err := ifconfig(InterconnectBridge)
	present := map[netip.Addr]int{}
	switch {
	case err == nil:
		present = ParseBridgeIfconfig(out).Addrs
	case strings.Contains(string(out), "does not exist"):
		// No bridge0, so no alias on it to remove.
	default:
		return fmt.Errorf("ifconfig %s: %w\n%s", InterconnectBridge, err, out)
	}
	remove, skipped := interconnectFlushOrder(owned, present, nodeIndex)
	for _, why := range skipped {
		log.Warn("interconnect ledger entry left in place", "reason", why)
	}
	var errs []error
	for _, ip := range remove {
		if rmOut, err := ifconfig(InterconnectBridge, "-alias", ip.String()); err != nil {
			errs = append(errs, fmt.Errorf("ifconfig %s -alias %s: %w\n%s", InterconnectBridge, ip, err, rmOut))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if err := os.Remove(ledgerPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the interconnect ownership ledger: %w", err)
	}
	return nil
}

// interconnectNodeIndex is this node's cluster index from the pod range netd
// adopted (the identity file), or -1 when there is none or it does not parse.
// Uninstall reads it before the manifest walk removes that file.
func interconnectNodeIndex(sys System) int {
	raw, err := sys.ReadRegularFile(netdsvc.NodeIdentityPath(MeshKeyDir))
	if err != nil {
		return -1
	}
	cidr, err := netip.ParsePrefix(strings.TrimSpace(string(raw)))
	if err != nil {
		return -1
	}
	idx, err := podnet.NodeIndex(podnet.ClusterPodCIDR, cidr.Masked())
	if err != nil {
		return -1
	}
	return idx
}
