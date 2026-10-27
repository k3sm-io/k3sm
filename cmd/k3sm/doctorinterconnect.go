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

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/netdsvc"
	"k3sm.io/k3sm/pkg/status"
)

// The interconnect section's row names. They share the "ic-" prefix so the
// section reads as one block in the ladder and in --json.
const (
	icBridge    = "ic-bridge"
	icNetd      = "ic-netd"
	icAddress   = "ic-address"
	icPeers     = "ic-peers"
	icPods      = "ic-pods"
	icLoop      = "ic-loop"
	icStray     = "ic-stray"
	icResidue   = "ic-residue"
	icSleep     = "ic-sleep"
	icAutoLogin = "ic-autologin"
	icPower     = "ic-power"
)

// errNoBridge reports that the host has no bridge0 interface (the Thunderbolt
// Bridge was deleted).
var errNoBridge = errors.New("bridge0 does not exist")

// oldHalf is the high RFC 3927 reserved half, 169.254.255.0/24. An earlier
// interconnect design configured it; nothing k3sm ships does now, so any alias
// or route there is left over.
var oldHalf = netip.MustParsePrefix("169.254.255.0/24")

// icCIDR is the one interconnect subnet (netv1alpha1.InterconnectCIDR).
var icCIDR = netip.MustParsePrefix(netv1alpha1.InterconnectCIDR)

// icRoute is one IPv4 routing-table entry inside 169.254/16, as `netstat -rn -f
// inet` prints it.
type icRoute struct {
	Dest  netip.Prefix
	Flags string
	Iface string
}

// icCluster is what the apiserver says about this node's interconnect: the
// node's name, whether the server armed it as a member (its desired
// annotation), its member state when this credential may read the Interconnect
// (a control plane's may, a worker's may not), and the pods on it holding an
// interconnect address.
type icCluster struct {
	Node        string
	Desired     bool
	MemberState netv1alpha1.InterconnectMemberState
	Pods        []status.InterconnectPod
}

// powerSettings is what `pmset -g` reports for the two TN3205 power settings.
// The Has fields are false when pmset printed no such line (a Mac that does not
// offer the setting).
type powerSettings struct {
	Sleep          int
	HasSleep       bool
	AutoRestart    int
	HasAutoRestart bool
}

// interconnectEnv is the interconnect section's fakeable seams, every one of
// them a read. The real probes are wired in realInterconnectEnv; nothing in the
// checks below runs a command or opens a file.
type interconnectEnv struct {
	// ports enumerates the Thunderbolt ports (darwin-net pkg/linkenum); an
	// error wrapping linkenum.ErrNoThunderboltService means this Mac has none.
	ports func() ([]linkenum.Port, error)
	// bridge reads bridge0's members and IPv4 addresses; errNoBridge when it
	// does not exist.
	bridge func() (install.BridgeState, error)
	// routes lists the routing-table entries inside 169.254/16.
	routes func() ([]icRoute, error)
	// neighbors lists the complete ARP entries on bridge0 inside the
	// interconnect subnet.
	neighbors func() ([]netip.Addr, error)
	// rtt pings each address once and returns the round trip of every one that
	// answered.
	rtt func(addrs []netip.Addr) map[netip.Addr]time.Duration
	// helper dials netd's socket; nil means it answered.
	helper func() error
	// ledger is netd's interconnect ownership record (root-only); an absent
	// record is (nil, nil).
	ledger func() ([]install.InterconnectAlias, error)
	// identity is the node pod range netd adopted (root-only).
	identity func() (netip.Prefix, error)
	// cluster reads this node's view from the apiserver.
	cluster func() (icCluster, error)
	// power reads the sleep and start-after-power-failure settings, and
	// autoLogin the account macOS logs in automatically ("" for none).
	power     func() (powerSettings, error)
	autoLogin func() (string, error)
}

// icFacts is every seam's answer, read once so each row reads the same
// snapshot.
type icFacts struct {
	ports     []linkenum.Port
	portsErr  error
	bridge    install.BridgeState
	bridgeErr error
	routes    []icRoute
	routesErr error
	ledger    []install.InterconnectAlias
	ledgerErr error
	ident     netip.Prefix
	identErr  error
	cluster   icCluster
	clusterOK error
}

// ownsSlot0 reports whether netd's record holds a slot-0 alias.
func (f icFacts) ownsSlot0() bool {
	return slices.ContainsFunc(f.ledger, func(a install.InterconnectAlias) bool { return a.Slot == netv1alpha1.InterconnectSlotNode })
}

// owns reports whether netd's record names addr.
func (f icFacts) owns(addr netip.Addr) bool {
	return slices.ContainsFunc(f.ledger, func(a install.InterconnectAlias) bool { return a.Address == addr })
}

// cabled reports whether any Thunderbolt port has another Mac on its far end.
func (f icFacts) cabled() bool {
	return slices.ContainsFunc(f.ports, func(p linkenum.Port) bool { return p.PeerDomainUUID != "" })
}

// hasInterconnectAlias reports whether bridge0 holds any address in the
// interconnect subnet.
func (f icFacts) hasInterconnectAlias() bool {
	for a := range f.bridge.Addrs {
		if icCIDR.Contains(a) {
			return true
		}
	}
	return false
}

// interconnectChecks is the doctor's interconnect section. A nil env adds
// nothing. A Mac with no Thunderbolt port gets one SKIP; a Mac with no cable to
// another Mac and no interconnect state gets that SKIP plus the stray-state
// check (stray state outlives the cable); every other Mac gets the whole
// section: bridge0, netd, the address, the peers, the pods, the loop check, the
// stray and residue state, and the three TN3205 power and login advisories.
func interconnectChecks(ic *interconnectEnv, role install.Role) []checkResult {
	if ic == nil {
		return nil
	}
	var f icFacts
	f.ports, f.portsErr = ic.ports()
	if errors.Is(f.portsErr, linkenum.ErrNoThunderboltService) {
		return []checkResult{{name: icBridge, status: statusSkip,
			detail: "this Mac has no Thunderbolt network port, so there is no interconnect to check"}}
	}
	f.bridge, f.bridgeErr = ic.bridge()
	f.routes, f.routesErr = ic.routes()
	f.ledger, f.ledgerErr = ic.ledger()
	f.ident, f.identErr = ic.identity()
	f.cluster, f.clusterOK = ic.cluster()

	stray := checkICStray(f)
	residue, hasResidue := checkICResidue(f)
	inUse := f.cabled() || f.ownsSlot0() || f.hasInterconnectAlias() || (f.clusterOK == nil && f.cluster.Desired)
	if !inUse {
		rows := []checkResult{{name: icBridge, status: statusSkip,
			detail: "no Thunderbolt cable to another Mac is plugged in and this node holds no interconnect address, so only stray state is checked"}}
		rows = append(rows, stray)
		if hasResidue {
			rows = append(rows, residue)
		}
		return rows
	}
	address, own := checkICAddress(f, role)
	rows := []checkResult{
		checkICBridge(f),
		checkICNetd(ic.helper()),
		address,
		checkICPeers(own, ic),
		checkICPods(f),
		checkICLoop(f),
		stray,
	}
	if hasResidue {
		rows = append(rows, residue)
	}
	power, powerErr := ic.power()
	user, userErr := ic.autoLogin()
	return append(rows, checkICSleep(power, powerErr), checkICAutoLogin(user, userErr), checkICPower(power, powerErr))
}

// checkICBridge reports bridge0's members and which are Thunderbolt ports.
// k3sm never changes bridge0's membership, so a bridge with no Thunderbolt
// member is repaired by macOS, not by k3sm.
func checkICBridge(f icFacts) checkResult {
	switch {
	case errors.Is(f.bridgeErr, errNoBridge):
		return checkResult{name: icBridge, status: statusWarn,
			detail: "bridge0 (the Thunderbolt Bridge) does not exist, so the interconnect has no interface on this Mac",
			remedy: "recreate the Thunderbolt Bridge in System Settings > Network (the ... menu > Manage Virtual Interfaces) with every Thunderbolt port in it"}
	case f.bridgeErr != nil:
		return checkResult{name: icBridge, status: statusWarn,
			detail: fmt.Sprintf("could not read bridge0: %v", f.bridgeErr),
			remedy: "ifconfig bridge0   # read it by hand"}
	}
	tb := map[string]int{}
	for _, p := range f.ports {
		tb[p.Iface] = p.PortOrdinal + 1
	}
	var named []string
	tbMembers := 0
	for _, m := range f.bridge.Members {
		if n, ok := tb[m]; ok {
			tbMembers++
			named = append(named, fmt.Sprintf("%s (Thunderbolt %d)", m, n))
			continue
		}
		named = append(named, m)
	}
	members := "none"
	if len(named) > 0 {
		members = strings.Join(named, ", ")
	}
	if f.portsErr != nil {
		return checkResult{name: icBridge, status: statusWarn,
			detail: fmt.Sprintf("bridge0 members: %s; could not tell which are Thunderbolt ports: %v", members, f.portsErr),
			remedy: "system_profiler SPThunderboltDataType   # read the ports by hand"}
	}
	if tbMembers == 0 {
		return checkResult{name: icBridge, status: statusWarn,
			detail: fmt.Sprintf("bridge0 has no Thunderbolt port as a member (members: %s), so the cable carries nothing here", members),
			remedy: "restart this Mac: a Thunderbolt port taken out of bridge0 comes back only after a restart (k3sm never changes bridge0's members)"}
	}
	return checkResult{name: icBridge, status: statusPass, detail: "bridge0 members: " + members}
}

// checkICNetd reports whether netd answers on its socket: it is the process that
// adds and removes this node's interconnect addresses while k3sm runs (uninstall
// sweeps the ones its record names).
func checkICNetd(err error) checkResult {
	switch {
	case err == nil:
		return checkResult{name: icNetd, status: statusPass,
			detail: install.NetdLabel + " answers on its socket (it adds and removes the interconnect addresses)"}
	case errors.Is(err, fs.ErrPermission):
		return checkResult{name: icNetd, status: statusSkip,
			detail: "netd's socket is not open to this account",
			remedy: "sudo k3sm doctor"}
	}
	return checkResult{name: icNetd, status: statusWarn,
		detail: fmt.Sprintf("%s does not answer on its socket (%v), so this node cannot add or remove its interconnect address", install.NetdLabel, err),
		remedy: "sudo launchctl kickstart -k system/" + install.NetdLabel}
}

// nodeDaemon is the role's node daemon label and the `k3sm status logs` view
// that reads its log.
func nodeDaemon(role install.Role) (label, logs string) {
	if role == install.RoleAgent {
		return install.AgentLabel, "agent"
	}
	return install.ServerLabel, "server"
}

// checkICAddress reports this node's slot-0 interconnect address: present on
// bridge0 with a /24 netmask when netd owns it or the server armed this node,
// absent otherwise. It returns the address when it is on bridge0 (the peers
// check needs it), else the zero Addr.
func checkICAddress(f icFacts, role install.Role) (checkResult, netip.Addr) {
	label, logs := nodeDaemon(role)
	reapply := fmt.Sprintf("sudo launchctl kickstart -k system/%s   # the node applies its interconnect address again\nsudo k3sm status logs %s", label, logs)
	switch {
	case errors.Is(f.ledgerErr, fs.ErrPermission) || errors.Is(f.identErr, fs.ErrPermission):
		return checkResult{name: icAddress, status: statusSkip,
			detail: "netd's address records are readable only by root", remedy: "sudo k3sm doctor"}, netip.Addr{}
	case errors.Is(f.identErr, fs.ErrNotExist):
		return checkResult{name: icAddress, status: statusSkip,
			detail: "netd has not adopted this node's pod range yet (the node has not joined), so there is no interconnect address to expect"}, netip.Addr{}
	case f.identErr != nil:
		return checkResult{name: icAddress, status: statusWarn,
			detail: fmt.Sprintf("could not read the pod range netd adopted: %v", f.identErr), remedy: "sudo launchctl kickstart -k system/" + install.NetdLabel}, netip.Addr{}
	case install.IsUntrustedLedger(f.ledgerErr):
		return checkResult{name: icAddress, status: statusFail,
			detail: fmt.Sprintf("netd's interconnect record is not trusted, so it was not read (uninstall refuses it the same way): %v", f.ledgerErr),
			remedy: "sudo ls -l " + netdsvc.InterconnectStatePath(install.MeshKeyDir) + "   # it must be a root-owned regular file, not writable by group or others"}, netip.Addr{}
	case f.ledgerErr != nil:
		return checkResult{name: icAddress, status: statusWarn,
			detail: fmt.Sprintf("could not read netd's interconnect record: %v", f.ledgerErr), remedy: "sudo launchctl kickstart -k system/" + install.NetdLabel}, netip.Addr{}
	case f.bridgeErr != nil:
		return checkResult{name: icAddress, status: statusSkip,
			detail: "bridge0 could not be read (see " + icBridge + "), so the address could not be checked"}, netip.Addr{}
	}
	idx, err := podnet.NodeIndex(podnet.ClusterPodCIDR, f.ident)
	if err != nil {
		return checkResult{name: icAddress, status: statusWarn,
			detail: fmt.Sprintf("netd's adopted pod range %s has no cluster index: %v", f.ident, err), remedy: "sudo launchctl kickstart -k system/" + install.NetdLabel}, netip.Addr{}
	}
	want, err := netv1alpha1.InterconnectSlotAddress(idx, netv1alpha1.InterconnectSlotNode)
	if err != nil {
		node := f.cluster.Node
		if node == "" {
			node = "<this node>"
		}
		return checkResult{name: icAddress, status: statusWarn,
			detail: fmt.Sprintf("this node's cluster index is %d, above %d, so it gets no interconnect address", idx, netv1alpha1.MaxInterconnectNodeIndex),
			remedy: fmt.Sprintf(`k3sm kubectl patch interconnect %s --type merge -p '{"spec":{"excludedNodes":["%s"]}}'   # or cable only nodes with cluster index 0..%d`,
				netv1alpha1.MediumThunderbolt, node, netv1alpha1.MaxInterconnectNodeIndex)}, netip.Addr{}
	}
	expected := f.ownsSlot0() || (f.clusterOK == nil && f.cluster.Desired)
	bits, present := f.bridge.Addrs[want]
	switch {
	case present && bits == icCIDR.Bits():
		return checkResult{name: icAddress, status: statusPass,
			detail: fmt.Sprintf("%s/%d on bridge0, this node's interconnect address (cluster index %d)", want, bits, idx)}, want
	case present:
		return checkResult{name: icAddress, status: statusWarn,
			detail: fmt.Sprintf("%s is on bridge0 with a /%d netmask; it must be /%d so peers are reached without a route", want, bits, icCIDR.Bits()),
			remedy: reapply}, want
	case expected:
		return checkResult{name: icAddress, status: statusFail,
			detail: fmt.Sprintf("this node is an armed member, but its interconnect address %s is not on bridge0", want),
			remedy: reapply}, netip.Addr{}
	}
	return checkResult{name: icAddress, status: statusSkip,
		detail: fmt.Sprintf("no interconnect address: the interconnect is disarmed or this node is not an armed member (it will be %s/%d)", want, icCIDR.Bits())}, netip.Addr{}
}

// isSlot0 reports whether addr is a node's slot-0 address (169.254.0.(8·idx+1)).
func isSlot0(addr netip.Addr) bool {
	if !icCIDR.Contains(addr) {
		return false
	}
	host := int(addr.As4()[3])
	return host >= 1 && (host-1)%(netv1alpha1.MaxInterconnectSlot+1) == netv1alpha1.InterconnectSlotNode
}

// checkICPeers pings every peer node's slot-0 address this node has an ARP
// entry for and reports the round trips. own is this node's address, or the
// zero Addr when it has none (then there is nothing to reach from).
func checkICPeers(own netip.Addr, ic *interconnectEnv) checkResult {
	const awake = "check the cable, and that each peer Mac is awake: Thunderbolt has no Wake-on-LAN\nk3sm status   # on a control-plane Mac: which members are up"
	if !own.IsValid() {
		return checkResult{name: icPeers, status: statusSkip, detail: "this node has no interconnect address, so there are no peers to reach"}
	}
	neigh, err := ic.neighbors()
	if err != nil {
		return checkResult{name: icPeers, status: statusWarn,
			detail: fmt.Sprintf("could not read the ARP table: %v", err), remedy: "arp -an -i bridge0   # read it by hand"}
	}
	var peers []netip.Addr
	for _, a := range neigh {
		if a != own && isSlot0(a) && !slices.Contains(peers, a) {
			peers = append(peers, a)
		}
	}
	slices.SortFunc(peers, func(a, b netip.Addr) int { return a.Compare(b) })
	if len(peers) == 0 {
		return checkResult{name: icPeers, status: statusWarn,
			detail: "no peer node's interconnect address has been seen on bridge0", remedy: awake}
	}
	rtt := ic.rtt(peers)
	parts := make([]string, 0, len(peers))
	silent := 0
	for _, p := range peers {
		d, ok := rtt[p]
		if !ok {
			silent++
			parts = append(parts, p.String()+" no answer")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %.2f ms", p, float64(d.Microseconds())/1000))
	}
	if silent > 0 {
		return checkResult{name: icPeers, status: statusWarn,
			detail: fmt.Sprintf("%d of %d peers answered: %s", len(peers)-silent, len(peers), strings.Join(parts, ", ")), remedy: awake}
	}
	return checkResult{name: icPeers, status: statusPass,
		detail: fmt.Sprintf("%d reachable: %s", len(peers), strings.Join(parts, ", "))}
}

// checkICPods lists the pods on this node holding an interconnect address, from
// their attach condition. Without the apiserver it lists the pod addresses
// netd holds instead.
func checkICPods(f icFacts) checkResult {
	if f.clusterOK != nil {
		detail := fmt.Sprintf("the apiserver could not be read (%v), so the pods are not listed", f.clusterOK)
		var held []string
		for _, a := range f.ledger {
			if a.Slot != netv1alpha1.InterconnectSlotNode {
				held = append(held, a.Address.String())
			}
		}
		if len(held) > 0 {
			detail += "; netd holds pod addresses " + strings.Join(held, ", ")
		}
		return checkResult{name: icPods, status: statusSkip, detail: detail}
	}
	if len(f.cluster.Pods) == 0 {
		return checkResult{name: icPods, status: statusPass, detail: "no pod on this node holds an interconnect address"}
	}
	parts := make([]string, 0, len(f.cluster.Pods))
	for _, p := range f.cluster.Pods {
		parts = append(parts, fmt.Sprintf("%s/%s %s", p.Namespace, p.Pod, p.Address))
	}
	return checkResult{name: icPods, status: statusPass,
		detail: fmt.Sprintf("%d on this node: %s", len(parts), strings.Join(parts, ", "))}
}

// checkICLoop warns when the cables form a loop: two of this Mac's ports reach
// the same Mac, a cable joins two of its own ports, or the server marked this
// node a loop member (which sees cycles through other Macs). Bridged
// Thunderbolt ports must not form a loop, and k3sm never turns on spanning tree.
func checkICLoop(f icFacts) checkResult {
	const remedy = "remove one cable: bridged Thunderbolt ports must not form a loop, and k3sm never turns on spanning tree"
	own := map[string]bool{}
	for _, p := range f.ports {
		own[p.DomainUUID] = true
	}
	byPeer := map[string][]string{}
	var reasons []string
	for _, p := range f.ports {
		if p.PeerDomainUUID == "" {
			continue
		}
		if own[p.PeerDomainUUID] {
			reasons = append(reasons, fmt.Sprintf("%s is cabled to another port of this Mac", p.Iface))
		}
		byPeer[p.PeerDomainUUID] = append(byPeer[p.PeerDomainUUID], p.Iface)
	}
	for _, ifaces := range byPeer {
		if len(ifaces) > 1 {
			sort.Strings(ifaces)
			reasons = append(reasons, strings.Join(ifaces, " and ")+" reach the same Mac")
		}
	}
	if f.clusterOK == nil && f.cluster.MemberState == netv1alpha1.InterconnectMemberLoop {
		reasons = append(reasons, "the server marked this node a loop member")
	}
	sort.Strings(reasons)
	if len(reasons) > 0 {
		return checkResult{name: icLoop, status: statusWarn,
			detail: "the cables form a loop, so this node is not used: " + strings.Join(reasons, "; "), remedy: remedy}
	}
	cables := 0
	for _, ifaces := range byPeer {
		cables += len(ifaces)
	}
	return checkResult{name: icLoop, status: statusPass, detail: fmt.Sprintf("no loop (%s to other Macs)", plural(cables, "cable"))}
}

// plural renders a count with a singular or plural noun.
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// isResidue reports whether r is the cloned host route macOS keeps after an
// address is removed: a /32 on bridge0 in either reserved half, not an ARP
// entry (no L flag), for an address no longer on bridge0. macOS refuses to
// delete it ("not in table"), so it is reported, never repaired, and k3sm
// never adds an address over it.
func isResidue(r icRoute, addrs map[netip.Addr]int) bool {
	if r.Iface != install.InterconnectBridge || r.Dest.Bits() != 32 || strings.Contains(r.Flags, "L") {
		return false
	}
	a := r.Dest.Addr()
	if !icCIDR.Contains(a) && !oldHalf.Contains(a) {
		return false
	}
	_, here := addrs[a]
	return !here
}

// checkICStray reports reserved-range state on bridge0 that is not k3sm's: an
// interconnect-subnet alias netd's record does not own, any alias in the old
// half, and any old-half route that is not residue. Each comes with the
// command that removes it; k3sm removes none of it on its own.
func checkICStray(f icFacts) checkResult {
	var found, remedy []string
	if f.bridgeErr == nil {
		var addrs []netip.Addr
		for a := range f.bridge.Addrs {
			addrs = append(addrs, a)
		}
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
		for _, a := range addrs {
			switch {
			case oldHalf.Contains(a):
				found = append(found, fmt.Sprintf("alias %s in 169.254.255.0/24, the half k3sm no longer uses", a))
			case icCIDR.Contains(a) && f.ledgerErr == nil && !f.owns(a):
				found = append(found, fmt.Sprintf("alias %s in %s that netd does not own", a, icCIDR))
			default:
				continue
			}
			remedy = append(remedy, fmt.Sprintf("sudo ifconfig %s -alias %s   # only if nothing else on this Mac put it there", install.InterconnectBridge, a))
		}
	}
	if f.routesErr == nil {
		for _, r := range f.routes {
			if !oldHalf.Contains(r.Dest.Addr()) || strings.Contains(r.Flags, "L") || isResidue(r, f.bridge.Addrs) {
				continue
			}
			found = append(found, fmt.Sprintf("route %s via %s in 169.254.255.0/24", r.Dest, r.Iface))
			remedy = append(remedy, fmt.Sprintf("sudo route -n delete -net %s -interface %s", r.Dest, r.Iface))
		}
	}
	if len(found) > 0 {
		return checkResult{name: icStray, status: statusWarn,
			detail: "stray reserved-range state: " + strings.Join(found, "; "), remedy: strings.Join(remedy, "\n")}
	}
	switch {
	case f.bridgeErr != nil && !errors.Is(f.bridgeErr, errNoBridge):
		return checkResult{name: icStray, status: statusSkip, detail: "bridge0 could not be read (see " + icBridge + ")"}
	case f.routesErr != nil:
		return checkResult{name: icStray, status: statusWarn,
			detail: fmt.Sprintf("could not read the routing table: %v", f.routesErr), remedy: "netstat -rn -f inet   # read it by hand"}
	case errors.Is(f.ledgerErr, fs.ErrPermission) && f.hasInterconnectAlias():
		return checkResult{name: icStray, status: statusSkip,
			detail: "no old-half state; the aliases in " + icCIDR.String() + " could not be checked against netd's record, which only root can read",
			remedy: "sudo k3sm doctor"}
	}
	return checkResult{name: icStray, status: statusPass, detail: "no stray reserved-range alias or route on bridge0"}
}

// checkICResidue reports the cloned host routes macOS will not delete, as the
// harmless pre-existing state they are; ok is false when there are none.
func checkICResidue(f icFacts) (checkResult, bool) {
	if f.routesErr != nil {
		return checkResult{}, false
	}
	var left []string
	for _, r := range f.routes {
		if isResidue(r, f.bridge.Addrs) {
			left = append(left, r.Dest.String())
		}
	}
	if len(left) == 0 {
		return checkResult{}, false
	}
	return checkResult{name: icResidue, status: statusPass, detail: fmt.Sprintf(
		"harmless pre-existing state: %s on bridge0 (cloned routes macOS keeps after an address is removed and will not delete; k3sm never adds an address over one)",
		strings.Join(left, ", "))}, true
}

// tn3205 names Apple's guidance for Macs joined by Thunderbolt, which the
// three advisories below follow.
const tn3205 = "Apple's guidance for Macs joined by Thunderbolt (TN3205)"

// checkICSleep advises turning idle sleep off: Thunderbolt has no Wake-on-LAN,
// so a sleeping Mac drops off the interconnect until someone wakes it.
func checkICSleep(p powerSettings, err error) checkResult {
	const remedy = "sudo pmset -a sleep 0"
	switch {
	case err != nil:
		return checkResult{name: icSleep, status: statusWarn, detail: fmt.Sprintf("could not read the power settings: %v", err), remedy: "pmset -g   # read them by hand"}
	case !p.HasSleep:
		return checkResult{name: icSleep, status: statusWarn, detail: "pmset reports no system sleep setting, so idle sleep could not be checked", remedy: remedy}
	case p.Sleep == 0:
		return checkResult{name: icSleep, status: statusPass, detail: "idle sleep is off (Thunderbolt has no Wake-on-LAN)"}
	}
	return checkResult{name: icSleep, status: statusWarn, detail: fmt.Sprintf(
		"this Mac sleeps after %s idle; Thunderbolt has no Wake-on-LAN, so a sleeping Mac drops off the interconnect until someone wakes it (%s)",
		plural(p.Sleep, "minute"), tn3205), remedy: remedy}
}

// checkICAutoLogin advises automatic login, so a Mac that restarts (a power
// failure, an update) comes back without someone at the login window.
func checkICAutoLogin(user string, err error) checkResult {
	const remedy = "System Settings > Users & Groups > Automatically log in as: choose an account (macOS does not offer it while FileVault is on)"
	if err == nil && user != "" {
		return checkResult{name: icAutoLogin, status: statusPass, detail: "automatic login as " + user}
	}
	return checkResult{name: icAutoLogin, status: statusWarn, detail: fmt.Sprintf(
		"automatic login is off, so after a restart this Mac waits at the login window (%s)", tn3205), remedy: remedy}
}

// checkICPower advises starting up after a power failure, so a cabled Mac comes
// back on its own when the power does.
func checkICPower(p powerSettings, err error) checkResult {
	switch {
	case err != nil:
		return checkResult{name: icPower, status: statusWarn, detail: fmt.Sprintf("could not read the power settings: %v", err), remedy: "pmset -g   # read them by hand"}
	case !p.HasAutoRestart:
		return checkResult{name: icPower, status: statusSkip, detail: "this Mac does not offer starting up after a power failure (pmset lists no autorestart setting)"}
	case p.AutoRestart != 0:
		return checkResult{name: icPower, status: statusPass, detail: "starts up again after a power failure"}
	}
	return checkResult{name: icPower, status: statusWarn, detail: fmt.Sprintf(
		"this Mac stays off after a power failure until someone presses the power button (%s)", tn3205),
		remedy: "sudo pmset -a autorestart 1"}
}

// parseNetstatRoutes reads `netstat -rn -f inet` output and returns the entries
// inside 169.254/16. netstat abbreviates destinations ("169.254.0/24",
// "169.254"), and prints a host entry without a prefix length.
func parseNetstatRoutes(out string) []icRoute {
	linkLocal := netip.MustParsePrefix("169.254.0.0/16")
	var routes []icRoute
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasPrefix(f[0], "169.254") {
			continue
		}
		dest, ok := parseNetstatDest(f[0], f[2])
		if !ok || !linkLocal.Contains(dest.Addr()) {
			continue
		}
		routes = append(routes, icRoute{Dest: dest, Flags: f[2], Iface: f[3]})
	}
	return routes
}

// parseNetstatDest turns one netstat destination into a prefix: "a.b.c/24"
// (missing octets are zero), "a.b.c.d/32", a host entry "a.b.c.d" (flag H, or
// all four octets) as a /32, and a bare network "a.b" as /8 per octet given.
func parseNetstatDest(s, flags string) (netip.Prefix, bool) {
	addr, bitsText, hasBits := strings.Cut(s, "/")
	octets := strings.Split(addr, ".")
	if len(octets) == 0 || len(octets) > 4 {
		return netip.Prefix{}, false
	}
	var b [4]byte
	for i, o := range octets {
		n, err := strconv.Atoi(o)
		if err != nil || n < 0 || n > 255 {
			return netip.Prefix{}, false
		}
		b[i] = byte(n)
	}
	bits := len(octets) * 8
	switch {
	case hasBits:
		n, err := strconv.Atoi(bitsText)
		if err != nil || n < 0 || n > 32 {
			return netip.Prefix{}, false
		}
		bits = n
	case strings.Contains(flags, "H"):
		bits = 32
	}
	p, err := netip.AddrFrom4(b).Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// parseARPNeighbors reads `arp -an -i bridge0` output ("? (A) at MAC on
// bridge0 ...") and returns the addresses of complete entries inside the
// interconnect subnet.
func parseARPNeighbors(out string) []netip.Addr {
	var addrs []netip.Addr
	for _, line := range strings.Split(out, "\n") {
		lp, rp := strings.IndexByte(line, '('), strings.IndexByte(line, ')')
		if lp < 0 || rp <= lp || strings.Contains(line, "incomplete") {
			continue
		}
		a, err := netip.ParseAddr(line[lp+1 : rp])
		if err == nil && icCIDR.Contains(a) {
			addrs = append(addrs, a)
		}
	}
	return addrs
}

// parsePingRTT reads the average round trip from `ping -c 1` output
// ("round-trip min/avg/max/stddev = 0.612/0.640/0.700/0.020 ms"). A value that
// is not a finite, non-negative number (ParseFloat accepts "NaN" and "Inf") is
// no round trip.
func parsePingRTT(out string) (time.Duration, bool) {
	_, rest, ok := strings.Cut(out, "min/avg/max")
	if !ok {
		return 0, false
	}
	_, nums, ok := strings.Cut(rest, "= ")
	if !ok {
		return 0, false
	}
	fields := strings.Fields(nums)
	if len(fields) == 0 {
		return 0, false
	}
	f := strings.Split(fields[0], "/")
	if len(f) < 2 {
		return 0, false
	}
	ms, err := strconv.ParseFloat(f[1], 64)
	if err != nil || math.IsNaN(ms) || math.IsInf(ms, 0) || ms < 0 {
		return 0, false
	}
	return time.Duration(ms * float64(time.Millisecond)), true
}

// parsePmset reads the "sleep" and "autorestart" lines of `pmset -g`. Only the
// exact keys count: "displaysleep" and "disksleep" are other settings.
func parsePmset(out string) powerSettings {
	var p powerSettings
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		switch f[0] {
		case "sleep":
			p.Sleep, p.HasSleep = n, true
		case "autorestart":
			p.AutoRestart, p.HasAutoRestart = n, true
		}
	}
	return p
}
