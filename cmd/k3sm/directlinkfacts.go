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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"

	"k3sm.io/k3sm/pkg/status"
)

// directLinkFacts is what the node's advisory direct-link labels are derived from:
// one enumeration of the node's Thunderbolt ports plus the RDMA probe.
type directLinkFacts struct {
	// Ports is how many Thunderbolt network ports the node has.
	Ports int
	// SpeedGbps is the fastest port's speed (0 = unknown).
	SpeedGbps int
	// RDMA is true iff RDMA is enabled (rdma_ctl) AND at least one port has an
	// rdma_enX device.
	RDMA bool
}

// factsFromPorts derives the label facts from an enumeration and the rdma_ctl
// verdict.
func factsFromPorts(ports []linkenum.Port, rdmaEnabled bool) directLinkFacts {
	f := directLinkFacts{Ports: len(ports)}
	anyDevice := false
	for _, p := range ports {
		if p.SpeedGbps > f.SpeedGbps {
			f.SpeedGbps = p.SpeedGbps
		}
		if p.RDMADevice != "" {
			anyDevice = true
		}
	}
	f.RDMA = rdmaEnabled && anyDevice
	return f
}

// nodeDirectLinkFacts is the latest enumeration's facts, read by configureNode.
// It is set by the node's direct-link loop before the node registers and on every
// re-enumeration; nil (no loop, no ports) sets no direct-link label.
var nodeDirectLinkFacts atomic.Pointer[directLinkFacts]

// applyDirectLinkLabels sets the advisory direct-link labels with the
// presence-only discipline the other capability labels use: a node with no
// Thunderbolt port carries none of them, and a capability that goes away removes
// its label. They are ADVISORY: a node can label itself anything under k3sm.io,
// so placement reads DirectLink.status, never these.
func applyDirectLinkLabels(n *corev1.Node, f *directLinkFacts) {
	ports, medium, speed := "", "", ""
	if f != nil && f.Ports > 0 {
		ports, medium = strconv.Itoa(f.Ports), netv1alpha1.MediumThunderbolt
		if f.SpeedGbps > 0 {
			speed = strconv.Itoa(f.SpeedGbps)
		}
	}
	setLabelValue(n, netv1alpha1.LabelDirectLinkPorts, ports)
	setLabelValue(n, netv1alpha1.LabelDirectLinkMedium, medium)
	setLabelValue(n, netv1alpha1.LabelDirectLinkSpeedGbps, speed)
	setLabelPresence(n, netv1alpha1.LabelRDMA, f != nil && f.Ports > 0 && f.RDMA)
}

// rdmaCtlPath is the RDMA control tool (TN3205). It is run, never linked.
const rdmaCtlPath = "/usr/bin/rdma_ctl"

// probeRDMAEnabled reports whether `rdma_ctl status` says enabled. A missing tool
// or any failure is "not enabled": the label is presence-only and fails closed.
func probeRDMAEnabled() bool {
	out, err := exec.Command(rdmaCtlPath, "status").Output()
	if err != nil {
		return false
	}
	return parseRDMACtlStatus(out)
}

// parseRDMACtlStatus reads rdma_ctl's verdict: enabled iff the output says
// "enabled" and not "disabled".
func parseRDMACtlStatus(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "enabled") && !strings.Contains(s, "disabled")
}

// tunnelOnlyFile is the node-local per-port tunnel-only override `k3sm link
// tunnel-only` writes, under the role's work dir.
const tunnelOnlyFile = "direct-link-tunnel-only.json"

// tunnelOnlyOverrides is that file: explicit per-interface values, and an
// optional value for every port ("all"). An explicit interface entry wins over
// "all", and either wins over the DirectLink object's own spec (an
// administrator's `kubectl patch`), which applies when the file says nothing.
type tunnelOnlyOverrides struct {
	All    *bool           `json:"all,omitempty"`
	Ifaces map[string]bool `json:"ifaces,omitempty"`
}

func (o tunnelOnlyOverrides) resolve(iface string, object bool) bool {
	if v, ok := o.Ifaces[iface]; ok {
		return v
	}
	if o.All != nil {
		return *o.All
	}
	return object
}

// readTunnelOnly reads the override file; an absent file is no override.
func readTunnelOnly(path string) (tunnelOnlyOverrides, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return tunnelOnlyOverrides{}, nil
	}
	if err != nil {
		return tunnelOnlyOverrides{}, err
	}
	var o tunnelOnlyOverrides
	if err := json.Unmarshal(b, &o); err != nil {
		return tunnelOnlyOverrides{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return o, nil
}

// directLinkStatusFile is where a node's direct-link loop records its own
// DirectLink as last resolved, for `k3sm doctor` and `k3sm status` to read without
// a cluster client. It is not a secret: it carries port names, addresses and
// states, so it is world-readable.
const directLinkStatusFile = "direct-link-status.json"

// writeDirectLinkStatus records the node's DirectLink beside its work dir.
func writeDirectLinkStatus(workDir string, dl *netv1alpha1.DirectLink) error {
	b, err := json.MarshalIndent(dl, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(workDir, directLinkStatusFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readDirectLinkStatus reads the first recorded DirectLink among dirs.
func readDirectLinkStatus(dirs ...string) (*netv1alpha1.DirectLink, bool) {
	for _, d := range dirs {
		b, err := os.ReadFile(filepath.Join(d, directLinkStatusFile))
		if err != nil {
			continue
		}
		var dl netv1alpha1.DirectLink
		if json.Unmarshal(b, &dl) == nil {
			return &dl, true
		}
	}
	return nil, false
}

// directLinkProbe is everything the doctor section and the status row read about
// this Mac's direct links. Every field is a value so the renderers are pure.
type directLinkProbe struct {
	// EnumErr is the enumeration's error (ErrNoThunderboltService: no port).
	EnumErr error
	Ports   []linkenum.Port
	// BridgeMembers are bridge0's members (nil: no bridge0).
	BridgeMembers map[string]bool
	// RDMAEnabled is rdma_ctl's verdict.
	RDMAEnabled bool
	// Object is the node's DirectLink as last resolved, when one is recorded.
	Object *netv1alpha1.DirectLink
	// IdleSleepOff, AutoLogin and AutoRestart are the three TN3205 cluster
	// settings; a nil pointer is "could not tell".
	IdleSleepOff *bool
	AutoLogin    *bool
	AutoRestart  *bool
}

// realDirectLinkProbe gathers the probe on this Mac. Every command is a plain
// system executable run by absolute path with no privilege.
func realDirectLinkProbe(ctx context.Context, statusDirs ...string) directLinkProbe {
	var p directLinkProbe
	p.Ports, p.EnumErr = linkenum.Exec{}.Ports(ctx)
	p.BridgeMembers = probeBridgeMembers()
	p.RDMAEnabled = probeRDMAEnabled()
	p.Object, _ = readDirectLinkStatus(statusDirs...)
	if out, err := exec.Command("/usr/bin/pmset", "-g").Output(); err == nil {
		sleep, restart := parsePmset(out)
		p.IdleSleepOff, p.AutoRestart = sleep, restart
	}
	if out, err := exec.Command("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser").Output(); err == nil {
		v := strings.TrimSpace(string(out)) != ""
		p.AutoLogin = &v
	} else {
		v := false
		p.AutoLogin = &v
	}
	return p
}

// probeBridgeMembers reads `ifconfig bridge0`'s members; nil when there is no
// bridge0.
func probeBridgeMembers() map[string]bool {
	out, err := exec.Command("/sbin/ifconfig", "bridge0").Output()
	if err != nil {
		return nil
	}
	return parseBridgeMembers(out)
}

// parseBridgeMembers reads the "member: enX flags=..." lines of `ifconfig bridge0`.
func parseBridgeMembers(out []byte) map[string]bool {
	m := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "member:" {
			m[f[1]] = true
		}
	}
	return m
}

// parsePmset reads `pmset -g`: idle sleep is off when "sleep" is 0, and the Mac
// starts after a power failure when "autorestart" is 1.
func parsePmset(out []byte) (sleepOff, autoRestart *bool) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "sleep":
			v := f[1] == "0"
			sleepOff = &v
		case "autorestart":
			v := f[1] == "1"
			autoRestart = &v
		}
	}
	return sleepOff, autoRestart
}

// cabled returns the ports with something cabled to them.
func (p directLinkProbe) cabled() []linkenum.Port {
	var out []linkenum.Port
	for _, port := range p.Ports {
		if port.PeerDomainUUID != "" {
			out = append(out, port)
		}
	}
	return out
}

// portStatus returns the recorded resolved status of an interface.
func (p directLinkProbe) portStatus(iface string) (netv1alpha1.DirectLinkPortStatus, bool) {
	if p.Object == nil {
		return netv1alpha1.DirectLinkPortStatus{}, false
	}
	for _, s := range p.Object.Status.Ports {
		if s.Iface == iface {
			return s, true
		}
	}
	return netv1alpha1.DirectLinkPortStatus{}, false
}

// upCount is the number of recorded up ports.
func (p directLinkProbe) upCount() int {
	n := 0
	if p.Object != nil {
		for _, s := range p.Object.Status.Ports {
			if s.State == netv1alpha1.DirectLinkStateUp {
				n++
			}
		}
	}
	return n
}

// lastTransition is the latest recorded port transition.
func (p directLinkProbe) lastTransition() (time.Time, bool) {
	var last time.Time
	if p.Object == nil {
		return last, false
	}
	for _, s := range p.Object.Status.Ports {
		if s.LastTransition != nil && s.LastTransition.After(last) {
			last = s.LastTransition.Time
		}
	}
	return last, !last.IsZero()
}

// maxSpeed is the fastest port's speed.
func (p directLinkProbe) maxSpeed() int {
	s := 0
	for _, port := range p.Ports {
		if port.SpeedGbps > s {
			s = port.SpeedGbps
		}
	}
	return s
}

// rdmaDevices reports whether any port has an RDMA device.
func (p directLinkProbe) rdmaDevices() bool {
	for _, port := range p.Ports {
		if port.RDMADevice != "" {
			return true
		}
	}
	return false
}

// rdmaRecoveryRemedy is the exact, printed-never-attempted Recovery step (TN3205).
const rdmaRecoveryRemedy = "RDMA is enabled once per Mac in macOS Recovery: shut down, hold the power button to open Recovery, choose Utilities > Terminal, run `rdma_ctl enable`, and restart. k3sm never attempts this."

// directLinkChecks are the doctor's direct-link section, in order. Each row is
// pure over the probe.
func directLinkChecks(p directLinkProbe) []checkResult {
	rows := []checkResult{directLinkPortsCheck(p), directLinkBridgeCheck(p), directLinkRDMACheck(p)}
	return append(rows, directLinkSettingsChecks(p)...)
}

func directLinkPortsCheck(p directLinkProbe) checkResult {
	r := checkResult{name: "direct-links"}
	if errors.Is(p.EnumErr, linkenum.ErrNoThunderboltService) || (p.EnumErr == nil && len(p.Ports) == 0) {
		r.status, r.detail = statusSkip, "no Thunderbolt network port is listed (a Mac without one, or its Thunderbolt Bridge service was deleted in System Settings)"
		return r
	}
	if p.EnumErr != nil {
		r.status, r.detail = statusWarn, fmt.Sprintf("the Thunderbolt ports could not be enumerated: %v", p.EnumErr)
		r.remedy = "run `/usr/sbin/system_profiler SPThunderboltDataType` and `/usr/sbin/networksetup -listallhardwareports` to see what this Mac reports"
		return r
	}
	var parts []string
	unknown := 0
	for _, port := range p.Ports {
		desc := fmt.Sprintf("%s (Thunderbolt %d, %d Gb/s)", port.Iface, port.PortOrdinal+1, port.SpeedGbps)
		switch st, ok := p.portStatus(port.Iface); {
		case port.PeerDomainUUID == "":
			desc += " nothing cabled"
		case ok && st.State == netv1alpha1.DirectLinkStateUp:
			desc += fmt.Sprintf(" up to %s via %s, PLAINTEXT", st.PeerNodeName, st.PeerLinkIP)
		case ok && st.State == netv1alpha1.DirectLinkStatePeerUnknown:
			desc += " cabled to a Mac that is not in this cluster"
			unknown++
		case ok:
			desc += fmt.Sprintf(" cabled, %s", st.State)
			if st.PeerNodeName != "" {
				desc += " (peer " + st.PeerNodeName + ")"
			}
		default:
			desc += " cabled, not yet resolved by the control plane"
		}
		parts = append(parts, desc)
	}
	r.status, r.detail = statusPass, strings.Join(parts, "; ")
	if last, ok := p.lastTransition(); ok {
		r.detail += "; last transition " + last.UTC().Format(time.RFC3339)
	}
	if unknown > 0 {
		r.status = statusWarn
		r.remedy = "a cabled Mac is not a member: on the control plane run `sudo k3sm pair --for 10m`, and on that Mac `sudo k3sm install --auto-join` (see docs/user/direct-links.md)"
	}
	return r
}

func directLinkBridgeCheck(p directLinkProbe) checkResult {
	r := checkResult{name: "direct-link-bridge"}
	cabled := p.cabled()
	if len(cabled) == 0 {
		r.status, r.detail = statusSkip, "no cabled Thunderbolt port"
		return r
	}
	if p.BridgeMembers == nil {
		r.status, r.detail = statusPass, "there is no bridge0; every cabled port is free of it"
		return r
	}
	var in []string
	for _, port := range cabled {
		if p.BridgeMembers[port.Iface] {
			in = append(in, port.Iface)
		}
	}
	sort.Strings(in)
	if len(in) == 0 {
		r.status, r.detail = statusPass, "every cabled port is out of bridge0 (k3sm keeps it out; `sudo k3sm link reset` puts it back)"
		return r
	}
	r.status = statusWarn
	r.detail = fmt.Sprintf("cabled port(s) %s are still members of bridge0, so they carry no direct route", strings.Join(in, ", "))
	r.remedy = "check that this Mac is a joined node and that io.k3sm.netd is running (`sudo launchctl print system/io.k3sm.netd`); the node takes cabled ports out of the bridge itself"
	return r
}

func directLinkRDMACheck(p directLinkProbe) checkResult {
	r := checkResult{name: "rdma"}
	switch {
	case len(p.Ports) == 0:
		r.status, r.detail = statusSkip, "no Thunderbolt network port"
	case p.RDMAEnabled && p.rdmaDevices():
		r.status, r.detail = statusPass, "enabled, with an RDMA device on a Thunderbolt port"
	case p.maxSpeed() < 80:
		r.status, r.detail = statusPass, fmt.Sprintf("not available: RDMA over Thunderbolt needs Thunderbolt 5 and macOS 26.2 or later, and this Mac's ports report %d Gb/s", p.maxSpeed())
	case !p.RDMAEnabled:
		r.status, r.detail = statusWarn, "disabled on a Thunderbolt 5 Mac"
		r.remedy = rdmaRecoveryRemedy
	default:
		r.status, r.detail = statusWarn, "enabled, but no rdma_enX device is listed"
		r.remedy = "run `/usr/bin/ibv_devices`; both ends of a cable must have RDMA enabled"
	}
	return r
}

func directLinkSettingsChecks(p directLinkProbe) []checkResult {
	type setting struct {
		name, good, bad, remedy string
		v                       *bool
	}
	settings := []setting{
		{"idle-sleep", "idle sleep is off", "idle sleep is on: a sleeping Mac stops answering on its cable (Thunderbolt has no wake-on-LAN), and its peers fall back to the tunnel", "sudo pmset -a sleep 0", p.IdleSleepOff},
		{"auto-login", "automatic login is on", "automatic login is off: after a restart this Mac waits at the login window", "System Settings > Users & Groups > Automatically log in as", p.AutoLogin},
		{"power-restart", "the Mac starts after a power failure", "the Mac stays off after a power failure", "sudo pmset -a autorestart 1", p.AutoRestart},
	}
	var out []checkResult
	cabled := len(p.cabled()) > 0
	for _, s := range settings {
		r := checkResult{name: s.name}
		switch {
		case !cabled:
			r.status, r.detail = statusSkip, "no cabled Thunderbolt port; a cluster setting only a cabled Mac needs"
		case s.v == nil:
			r.status, r.detail = statusSkip, "could not be read"
		case *s.v:
			r.status, r.detail = statusPass, s.good
		default:
			r.status, r.detail, r.remedy = statusWarn, s.bad, s.remedy
		}
		out = append(out, r)
	}
	return out
}

// directLinkStatusLine is the `k3sm status` links row: the count of links up, the
// medium and speed, the PLAINTEXT state, and RDMA. It is the one place outside a
// Node Event the plaintext state is shown to an operator by default (R3).
func directLinkStatusLine(p directLinkProbe) (string, bool) {
	if len(p.Ports) == 0 {
		return "", false
	}
	up := p.upCount()
	rdma := "no"
	if p.RDMAEnabled && p.rdmaDevices() {
		rdma = "yes"
	}
	state := "plaintext"
	if up == 0 {
		state = "none up"
	}
	return fmt.Sprintf("direct links: %d up (%s, %d Gb/s, %s) · rdma: %s", up, netv1alpha1.MediumThunderbolt, p.maxSpeed(), state, rdma), true
}

// recordedDirectLinkProbe is the cheap probe `k3sm status` uses: only the node's
// recorded DirectLink (no system_profiler on every screen refresh) and rdma_ctl.
// The ports are the recorded spec's.
func recordedDirectLinkProbe(dirs ...string) directLinkProbe {
	var p directLinkProbe
	p.Object, _ = readDirectLinkStatus(dirs...)
	if p.Object != nil {
		for _, sp := range p.Object.Spec.Ports {
			p.Ports = append(p.Ports, linkenum.Port{
				Iface: sp.Iface, PortOrdinal: int(sp.PortOrdinal), DomainUUID: sp.DomainUUID,
				PeerDomainUUID: sp.PeerDomainUUID, SpeedGbps: int(sp.SpeedGbps), RDMADevice: sp.RDMADevice,
			})
		}
		p.RDMAEnabled = p.rdmaDevices() && probeRDMAEnabled()
	}
	return p
}

// directLinkStatusRowName is the links row's name on the status screen.
const directLinkStatusRowName = "direct-links"

// withDirectLinkRow appends the links row to a status report when this node has
// direct-link ports. The row is informational (severity OK): it never changes the
// verdict, it makes the plaintext state visible.
func withDirectLinkRow(rep status.Report, p directLinkProbe) status.Report {
	line, ok := directLinkStatusLine(p)
	if !ok {
		return rep
	}
	state := status.RowState("plaintext")
	if p.upCount() == 0 {
		state = status.RowState("none-up")
	}
	rep.Rows = append(rep.Rows, status.Row{Name: directLinkStatusRowName, State: state, Severity: status.SeverityOK, Detail: line})
	return rep
}
