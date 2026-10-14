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
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/ports"
)

// errLANMismatch is the named failure of a daemon whose listening sockets do
// not match the LAN state it reported applying.
var errLANMismatch = errors.New("the node daemon's listening sockets do not match")

// lanSocketPolicy is what the root CLI checks the node daemon's own TCP
// listening sockets against after the daemon reports an apply. The daemon's
// report is a progress signal only; this is the proof.
type lanSocketPolicy struct {
	want install.LAN
	// lanAddrs are this Mac's network-facing addresses: its interface
	// addresses other than loopback, the cluster pod/mesh range and the vm
	// NAT segment.
	lanAddrs []netip.Addr
	// alwaysOn are the ports allowed on every interface whatever the switch
	// says (the worker join port on a server).
	alwaysOn map[uint16]bool
	// exempt are ports that are not covered listeners (the kubelet API, the
	// ingest registry relay).
	exempt map[uint16]bool
	// ingress are a server's ingress listener ports.
	ingress []uint16
	// nodePortSpec is an explicit --nodeport-addresses: with LAN access on,
	// NodePorts then bind that set rather than the wildcard.
	nodePortSpec bool
}

// isNodePort reports whether port is in the NodePort range.
func isNodePort(port uint16) bool {
	return int(port) >= ports.NodePortRangeMin && int(port) <= ports.NodePortRangeMax
}

// verifyLANSockets checks socks (the daemon's TCP listeners) against p.
//
// Off: no listener outside the always-on ports binds the wildcard or a
// network-facing address of this Mac.
//
// On: every NodePort (unless --nodeport-addresses narrows them) and every
// ingress port the daemon listens on has a wildcard listener, and no other
// covered port is left in the off shape (bound on 127.0.0.1 without the
// wildcard).
func verifyLANSockets(p lanSocketPolicy, socks []netip.AddrPort) error {
	var bad []string
	byPort := map[uint16][]netip.Addr{}
	for _, s := range socks {
		byPort[s.Port()] = append(byPort[s.Port()], s.Addr().Unmap())
	}
	portList := make([]uint16, 0, len(byPort))
	for port := range byPort {
		portList = append(portList, port)
	}
	slices.Sort(portList)
	for _, port := range portList {
		addrs := byPort[port]
		if p.alwaysOn[port] {
			continue
		}
		wild := slices.ContainsFunc(addrs, netip.Addr.IsUnspecified)
		if p.want == install.LANOff {
			for _, a := range addrs {
				switch {
				case a.IsUnspecified():
					bad = append(bad, fmt.Sprintf("port %d listens on every interface", port))
				case slices.Contains(p.lanAddrs, a):
					bad = append(bad, fmt.Sprintf("port %d listens on the network address %s", port, a))
				}
			}
			continue
		}
		if p.exempt[port] || wild {
			continue
		}
		switch {
		case isNodePort(port) && !p.nodePortSpec:
			bad = append(bad, fmt.Sprintf("NodePort %d listens on %s, not on every interface", port, addrsString(addrs)))
		case slices.Contains(p.ingress, port):
			bad = append(bad, fmt.Sprintf("ingress port %d listens on %s, not on every interface", port, addrsString(addrs)))
		case !isNodePort(port) && slices.ContainsFunc(addrs, netip.Addr.IsLoopback):
			bad = append(bad, fmt.Sprintf("port %d still listens only on %s", port, addrsString(addrs)))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w LAN access %s: %s", errLANMismatch, p.want, strings.Join(bad, "; "))
	}
	return nil
}

// addrsString renders addresses for a message.
func addrsString(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ",")
}

// lanFacingAddrs filters this Mac's interface addresses to the ones a LAN
// peer can reach: not loopback, not the cluster pod and mesh range, not the vm
// NAT segment.
func lanFacingAddrs(host []netip.Addr) []netip.Addr {
	vmnet, _ := netip.ParsePrefix(netserve.DefaultVMNetSubnet)
	var out []netip.Addr
	for _, a := range host {
		a = a.Unmap()
		if !a.IsValid() || a.IsLoopback() || a.IsUnspecified() || podnet.ClusterPodCIDR.Contains(a) || (vmnet.IsValid() && vmnet.Contains(a)) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// lanPolicyFor builds the policy for role from the installed node daemon's
// arguments and this Mac's addresses.
func lanPolicyFor(want install.LAN, role install.Role, args []string, host []netip.Addr) lanSocketPolicy {
	p := lanSocketPolicy{
		want:         want,
		lanAddrs:     lanFacingAddrs(host),
		alwaysOn:     map[uint16]bool{},
		exempt:       map[uint16]bool{uint16(ports.KubeletAPIPort): true},
		nodePortSpec: strings.TrimSpace(install.ServerArgValue(args, nodePortAddressesFlag)) != "",
	}
	if role == install.RoleAgent {
		return p
	}
	p.alwaysOn[install.JoinBootstrapPort] = true
	argPort := func(name string, def int) int {
		if v, err := strconv.Atoi(install.ServerArgValue(args, name)); err == nil {
			return v
		}
		return def
	}
	if kp := argPort("kubelet-port", ports.KubeletAPIPort); kp > 0 && kp < 65536 {
		p.exempt[uint16(kp)] = true
	}
	if rp := argPort("registry-port", 0); rp > 0 && rp < 65536 {
		p.exempt[uint16(rp)] = true
	}
	for _, ip := range []int{argPort("ingress-http-port", 80), argPort("ingress-https-port", 443)} {
		if ip > 0 && ip < 65536 {
			p.ingress = append(p.ingress, uint16(ip))
		}
	}
	return p
}

// lsofListeners is the production socket lister: the TCP listening sockets
// of pid, read with lsof as root. lsof exiting 1 with no output means none.
func lsofListeners(ctx context.Context, pid int) ([]netip.AddrPort, error) {
	cmd := exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-a", "-p", strconv.Itoa(pid), "-iTCP", "-sTCP:LISTEN", "-Fn")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 && len(out) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("lsof -p %d: %w: %s", pid, err, strings.TrimSpace(stderr.String()))
	}
	return parseLsofListeners(out)
}

// parseLsofListeners parses lsof -F n output: one "n<host>:<port>" line per
// socket, "*" being the wildcard.
func parseLsofListeners(out []byte) ([]netip.AddrPort, error) {
	var socks []netip.AddrPort
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "n") {
			continue
		}
		name := strings.TrimPrefix(line, "n")
		i := strings.LastIndex(name, ":")
		if i < 0 {
			return nil, fmt.Errorf("lsof: unparseable socket name %q", name)
		}
		host, portStr := strings.Trim(name[:i], "[]"), name[i+1:]
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("lsof: unparseable port in %q", name)
		}
		addr := netip.IPv4Unspecified()
		if host != "*" {
			if addr, err = netip.ParseAddr(host); err != nil {
				return nil, fmt.Errorf("lsof: unparseable address in %q", name)
			}
		}
		socks = append(socks, netip.AddrPortFrom(addr, uint16(port)))
	}
	return socks, sc.Err()
}
