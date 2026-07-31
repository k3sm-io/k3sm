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
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"k8s.io/client-go/kubernetes"

	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/ingresshost"
	"k3sm.io/k3sm/pkg/ports"
	"k3sm.io/k3sm/pkg/svclb"
)

// wildcardBindAddr is the address every LoadBalancer and ingress listener binds:
// the IPv4 wildcard, as an EXPLICIT netip.Addr.
//
// It is deliberately NOT the ":port" form. `net.Listen("tcp", ":80")` yields a
// DUAL-STACK [::] socket with IPV6_V6ONLY=0, which would additionally expose the
// listener on every IPv6 link-local/SLAAC address — a surface neither the mesh
// (IPv4 /24 AllowedIPs) nor the ratified parity argument (Docker Desktop's vpnkit
// and k3s' klipper-lb both publish IPv4) covers. netip.AddrFrom4 pins Is4().
var wildcardBindAddr = netip.AddrFrom4([4]byte{})

// statusOwnedPodCIDR is the pod address space whose LoadBalancer/Ingress status
// entries the k3sm controllers own and therefore retract. It is the CLUSTER
// aggregate, not this node's /24, so a node that re-enrolls into a different /24
// still retracts the entry its previous life wrote. Derived from darwin-net's one
// cluster-CIDR constant, so there is no second literal to drift.
func statusOwnedPodCIDR() netip.Prefix {
	return podnet.ClusterPodCIDR
}

// lbHostingConfigs assembles the svclb + ingress-host configurations for one
// node. It is a PURE function of the node's already-resolved options: the whole
// decision — the bind address, the advertise address, the binder selection, the
// reserved-port set and the retraction scope — is made here rather than inline
// inside runServer behind exec.Start, where no unit test can reach it.
//
// The two addresses are DIFFERENT and both are decided here:
//
//   - BindAddr is the IPv4 wildcard. On Darwin a wildcard bind needs no privilege
//     at any port (0.0.0.0:1023 binds as an ordinary uid; 127.0.0.1:1023 returns
//     EACCES — inverted from Linux), so BOTH configs get the ONE in-process binder
//     and neither is handed a privileged netd binder. netd refuses the wildcard by
//     design (an explicit non-goal to change), so wiring it here would fail every
//     listener.
//   - AdvertiseAddr is the node's derived globally-unicast InternalIP —
//     advertisedNodeIP, the SAME function startNode uses, called on the SAME
//     nodeOptions value runServer passes to startNode, so the address kubectl shows
//     as EXTERNAL-IP cannot disagree with the address the Node object carries. When
//     it does not parse (a derivation failure) the advertise address is left ZERO:
//     the listeners still bind, and the controllers write no status at all rather
//     than publishing loopback or the zero Addr's "invalid IP".
//
// It NEVER writes back into the node options: opts is by value, and opts.nodeIP
// feeds the apiserver's --advertise-address/--bind-address in runServer. One
// assignment there would invalidate the loopback admin kubeconfig, empty the
// `kubernetes` VIP's only static backend and change the NetworkPolicy seed.
//
// The port-range checks keep this seam TOTAL (a uint16 conversion would otherwise
// silently truncate 70000 to 4464). runServer also rejects an out-of-range argv at
// flag-parse time; this one holds for any caller of the seam, argv or test.
func lbHostingConfigs(cs kubernetes.Interface, opts nodeOptions, httpPort, httpsPort int, log *slog.Logger) (svclb.Config, ingresshost.Config, error) {
	if httpPort < 0 || httpPort > 65535 {
		return svclb.Config{}, ingresshost.Config{}, fmt.Errorf("--ingress-http-port %d is out of range (0-65535)", httpPort)
	}
	if httpsPort < 0 || httpsPort > 65535 {
		return svclb.Config{}, ingresshost.Config{}, fmt.Errorf("--ingress-https-port %d is out of range (0-65535)", httpsPort)
	}

	// The advertise address is DERIVED, and it may fail: a bad/absent podCIDR
	// yields the raw --node-ip, which may itself be the loopback default on a
	// no-datapath node. A loopback EXTERNAL-IP is worse than none (nothing off
	// this Mac can reach it), so it is not advertised either.
	advertise := netip.Addr{}
	if addr, err := netip.ParseAddr(advertisedNodeIP(opts)); err == nil && !addr.IsLoopback() {
		advertise = addr.Unmap()
	} else {
		log.Warn("loadbalancer/ingress status will stay EMPTY: no advertisable node address could be derived (Services stay <pending>); listeners still bind",
			"node-ip", opts.nodeIP, "pod-cidr", opts.podCIDR, "datapath", opts.netMode.DataPath())
	}

	podCIDR := statusOwnedPodCIDR()
	lb := svclb.Config{
		Client:        cs,
		BindAddr:      wildcardBindAddr,
		AdvertiseAddr: advertise,
		PodCIDR:       podCIDR,
		// The datapath-side half of the reserved-port guard (the admission VAP is
		// the legible half). Same single source as the CEL and the apiserver argv.
		ReservedPorts: ports.ReservedSet(),
		Logger:        log,
	}
	ih := ingresshost.Config{
		Client:        cs,
		BindAddr:      wildcardBindAddr,
		AdvertiseAddr: advertise,
		PodCIDR:       podCIDR,
		HTTPPort:      uint16(httpPort),
		HTTPSPort:     uint16(httpsPort),
		Logger:        log,
	}
	return lb, ih, nil
}

// ensureAdvertisedNodeAlias plumbs the lo0 /32 alias for the address the
// LoadBalancer/Ingress statuses will advertise, BEFORE either controller starts.
//
// Why here and not only in startNode's podnet reconcile (which runs later): a
// wildcard bind cannot witness the advertised address, so the packages' honesty
// contract ("never advertise a dead address") no longer covers reachability. The
// controllers write status as soon as their listeners bind; without this call the
// window between that write and startNode's ReconcileStartup shows an EXTERNAL-IP
// that answers from nowhere — and it fails by TIMEOUT (100.64/10 has no local
// route, so the dial leaves via the default gateway), not the loud EADDRNOTAVAIL
// the old specific bind produced.
//
// It acts ONLY on a DERIVED address (derivedNodeAdvertiseIP): an explicit
// --node-ip or a mesh IP belongs to the operator or the mesh device, and aliasing
// it on lo0 here would make this host answer for an address it must not own.
// EnsureNodeAlias is idempotent and SweepStale deliberately excludes the .1, so
// ReconcileStartup re-ensuring it later inside startNode is a no-op — no liveness
// probe, no ticker, no control-flow inversion.
//
// Log-and-continue: startNode's reconcile is the fail-closed authority for this
// alias. A failure here degrades to the pre-existing window, it does not halt
// bring-up.
func ensureAdvertisedNodeAlias(ctx context.Context, opts nodeOptions, log *slog.Logger) {
	derived := derivedNodeAdvertiseIP(opts)
	if derived == "" {
		return
	}
	addr, err := netip.ParseAddr(derived)
	if err != nil {
		log.Error("advertised node address does not parse; lo0 alias not ensured", "addr", derived, "err", err)
		return
	}
	// A SECOND podnet.Network over the same /24, built through the shared
	// buildPodNetwork so the two constructions cannot drift on podnet.Options.
	// This instance is a stateless throwaway used ONLY for EnsureNodeAlias — see
	// buildPodNetwork's doc for why that is safe and what would make it unsafe.
	// The node's one ALLOCATING Network is still the adapter startNode builds.
	nw, err := buildPodNetwork(opts, log)
	if err != nil {
		log.Error("build pod network for the advertised lo0 alias", "pod-cidr", opts.podCIDR, "err", err)
		return
	}
	if err := nw.EnsureNodeAlias(ctx, addr); err != nil {
		log.Error("ensure advertised node lo0 alias before LB/ingress hosting; the advertised EXTERNAL-IP may not answer until the node's startup reconcile runs",
			"addr", addr.String(), "err", err)
		return
	}
	log.Info("advertised node lo0 alias ensured before LB/ingress hosting", "addr", addr.String())
}
