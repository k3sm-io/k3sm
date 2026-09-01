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
	"net"
	"net/netip"
	"os/exec"

	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/hostnet"
)

// meshAliasOps are the two environment-touching legs of the mesh-IP alias ensure,
// named so the decision above them is unit-testable without root and without a
// live k3sm-netd.
//
// plumb is NIL when this process has no privileged path to lo0 at all (`--network
// none`), which is a distinct outcome from a plumb that fails: nothing is wrong
// with the datapath, there simply is not one, and the operator has to be told to
// plumb the address by hand.
type meshAliasOps struct {
	// present reports whether ip is already assigned to some interface on this
	// host. It short-circuits every mode, which is what makes a loopback mesh IP
	// (the single-host posture) and a restart over a live alias free.
	present func(netip.Addr) (bool, error)
	// plumb adds ip as a /32 lo0 alias. nil means this mode has no privileged
	// path to lo0.
	plumb func(context.Context, netip.Addr) error
}

// hostAliasOps selects the alias legs for a resolved --network backend, mirroring
// the same split every other privileged lo0 operation in this binary follows: the
// root k3sm-netd helper when unprivileged, the direct ifconfig-equivalent as root,
// and nothing at all under `--network none`.
func hostAliasOps(mode hostnet.Mode) meshAliasOps {
	ops := meshAliasOps{present: addrIsLocal}
	switch {
	case mode.UsesHelper():
		// The daemon's alias policy admits an address inside this node's pod /24
		// (its --node-pod-cidr default is the index-0 100.64.0.0/24), which is
		// exactly where a control-plane mesh IP lives.
		ops.plumb = func(ctx context.Context, ip netip.Addr) error {
			return wire.NewClient(mode.Socket).EnsureAlias(ctx, ip)
		}
	case mode.DataPath():
		ops.plumb = plumbLo0Alias
	}
	return ops
}

// ensureMeshIPAlias makes the mesh IP an address this host answers on, BEFORE the
// control plane is started against it.
//
// It exists because the apiserver binds --mesh-ip as its secure serving address
// while the only thing that ever plumbed that address was mesh.Start, several
// bring-up steps LATER. The first real `--mesh-ip 100.64.0.1` boot therefore died
// with `listen tcp 100.64.0.1:6444: bind: can't assign requested address`, and a
// human had to `ifconfig lo0 alias 100.64.0.1/32` by hand to get past it. The
// M14.2 lab tier had masked it by booting with --mesh-ip 127.0.0.1, an address
// every host already answers on.
//
// It is FAIL-FAST, unlike the log-and-continue mesh device bring-up further down:
// that stage degrades a working control plane to one with no cross-node path,
// whereas an unbindable serving address means no control plane comes up at all,
// so continuing only buys a more confusing error later.
//
// meshIP empty is the single-node posture: it returns before touching anything, so
// this call adds no failure mode to the single-node bring-up path.
//
// The mesh device's own alias plumb runs again later over whatever this leaves;
// both the direct (`ifconfig lo0 alias`) and helper (netd EnsureAlias) forms are
// idempotent on Darwin by design, so the second write is a no-op success.
func ensureMeshIPAlias(ctx context.Context, meshIP string, mode hostnet.Mode, logger *slog.Logger) error {
	return ensureMeshIPAliasWith(ctx, meshIP, hostAliasOps(mode), logger)
}

// ensureMeshIPAliasWith is the testable core of ensureMeshIPAlias.
func ensureMeshIPAliasWith(ctx context.Context, meshIP string, ops meshAliasOps, logger *slog.Logger) error {
	if meshIP == "" {
		return nil
	}
	ip, err := netip.ParseAddr(meshIP)
	if err != nil {
		return fmt.Errorf("--mesh-ip %q is not an IP address: %w", meshIP, err)
	}
	have, err := ops.present(ip)
	if err != nil {
		return fmt.Errorf("check whether this host answers on --mesh-ip %s: %w", ip, err)
	}
	if have {
		if logger != nil {
			logger.Info("mesh IP is already assigned to this host", "mesh-ip", ip.String())
		}
		return nil
	}
	if ops.plumb == nil {
		return fmt.Errorf("--mesh-ip %s is not assigned to any interface and --network none runs no privileged datapath to plumb it; "+
			"the apiserver and the worker-join supervisor both bind this address, so bring-up would die on \"bind: can't assign requested address\". "+
			"Run `sudo ifconfig lo0 alias %s/32` first, or use --network auto", ip, ip)
	}
	if err := ops.plumb(ctx, ip); err != nil {
		return fmt.Errorf("plumb --mesh-ip %s as an lo0 alias: %w; "+
			"the apiserver and the worker-join supervisor both bind this address. "+
			"Run `sudo ifconfig lo0 alias %s/32` by hand, or check the root helper (`launchctl print system/io.k3sm.netd`)", ip, err, ip)
	}
	if logger != nil {
		logger.Info("plumbed the mesh IP as an lo0 alias before control-plane bring-up", "mesh-ip", ip.String())
	}
	return nil
}

// addrIsLocal reports whether ip is assigned to any interface on this host. It
// reads the live interface list rather than tracking what this process plumbed,
// because the address may equally have been plumbed by a previous run, by the
// installer, or (loopback) by the kernel.
func addrIsLocal(ip netip.Addr) (bool, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, fmt.Errorf("list interface addresses: %w", err)
	}
	for _, a := range addrs {
		var have netip.Addr
		switch v := a.(type) {
		case *net.IPNet:
			have, _ = netip.AddrFromSlice(v.IP)
		case *net.IPAddr:
			have, _ = netip.AddrFromSlice(v.IP)
		default:
			continue
		}
		if have.Unmap() == ip.Unmap() {
			return true, nil
		}
	}
	return false, nil
}

// plumbLo0Alias adds ip as a /32 lo0 alias with ifconfig — the direct, root-gated
// form of the operation netd performs on the caller's behalf in helper mode. It is
// the same invocation darwin-net's mesh device and pkg/install use, kept here
// rather than reached for sideways because this is the one caller that must run
// before any mesh or proxy object exists.
func plumbLo0Alias(ctx context.Context, ip netip.Addr) error {
	out, err := exec.CommandContext(ctx, "ifconfig", "lo0", "alias", fmt.Sprintf("%s/32", ip)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig lo0 alias %s/32: %w: %s", ip, err, out)
	}
	return nil
}
