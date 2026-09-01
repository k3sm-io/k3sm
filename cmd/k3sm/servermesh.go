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
	"os"
	"path/filepath"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/mesh"

	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/install"
)

// serverMeshKeyRef is the file name, under both the server work dir and the
// root-only mesh key dir, holding this control-plane node's wireguard private
// key. It is DISTINCT from the agent's meshKeyRef so a server and a joined
// worker on one Mac (the single-host acceptance posture) never overwrite each
// other's identity in install.MeshKeyDir.
const serverMeshKeyRef = "server.key"

// serverMeshListenPort is the UDP port the control-plane node's wireguard
// listens on. It is the SAME default `k3sm agent --mesh-port` carries, and is
// deliberately not an operator flag on the server: a worker dials the server's
// endpoint from the MeshPeer this node writes, so the two must agree and there
// is exactly one value that makes them agree without a second knob.
const serverMeshListenPort = mesh.DefaultListenPort

// loadOrCreateServerMeshKey returns the CONTROL-PLANE node's persisted wireguard
// identity, minting it under workDir on first run. It is loadOrCreateMeshKey
// named at this node role's ref — the server and a worker on one Mac must not
// share a key file (serverMeshKeyRef).
func loadOrCreateServerMeshKey(workDir string) (privB64, pubB64 string, err error) {
	return loadOrCreateMeshKey(workDir, serverMeshKeyRef)
}

// serverMeshEndpoint is the address:port a joining worker dials to reach this
// server's wireguard listener.
//
// It is an UNDERLAY address by necessity, not by preference: a worker has no
// mesh until this handshake completes, so an endpoint inside the mesh would be
// unreachable at exactly the moment it is needed. The derivation is the same
// globally-unicast host-interface pick the node's own advertise path uses,
// falling back to the configured node IP when the host offers none (a
// single-host cluster, where loopback is a legitimate wireguard endpoint).
func serverMeshEndpoint(nodeIP string, port int) string {
	host := firstProxyableIP(hostInterfaceIPs())
	if host == "" {
		host = nodeIP
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

// meshBringUp is the DISCRETE input to bringUpMesh: everything the wireguard
// device needs, and nothing about where it came from.
//
// The fields are spelled out rather than passed as a *bootstrap.JoinResult
// because the server synthesizes them LOCALLY — it never joins anything and has
// no JoinResult. Reusing the wire DTO here would invite a later reader to assume
// the trust properties a JoinResult carries (delivery over the CA-pinned
// PinnedClient, a server-signed peer snapshot), none of which hold on this path.
type meshBringUp struct {
	// podCIDR is this node's assigned /24 — the mesh's self prefix, which is
	// also its sole AllowedIPs entry and its pod IPAM range.
	podCIDR string
	// meshIP is the mesh-egress /32 the caller expects podCIDR to derive. It is
	// ASSERTED against the device's own derivation, never used to configure it:
	// a mismatch means the caller's enroll and the mesh disagree about which
	// node this is, which must fail loudly rather than half-configure.
	meshIP string
	// privateKeyB64 is this node's wireguard private key. In helper mode it is
	// provisioned to the root-only dir under keyRef and never crosses the netd
	// socket.
	privateKeyB64 string
	// keyRef is the bare file name the netd MeshKeyResolver resolves in helper
	// mode.
	keyRef string
	// peers is the initial peer snapshot programmed before the watch takes over.
	peers []netv1.MeshPeerSpec
	// listenPort is the UDP port this node's wireguard binds.
	listenPort int
	// kubeconfig authenticates the MeshPeer watch that keeps the peer set
	// converging after the initial program.
	kubeconfig string
}

// provisionHelperKey writes the private key to the root-only path the netd
// MeshKeyResolver reads, best-effort: in the pure _k3sm posture that directory
// is privileged, so a privileged install/netd step owns provisioning and this
// process passes only the ref.
func (in meshBringUp) provisionHelperKey(logger *slog.Logger) {
	path := filepath.Join(install.MeshKeyDir, in.keyRef)
	if err := os.WriteFile(path, []byte(in.privateKeyB64), 0o600); err != nil {
		logger.Warn("could not provision mesh private key to the root-only path (provision it via the privileged install step)", "path", path, "err", err)
	}
}

// enrollSelfAndBringUpMesh is the control-plane node's own mesh join: it loads
// (or mints) this node's persistent wireguard identity, asserts-or-creates its
// index-0 MeshPeer through the SAME locked enroller the worker-join RPC uses,
// and brings the wireguard device up against the peer snapshot the enroll
// returned.
//
// It returns the enrolled identity so the caller can seed the node-local
// datapath with the mesh-egress source the proxy binds and the peer mesh-egress
// /32s the NetworkPolicy table always-allows.
//
// It is SYNCHRONOUS and returns only once the enroll has been list-back
// verified, because the caller must not open the worker-join listener until this
// node's index-0 claim is durable: a worker joining in that window would be
// assigned index 0 by the free-index scanner and two peers would claim one
// AllowedIPs, which wireguard cannot admit.
//
// The ENROLL runs on every mesh-path bring-up, including `--network none`: the
// index-0 claim is what keeps a worker's assignment off this node's /24, and that
// is true whether or not this process plumbs a wireguard device. Only the DEVICE
// bring-up is gated on the datapath.
func enrollSelfAndBringUpMesh(ctx context.Context, e *meshEnroller, opts serverOptions, mode hostnet.Mode, kubeconfig string, logger *slog.Logger) (netv1.MeshEnrollResponse, error) {
	priv, pub, err := loadOrCreateServerMeshKey(opts.workDir)
	if err != nil {
		return netv1.MeshEnrollResponse{}, err
	}
	res, err := e.EnrollSelf(ctx, opts.nodeName, netv1.MeshEnrollRequest{
		NodeName:  opts.nodeName,
		PublicKey: pub,
		Endpoint:  serverMeshEndpoint(opts.nodeIP, serverMeshListenPort),
	})
	if err != nil {
		return netv1.MeshEnrollResponse{}, err
	}
	logger.Info("enrolled this control-plane node into its own mesh",
		"node", opts.nodeName, "podCIDR", res.PodCIDR, "meshIP", res.MeshIP, "peers", len(res.Peers))
	if !mode.DataPath() {
		logger.Info("network datapath disabled (--network none): the index-0 MeshPeer is written, but this process brings up no wireguard device")
		return res, nil
	}
	if err := bringUpMesh(ctx, meshBringUp{
		podCIDR:       res.PodCIDR,
		meshIP:        res.MeshIP,
		privateKeyB64: priv,
		keyRef:        serverMeshKeyRef,
		peers:         res.Peers,
		listenPort:    serverMeshListenPort,
		kubeconfig:    kubeconfig,
	}, mode, logger); err != nil {
		return netv1.MeshEnrollResponse{}, err
	}
	return res, nil
}
