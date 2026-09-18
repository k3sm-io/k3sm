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
	"strconv"
	"strings"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/install"
)

// serverMeshKeyRef is the file name, under both the server work dir and the
// root-only mesh key dir, holding this control-plane node's wireguard private
// key. It is DISTINCT from the agent's meshKeyRef so a server and a joined
// worker on one Mac (the single-host acceptance posture) never overwrite each
// other's identity in install.MeshKeyDir.
//
// Like the agent's, it is pkg/install's constant: the privileged install
// provisions both copies under this name, and cmd must not spell it a second
// time.
const serverMeshKeyRef = install.MeshKeyRefServer

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

// serverNodePasswordRef is the file name, under the server work dir, holding the
// CONTROL-PLANE node's own node-password. It is spelled differently from the
// agent's node-password file for the reason serverMeshKeyRef is: a server and a
// joined worker can share one Mac, and two roles must never read each other's
// credential because a directory was pointed at both.
const serverNodePasswordRef = "server.node-password"

// loadOrCreateServerNodePassword returns the CONTROL-PLANE node's persisted
// node-password, minting a fresh high-entropy one 0600 under workDir on first
// run — the server-side twin of the agent's loadOrCreateNodePassword.
//
// LOAD-OR-CREATE, not create: the node-password store binds a name to the FIRST
// password it is shown and verifies every later presentation against that bcrypt
// hash. In the HA posture that store is a Secret on the shared datastore, so it
// outlives this process. A value re-minted on each start would therefore bind on
// the first boot and be REFUSED on the second — this node's own name would be
// unusable to it, and the failure would surface as a mesh bring-up error on a
// daemon restart, long after the change that caused it. Persisting the value is
// what makes the binding survive `launchctl kickstart`.
//
// An unreadable file is an ERROR, never a re-mint, for the same reason: a fresh
// password would walk straight into the mismatch above and destroy the evidence
// of whatever damaged the file.
func loadOrCreateServerNodePassword(workDir string) (string, error) {
	path := filepath.Join(workDir, serverNodePasswordRef)
	if b, err := os.ReadFile(path); err == nil {
		pw := strings.TrimSpace(string(b))
		if pw == "" {
			return "", fmt.Errorf("read the control-plane node-password %s: the file is empty", path)
		}
		return pw, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read the control-plane node-password %s: %w", path, err)
	}
	pw, err := bootstrap.GenerateNodePassword()
	if err != nil {
		return "", fmt.Errorf("mint the control-plane node-password: %w", err)
	}
	if err := os.WriteFile(path, []byte(pw), 0o600); err != nil {
		return "", fmt.Errorf("persist the control-plane node-password: %w", err)
	}
	return pw, nil
}

// bindSelfNodePassword takes the first-write-wins node-password binding for this
// control-plane node's OWN name, so no join can take it.
//
// The server enrolls itself directly and never passes through the join handler,
// so before this its own name was simply UNBOUND: the first join to present that
// name bound it and was then treated as that node for the rest of the exchange.
// Binding it here closes that, and closes it for the case the join handler's name
// guard cannot see — an HA sibling, whose SelfNodeName is its own and not this
// one's, reads the SAME datastore-backed store and refuses the claim on the hash.
//
// A failure is returned, not logged: not holding your own name is exactly the
// state this exists to prevent, and the caller's own posture (a logged,
// survivable mesh bring-up failure) is the right place for it to land.
func bindSelfNodePassword(ctx context.Context, passwords bootstrap.NodePasswordStore, nodeName, workDir string) error {
	if passwords == nil {
		return fmt.Errorf("bind the node-password of %q: no node-password store", nodeName)
	}
	pw, err := loadOrCreateServerNodePassword(workDir)
	if err != nil {
		return err
	}
	if err := passwords.Ensure(ctx, nodeName, pw); err != nil {
		return fmt.Errorf("bind the node-password of this control-plane node %q: %w", nodeName, err)
	}
	return nil
}

// serverMeshEndpoint is the address:port a joining worker dials to reach this
// server's wireguard listener.
//
// It is an UNDERLAY address by necessity, not by preference: a worker has no
// mesh until this handshake completes, so an endpoint inside the mesh would be
// unreachable at exactly the moment it is needed. The derivation is therefore
// the agent's — underlayInterfaceIPs (which EXCLUDES tunnels) filtered by
// usableUnderlayIP and reduced by firstProxyableIP — and not node.go's
// hostInterfaceIPs, which does not exclude them.
//
// That difference is the whole reason this function changed. At bring-up the
// mesh utun does not exist yet, so a tunnel-including scan happened to be
// harmless; the moment this derivation runs PERIODICALLY (meshEndpointRefresher)
// the device is up and carrying this node's mesh /32, and the scan would pick
// the one address no un-joined worker can route to — publishing an endpoint that
// can never complete a handshake, which from a peer's side is indistinguishable
// from a working one.
//
// It falls back to nodeIP ONLY when that address is loopback: the single-host
// posture, where every "peer" is on this Mac and loopback is a legitimate
// wireguard endpoint. Anywhere else an empty scan is an ERROR rather than a
// fallback, because on the mesh path nodeIP has already been rewritten to the
// mesh IP (runServer), so falling back would advertise exactly the address this
// function exists to refuse.
func serverMeshEndpoint(nodeIP, meshIP string, port int) (string, error) {
	scanned := underlayInterfaceIPs()
	candidates := make([]net.IP, 0, len(scanned))
	for _, ip := range scanned {
		if usableUnderlayIP(ip, meshIP) != "" {
			candidates = append(candidates, ip)
		}
	}
	if host := firstProxyableIP(candidates); host != "" {
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	}
	if ip := net.ParseIP(nodeIP); ip != nil && ip.IsLoopback() {
		return net.JoinHostPort(nodeIP, strconv.Itoa(port)), nil
	}
	return "", fmt.Errorf("no underlay address to advertise as this control-plane node's wireguard endpoint: "+
		"no up, non-loopback, non-tunnel interface has a globally-unicast address outside the mesh CIDR %s, "+
		"and the node IP %s is not loopback (the node's mesh IP %s is not a valid endpoint — no un-joined peer can dial it)",
		podnet.ClusterPodCIDR, nodeIP, meshIP)
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
	// On the RESUME path (see resume) it is a stored seed of unknown age and is
	// deliberately NOT programmed whole.
	peers []netv1.MeshPeerSpec
	// resume marks a bring-up whose peers came from the stored node credential
	// rather than from a join that just happened, which changes what may be
	// programmed before the MeshPeer watch exists. See bringUpMesh.
	resume bool
	// listPeers is a one-shot LIST of the cluster's MeshPeers, used only on the
	// resume path to replace the stored seed with live state before the watcher
	// starts. Production is meshPeerLister over this node's kubeconfig; nil (or a
	// failing lister) degrades to the seed after firstSyncTimeout.
	listPeers func(ctx context.Context) ([]netv1.MeshPeerSpec, error)
	// firstSyncTimeout bounds the wait for that live list. Zero means
	// meshFirstSyncTimeout; tests inject a small value.
	firstSyncTimeout time.Duration
	// onLivePeers persists the live list the resume path just programmed, so the
	// stored seed advances instead of staying pinned to the original join.
	//
	// It is a HOOK rather than a store reference because this struct is the
	// device's input and knows nothing about credential files — and because only
	// one of the three bring-up paths has anything to persist: the server
	// synthesizes its peers locally and holds no node credential, and a token
	// join has already written the live snapshot the join returned. Nil on both,
	// which is also what every device-level unit test wants.
	//
	// It is called at most ONCE per bring-up, on the live list, and its error is
	// logged rather than returned: the device is already programmed correctly by
	// the time it runs, so a failure costs only a staler fallback on the NEXT
	// start, which is exactly the state this hook exists to improve on.
	onLivePeers func(peers []netv1.MeshPeerSpec) error
	// listenPort is the UDP port this node's wireguard binds.
	listenPort int
	// kubeconfig authenticates the MeshPeer watch that keeps the peer set
	// converging after the initial program.
	kubeconfig string
	// refresher republishes this node's own endpoint when the address it is
	// reachable at changes. It is a FIELD rather than something bringUpMesh
	// builds because the two roles publish through different channels (a worker
	// over the certificate-authenticated bootstrap verb, the server in-process
	// through its enroller) and only the caller holds the credentials for its
	// own. Nil runs no refresher, which is what the unit tests of the device
	// bring-up want.
	refresher *meshEndpointRefresher
}

// provisionHelperKey writes the private key to the root-only path the netd
// MeshKeyResolver reads — best-effort, and no longer the mechanism anything
// depends on.
//
// `k3sm install` provisions that copy as root (pkg/install's provisionMeshKey),
// from the very work-dir key this process just loaded, so on an installed node
// the file is already there with these exact bytes. This write survives for the
// one case install does not cover: a node run out of a shell, where the process
// may itself be privileged enough for it to succeed.
//
// It cannot clobber a good copy with a bad one, because there is no other key it
// could write: the bytes are this node's persisted identity, which is what
// install copied. And it deliberately does not READ the existing file first — in
// the _k3sm posture it cannot (the directory is root-only), so a read would add a
// permission failure on the path that is already handled by the write failing.
func (in meshBringUp) provisionHelperKey(logger *slog.Logger) {
	path := filepath.Join(install.MeshKeyDir, in.keyRef)
	if err := os.WriteFile(path, []byte(in.privateKeyB64), 0o600); err != nil {
		logger.Warn("could not write the mesh private key to the root-only path; `k3sm install` provisions it as root, so this matters only on a node installed by other means",
			"path", path, "err", err)
	}
}

// enrollSelfAndBringUpMesh is the control-plane node's own mesh join: it binds
// this node's name in the node-password store no worker join can then claim,
// loads (or mints) this node's persistent wireguard identity,
// asserts-or-creates its index-0 MeshPeer through the SAME locked enroller the
// worker-join RPC uses, and brings the wireguard device up against the peer
// snapshot the enroll returned.
//
// It returns the enrolled identity so the caller can seed the node-local
// datapath with the mesh-egress source the proxy binds and the peer mesh-egress
// /32s the NetworkPolicy table always-allows, plus the mesh teardown handle the
// caller defers so this node's routes and pf anchor are released on the server's
// way out instead of by a goroutine racing process death (see meshTeardown).
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
func enrollSelfAndBringUpMesh(ctx context.Context, e *meshEnroller, passwords bootstrap.NodePasswordStore, opts serverOptions, mode hostnet.Mode, kubeconfig string, logger *slog.Logger) (netv1.MeshEnrollResponse, meshTeardown, error) {
	// The name binding comes FIRST, before this node has written anything of its
	// own: it is the claim on this node's identity, and the store it lands in is
	// the one every worker join is checked against.
	if err := bindSelfNodePassword(ctx, passwords, opts.nodeName, opts.workDir); err != nil {
		return netv1.MeshEnrollResponse{}, noMeshTeardown, err
	}
	priv, pub, err := loadOrCreateServerMeshKey(opts.workDir)
	if err != nil {
		return netv1.MeshEnrollResponse{}, noMeshTeardown, err
	}
	endpoint, err := serverMeshEndpoint(opts.nodeIP, opts.meshIP, serverMeshListenPort)
	if err != nil {
		return netv1.MeshEnrollResponse{}, noMeshTeardown, err
	}
	res, err := e.EnrollSelf(ctx, opts.nodeName, netv1.MeshEnrollRequest{
		NodeName:  opts.nodeName,
		PublicKey: pub,
		Endpoint:  endpoint,
	})
	if err != nil {
		return netv1.MeshEnrollResponse{}, noMeshTeardown, err
	}
	logger.Info("enrolled this control-plane node into its own mesh",
		"node", opts.nodeName, "podCIDR", res.PodCIDR, "meshIP", res.MeshIP, "peers", len(res.Peers))
	if !mode.DataPath() {
		logger.Info("network datapath disabled (--network none): the index-0 MeshPeer is written, but this process brings up no wireguard device")
		return res, noMeshTeardown, nil
	}
	down, err := bringUpMesh(ctx, meshBringUp{
		podCIDR:       res.PodCIDR,
		meshIP:        res.MeshIP,
		privateKeyB64: priv,
		keyRef:        serverMeshKeyRef,
		peers:         res.Peers,
		listenPort:    serverMeshListenPort,
		kubeconfig:    kubeconfig,
		// The control-plane node's endpoint goes stale the same way a worker's
		// does — this Mac's LAN address is no more fixed than any other — and a
		// worker that joined before the move dials the old one on its next full
		// resync. The write is in-process through the same locked enroller.
		refresher: newServerEndpointRefresher(e, opts, endpoint, logger),
	}, mode, logger)
	if err != nil {
		// The handle is returned even on a failed bring-up: a device that came up
		// before the failure still holds a utun, and the caller's deferred teardown
		// is what releases it.
		return netv1.MeshEnrollResponse{}, down, err
	}
	return res, down, nil
}
