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
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// meshEnroller is the server-side, controller-mediated mesh enroll
// (bootstrap.Enroller). It assigns the joining node a unique pod /24 from the cluster
// pod CIDR, derives its mesh-egress /32, writes THIS node's MeshPeer to the apiserver
// (named == nodeName, so bootstrap's write-guard holds — a node never writes a peer
// for any other node), and returns the current peer snapshot.
//
// Locking discipline: mu serializes the assign→write so two concurrent joins do not
// claim the same /24, and the SAME instance serves both the join RPC and this
// server's own EnrollSelf — the two allocators must contend on one lock or a worker
// joining during bring-up can be handed the index the server is claiming.
// podCIDR assignment is the LOWEST FREE index ≥ 1 (index 0 is the control-plane
// node's, pinned by EnrollSelf); it is a dev-scale scheme — robust index recycling
// across node deletes is an M4 concern.
type meshEnroller struct {
	client     rest.Interface
	clusterPod netip.Prefix
	log        *slog.Logger
	mu         sync.Mutex
}

// newMeshEnroller builds the enroller over the cluster REST config (the typed
// MeshPeer client mirrors darwin-net's NewWatcher construction).
func newMeshEnroller(cfg *rest.Config, log *slog.Logger) (*meshEnroller, error) {
	client, err := meshPeerRESTClient(cfg)
	if err != nil {
		return nil, err
	}
	return &meshEnroller{client: client, clusterPod: podnet.ClusterPodCIDR, log: log}, nil
}

// Enroll implements bootstrap.Enroller.
func (e *meshEnroller) Enroll(ctx context.Context, nodeName string, req netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	existing, err := e.listPeers(ctx)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("list mesh peers: %w", err)
	}

	// Reuse this node's already-assigned CIDR on a rejoin; else assign the next /24.
	podCIDR := ""
	for _, p := range existing {
		if p.NodeName == nodeName {
			podCIDR = p.PodCIDR
		}
	}
	if podCIDR == "" {
		index, err := lowestFreeNodeIndex(e.clusterPod, existing)
		if err != nil {
			return netv1.MeshEnrollResponse{}, fmt.Errorf("assign podCIDR: %w", err)
		}
		cidr, err := podnet.NodeCIDR(e.clusterPod, index)
		if err != nil {
			return netv1.MeshEnrollResponse{}, fmt.Errorf("assign podCIDR: %w", err)
		}
		podCIDR = cidr.String()
	}
	prefix, err := netip.ParsePrefix(podCIDR)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("parse assigned podCIDR %q: %w", podCIDR, err)
	}
	meshIP, err := podnet.MeshEgressIP(prefix)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("derive mesh-egress IP: %w", err)
	}

	peer, err := bootstrap.BuildMeshPeer(nodeName, podCIDR, meshIP.String(), req)
	if err != nil {
		return netv1.MeshEnrollResponse{}, err
	}
	if err := e.writePeer(ctx, peer); err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("write mesh peer %q: %w", nodeName, err)
	}

	// Snapshot the (now-current) peer set for the joining node to program immediately.
	peers, err := e.listPeers(ctx)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("snapshot mesh peers: %w", err)
	}
	return netv1.MeshEnrollResponse{
		NodeName: nodeName,
		PodCIDR:  podCIDR,
		MeshIP:   meshIP.String(),
		Peers:    peers,
	}.WithDefaults(), nil
}

// serverNodeIndex is the node index the CONTROL-PLANE node's pod /24 is carved
// at. It is pinned, not assigned: defaultNodePodCIDR() hard-codes the same index-0
// carve and feeds it to this node's routing locality and its pod IPAM, so a
// self-assigned different index would split "what the mesh routes here" from "what
// this node's pods are" — and mesh.BuildPlan's self-exclusion keys on exact CIDR
// equality, so the node would program a route to itself.
const serverNodeIndex = 0

// ErrMeshIndexClaimed is returned by EnrollSelf when the control-plane node's
// index-0 pod /24 is already held by a DIFFERENT node. Compare with errors.Is.
var ErrMeshIndexClaimed = errors.New("enroll: the control-plane mesh index is claimed by another node")

// EnrollSelf asserts-or-creates the CONTROL-PLANE node's own MeshPeer at index 0
// and returns the resulting peer snapshot, so the server participates in the mesh
// it hosts rather than only brokering other nodes into it.
//
// It runs under the SAME mutex as Enroll and through the same writePeer upsert, so
// it is serialized against every concurrent worker join; and it LIST-BACK VERIFIES
// its own write before returning, so a caller that opens the join listener only
// after this returns has a durable index-0 claim in place. Without that
// happens-before, Enroll's lowest-free-index scanner would legitimately hand index
// 0 to a worker that joins in the window, and two peers would claim one AllowedIPs
// — which wireguard cannot admit.
//
// It NEVER runs the free-index scanner (see serverNodeIndex) and it FAILS CLOSED
// with ErrMeshIndexClaimed if index 0 is held by a different node name: silently
// taking the slot would rewrite a live peer's AllowedIPs out from under it.
// Re-enrolling this same node is idempotent — the upsert updates the endpoint and
// public key in place.
func (e *meshEnroller) EnrollSelf(ctx context.Context, nodeName string, req netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	selfCIDR, err := podnet.NodeCIDR(e.clusterPod, serverNodeIndex)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("derive the control-plane podCIDR: %w", err)
	}
	meshIP, err := podnet.MeshEgressIP(selfCIDR)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("derive mesh-egress IP: %w", err)
	}

	existing, err := e.listPeers(ctx)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("list mesh peers: %w", err)
	}
	for _, p := range existing {
		idx, ok := nodeIndexOf(e.clusterPod, p.PodCIDR)
		if !ok || idx != serverNodeIndex || p.NodeName == nodeName {
			continue
		}
		return netv1.MeshEnrollResponse{}, fmt.Errorf("%w: %s is held by node %q, not %q",
			ErrMeshIndexClaimed, selfCIDR, p.NodeName, nodeName)
	}

	peer, err := bootstrap.BuildMeshPeer(nodeName, selfCIDR.String(), meshIP.String(), req)
	if err != nil {
		return netv1.MeshEnrollResponse{}, err
	}
	if err := e.writePeer(ctx, peer); err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("write mesh peer %q: %w", nodeName, err)
	}

	// LIST-BACK VERIFY. This is not a re-read for convenience: it is the
	// happens-before the caller depends on. Returning nil here is the claim that
	// index 0 is durably this node's, so it has to be read back from the apiserver
	// rather than inferred from a successful write.
	peers, err := e.listPeers(ctx)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("verify self-enroll: %w", err)
	}
	verified := false
	for _, p := range peers {
		if p.NodeName == nodeName && p.PodCIDR == selfCIDR.String() {
			verified = true
		}
	}
	if !verified {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("verify self-enroll: no MeshPeer %q at %s after the write", nodeName, selfCIDR)
	}
	return netv1.MeshEnrollResponse{
		NodeName: nodeName,
		PodCIDR:  selfCIDR.String(),
		MeshIP:   meshIP.String(),
		Peers:    peers,
	}.WithDefaults(), nil
}

// lowestFreeNodeIndex returns the lowest node index ≥ 1 whose /24 no existing peer
// holds.
//
// It replaces a len(existing)+1 counter, which is wrong the moment index 0 is
// occupied by the control-plane node's own MeshPeer: with one peer present the
// counter returns 2, skipping index 1 forever, and with the server plus one worker
// it returns 3 — an index scheme whose answers depend on how many peers exist
// rather than on which indices are taken. It also never recovered an index after a
// node was deleted. Starting at 1 keeps index 0 reserved (serverNodeIndex); a peer
// whose podCIDR does not parse or falls outside the cluster CIDR is ignored rather
// than allowed to shift the numbering.
func lowestFreeNodeIndex(clusterCIDR netip.Prefix, existing []netv1.MeshPeerSpec) (int, error) {
	used := make(map[int]struct{}, len(existing))
	for _, p := range existing {
		if idx, ok := nodeIndexOf(clusterCIDR, p.PodCIDR); ok {
			used[idx] = struct{}{}
		}
	}
	for index := serverNodeIndex + 1; ; index++ {
		if _, taken := used[index]; taken {
			continue
		}
		if _, err := podnet.NodeCIDR(clusterCIDR, index); err != nil {
			return 0, fmt.Errorf("no free node index in %s: %w", clusterCIDR, err)
		}
		return index, nil
	}
}

// nodeIndexOf reports which node index of clusterCIDR the /24 podCIDR is, and
// whether it is one at all. A podCIDR that does not parse, is not a /24, or lies
// outside clusterCIDR is not an index — the caller ignores it rather than guessing.
func nodeIndexOf(clusterCIDR netip.Prefix, podCIDR string) (int, bool) {
	prefix, err := netip.ParsePrefix(podCIDR)
	if err != nil {
		return 0, false
	}
	prefix = prefix.Masked()
	base := clusterCIDR.Masked()
	if !base.IsValid() || !prefix.Addr().Is4() || !base.Addr().Is4() {
		return 0, false
	}
	if prefix.Bits() != nodePodCIDRBits || !base.Contains(prefix.Addr()) {
		return 0, false
	}
	p := prefix.Addr().As4()
	b := base.Addr().As4()
	offset := (uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])) -
		(uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]))
	return int(offset >> (32 - nodePodCIDRBits)), true
}

// nodePodCIDRBits is the prefix length of a per-node pod CIDR, mirroring podnet's
// own unexported constant — the carve NodeCIDR produces and nodeIndexOf inverts.
const nodePodCIDRBits = 24

// listPeers returns the current MeshPeer specs from the apiserver.
func (e *meshEnroller) listPeers(ctx context.Context) ([]netv1.MeshPeerSpec, error) {
	var list netv1.MeshPeerList
	if err := e.client.Get().Resource(meshPeerResource).Do(ctx).Into(&list); err != nil {
		return nil, err
	}
	specs := make([]netv1.MeshPeerSpec, 0, len(list.Items))
	for i := range list.Items {
		specs = append(specs, list.Items[i].Spec)
	}
	return specs, nil
}

// writePeer creates the MeshPeer, or updates it in place on a rejoin (AlreadyExists).
func (e *meshEnroller) writePeer(ctx context.Context, peer *netv1.MeshPeer) error {
	err := e.client.Post().Resource(meshPeerResource).Body(peer).Do(ctx).Into(&netv1.MeshPeer{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return err
	}
	var cur netv1.MeshPeer
	if err := e.client.Get().Resource(meshPeerResource).Name(peer.Name).Do(ctx).Into(&cur); err != nil {
		return err
	}
	peer.ResourceVersion = cur.ResourceVersion
	return e.client.Put().Resource(meshPeerResource).Name(peer.Name).Body(peer).Do(ctx).Into(&netv1.MeshPeer{})
}

// meshPeerResource is the MeshPeer CRD resource name within net.k3sm.io/v1.
const meshPeerResource = "meshpeers"

// meshPeerRESTClient builds a typed REST client for the MeshPeer GVK, registering the
// net.k3sm.io/v1 scheme (the same construction darwin-net's mesh watcher uses).
func meshPeerRESTClient(cfg *rest.Config) (rest.Interface, error) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register net.k3sm.io scheme: %w", err)
	}
	codecs := serializer.NewCodecFactory(scheme)
	rc := rest.CopyConfig(cfg)
	rc.GroupVersion = &netv1.SchemeGroupVersion
	rc.APIPath = "/apis"
	rc.NegotiatedSerializer = codecs.WithoutConversion()
	return rest.RESTClientFor(rc)
}

// bootstrapPort is the dedicated TLS port the supervisor's worker-join endpoint
// binds (separate from the apiserver secure port).
const bootstrapPort = 9345

// bootstrapListenAddr derives the address the worker-join supervisor listens on.
//
// On the MESH path (meshIP set) it is the WILDCARD, and that is the whole point:
// a joining worker dials this endpoint over the UNDERLAY, because it has no mesh
// until the join it is making completes (`k3sm agent --server` documents exactly
// that, and the MeshPeer this endpoint enrolls advertises an underlay endpoint for
// the same reason). Bound to meshIP alone the supervisor answers only on an
// address no un-joined worker can route to, so every join is refused — which is
// the defect the first real --mesh-ip boot exposed and which a 127.0.0.1 mesh IP
// had masked, loopback being reachable from the same host either way.
//
// LAN exposure IS this endpoint's threat model, not a regression of it: every
// route it serves is authenticated by the K10 cluster token (CA-hash-pinned by the
// client) or the server-class secret, and the node-password binding is
// first-write-wins per node name. It has no ambient-authority route.
//
// With no mesh (single node) nothing ever opens this listener, but the address is
// still derived closed — loopback — so a future caller cannot acquire LAN exposure
// by accident.
func bootstrapListenAddr(meshIP string) string {
	host := "127.0.0.1"
	if meshIP != "" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(bootstrapPort))
}

// bootstrapServerDeps are the supervisor's wired dependencies. The worker-join deps
// (CAs, tokens, node-passwords, enroller) are always set; the M6.1 server-join deps
// (ServerAuth + Bundle + APIServers) are set only in the HA posture, where they light up
// the CA-bundle endpoint.
type bootstrapServerDeps struct {
	hierarchy     *certs.Hierarchy
	meshIP        string
	tokens        bootstrap.TokenVerifier
	nodePasswords bootstrap.NodePasswordStore
	enroller      bootstrap.Enroller
	serverAuth    bootstrap.ServerAuthorizer
	bundle        bootstrap.BundleSource
	apiServers    []string
}

// startBootstrapServer serves the worker-join endpoint (and, in HA, the M6.1 CA-bundle
// endpoint) at bootstrapListenAddr over a TLS listener presenting [serving-leaf,
// cluster-CA] so a joining node's CA-hash pin verifies. It blocks until ctx is
// cancelled, then shuts down. This is the live, mesh-bound supervisor — its end-to-end
// exercise is the two-Mac K3SM_LAB gate. The MeshPeer CRD the enroller's write lands
// in is ensured fail-closed by runServer's step 4a before this listener exists, so a
// join reaching it never meets a missing CRD (B224).
func startBootstrapServer(ctx context.Context, deps bootstrapServerDeps, log *slog.Logger) error {
	h := deps.hierarchy
	meshIP := deps.meshIP
	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:     h.Cluster,
		SigningCA:     h.Signing,
		Tokens:        deps.tokens,
		NodePasswords: deps.nodePasswords,
		Enroller:      deps.enroller,
		APIServers:    deps.apiServers,
		ServerAuth:    deps.serverAuth,
		Bundle:        deps.bundle,
		Logger:        log,
	})
	if err != nil {
		return fmt.Errorf("build bootstrap server: %w", err)
	}

	servingChain, err := h.Cluster.ServingChainTLS("k3sm-supervisor",
		[]string{"localhost"}, []net.IP{net.ParseIP(meshIP), net.ParseIP("127.0.0.1")}, 365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("supervisor serving cert: %w", err)
	}

	hs := &http.Server{
		Addr:              bootstrapListenAddr(meshIP),
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{servingChain}},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutCtx)
	}()
	log.Info("bootstrap supervisor listening", "addr", hs.Addr)
	if err := hs.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("bootstrap server: %w", err)
	}
	return nil
}
