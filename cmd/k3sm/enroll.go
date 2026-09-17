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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

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
// across node deletes is not implemented.
type meshEnroller struct {
	client     rest.Interface
	clusterPod netip.Prefix
	log        *slog.Logger
	// events records an endpoint change against the Node object. It is nil when
	// the core client could not be built, in which case the refresh still writes
	// the MeshPeer and only the Event is lost.
	events typedcorev1.EventInterface
	// nodes is the core Node client Deregister deletes through. It comes from the
	// same clientset as events and is nil for the same reason; unlike an Event,
	// a Node that cannot be deleted is reported, because a left-behind Node is
	// half the state deregistration exists to remove.
	nodes typedcorev1.NodeInterface
	mu    sync.Mutex
}

// newMeshEnroller builds the enroller over the cluster REST config (the typed
// MeshPeer client mirrors darwin-net's NewWatcher construction).
func newMeshEnroller(cfg *rest.Config, log *slog.Logger) (*meshEnroller, error) {
	client, err := meshPeerRESTClient(cfg)
	if err != nil {
		return nil, err
	}
	e := &meshEnroller{client: client, clusterPod: podnet.ClusterPodCIDR, log: log}
	// The Event sink is best-effort by construction: an enroller that cannot
	// record events still enrolls, and refusing to build one here would turn an
	// observability dependency into a join outage.
	if cs, err := kubernetes.NewForConfig(cfg); err != nil {
		log.Warn("mesh endpoint changes will not be recorded as Node Events, and a deregistering node's Node object cannot be deleted", "err", err)
	} else {
		e.events = cs.CoreV1().Events(metav1.NamespaceDefault)
		e.nodes = cs.CoreV1().Nodes()
	}
	return e, nil
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

// RefreshEndpoint implements bootstrap.Enroller: it updates ONLY spec.endpoint on
// this node's EXISTING MeshPeer, and records the change as a Node Event.
//
// It reads-modifies-writes rather than upserting, and never creates: a node whose
// peer is gone has lost its podCIDR assignment with it, so a peer invented here
// would advertise an endpoint with no AllowedIPs behind it and no IPAM range — the
// node has to rejoin. That case is bootstrap.ErrNoMeshPeer, which the handler maps
// to 404.
//
// Every other field is copied forward untouched. The public key, the podCIDR and
// the AllowedIPs are what a forged peer would use to hijack a victim's pod
// traffic; the refresh channel exists to move ONE string, so it moves one string.
// The assembled spec is Validate()d — apis owns the endpoint rule — before the PUT.
//
// It runs under the SAME mutex as Enroll/EnrollSelf. The mutex serializes the
// podCIDR assignment, and a refresh interleaved between a join's list and its
// write would be lost by that write's copy of the object.
func (e *meshEnroller) RefreshEndpoint(ctx context.Context, nodeName, endpoint string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var cur netv1.MeshPeer
	if err := e.client.Get().Resource(meshPeerResource).Name(nodeName).Do(ctx).Into(&cur); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%w: %q", bootstrap.ErrNoMeshPeer, nodeName)
		}
		return fmt.Errorf("read mesh peer %q: %w", nodeName, err)
	}
	old := cur.Spec.Endpoint
	if old == endpoint {
		return nil
	}
	cur.Spec.Endpoint = endpoint
	if err := cur.Spec.WithDefaults().Validate(); err != nil {
		return fmt.Errorf("refresh mesh peer %q endpoint: %w", nodeName, err)
	}
	if err := e.client.Put().Resource(meshPeerResource).Name(nodeName).Body(&cur).Do(ctx).Into(&netv1.MeshPeer{}); err != nil {
		return fmt.Errorf("write mesh peer %q endpoint: %w", nodeName, err)
	}
	e.log.Info("mesh peer endpoint refreshed", "node", nodeName, "old", old, "new", endpoint)
	e.recordEndpointChange(ctx, nodeName, old, endpoint)
	return nil
}

// recordEndpointChange posts the Node Event that makes an endpoint move visible to
// an operator running `kubectl describe node`.
//
// A node's address changing under a running cluster is otherwise a silent event
// with loud consequences — every peer keeps dialing the old address until
// wireguard roaming or the next full resync papers over it — so the record is
// worth more than it costs. It is BEST EFFORT and log-only on failure: the
// MeshPeer write above is the durable half and has already succeeded, and failing
// the refresh over an unrecorded event would turn an observability gap into a
// connectivity one.
func (e *meshEnroller) recordEndpointChange(ctx context.Context, nodeName, old, current string) {
	if e.events == nil {
		return
	}
	now := metav1.Now()
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.%x", nodeName, now.UnixNano()),
			Namespace: metav1.NamespaceDefault,
		},
		InvolvedObject: corev1.ObjectReference{Kind: "Node", Name: nodeName, APIVersion: "v1"},
		Reason:         meshEndpointChangedReason,
		Message:        fmt.Sprintf("wireguard endpoint %s -> %s", old, current),
		Type:           corev1.EventTypeNormal,
		Source:         corev1.EventSource{Component: "k3sm-supervisor"},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
	}
	if _, err := e.events.Create(ctx, event, metav1.CreateOptions{}); err != nil {
		e.log.Warn("could not record the mesh endpoint change as a Node Event", "node", nodeName, "err", err)
	}
}

// meshEndpointChangedReason is the Event reason an endpoint refresh records.
const meshEndpointChangedReason = "MeshEndpointChanged"

// Deregister implements bootstrap.Enroller: it removes a node from the cluster,
// its MeshPeer first and its Node second.
//
// THE ORDER IS THE POINT. The MeshPeer is what every remaining node's wireguard
// device is programmed from, so deleting it first makes the peers drop the
// tunnel entry for a Mac that is going away; deleting the Node first would leave
// a peer entry alive for a node that no longer exists in the cluster, which is
// precisely the residue this verb exists to remove. Freeing the peer also frees
// its pod /24, which lowestFreeNodeIndex hands to the next node that joins.
//
// A NotFound on either object is SUCCESS. Deregistration is idempotent by
// construction: an uninstall can be re-run, an operator may have deleted one
// half by hand, and a node that the cluster has already forgotten is in exactly
// the state this asks for.
//
// The node's coordination Lease is deliberately NOT deleted here. Virtual
// Kubelet's lease controller (v1.12.0 node/lease_controller_v1.go newLease) sets
// an OwnerReference to the Node — name and UID — on the lease it creates and
// re-asserts it on every renew until it sticks, so kube-controller-manager's
// garbage collector (which k3sm leaves enabled; see the executor's
// --controllers value) reaps kube-node-lease/<node> when the Node goes. Deleting
// it here would be a second, racing writer of state that already has an owner.
//
// It runs under the SAME mutex as Enroll/EnrollSelf, so a deregistration cannot
// interleave with a join's list-then-write and leave that write re-creating the
// peer this call just deleted.
func (e *meshEnroller) Deregister(ctx context.Context, nodeName string) error {
	if nodeName == "" {
		return errors.New("deregister: no node name")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.client.Delete().Resource(meshPeerResource).Name(nodeName).Do(ctx).Error(); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete mesh peer %q: %w", nodeName, err)
	}
	if e.nodes == nil {
		return fmt.Errorf("delete node %q: this supervisor has no core apiserver client, so only the MeshPeer was removed (`kubectl delete node %s` removes the rest)", nodeName, nodeName)
	}
	if err := e.nodes.Delete(ctx, nodeName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete node %q: %w", nodeName, err)
	}
	e.log.Info("node deregistered", "node", nodeName)
	return nil
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
	return listMeshPeers(ctx, e.client)
}

// listMeshPeers is the one-shot LIST of every MeshPeer spec in the cluster. It is
// a free function over the REST client rather than a method because the enroller
// is not its only caller: a resuming worker's mesh bring-up lists the same
// resource through the same client construction before it programs anything (see
// meshPeerLister), and a second copy of the list-and-project would be a second
// place for the projection to drift.
func listMeshPeers(ctx context.Context, client rest.Interface) ([]netv1.MeshPeerSpec, error) {
	var list netv1.MeshPeerList
	if err := client.Get().Resource(meshPeerResource).Do(ctx).Into(&list); err != nil {
		return nil, err
	}
	specs := make([]netv1.MeshPeerSpec, 0, len(list.Items))
	for i := range list.Items {
		specs = append(specs, list.Items[i].Spec)
	}
	return specs, nil
}

// meshPeerLister returns a one-shot MeshPeer LIST bound to a kubeconfig — the
// production value of meshBringUp.listPeers.
//
// The REST client is built ONCE, here, and its construction error is carried into
// the returned function: client construction is pure (it opens no connection), so
// building it before the wireguard device exists is safe, while re-building it per
// poll attempt would churn a transport for every retry. A failure to build is
// reported on every call rather than at wiring time, because the caller's contract
// is a lister that can fail — the bring-up degrades to the stored seed, it does not
// refuse to bring the mesh up.
func meshPeerLister(kubeconfig string) func(context.Context) ([]netv1.MeshPeerSpec, error) {
	var client rest.Interface
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		err = fmt.Errorf("load kubeconfig for the MeshPeer list: %w", err)
	} else {
		// A REQUEST timeout, on THIS client only (the enroller's serves a running
		// control plane and keeps its own posture): clientcmd leaves Timeout at zero,
		// so without it a connection the apiserver accepts and never answers hangs
		// the resuming node's poll past its own bound. The poll's per-attempt context
		// covers the same hazard; both are cheap and the client-side one also bounds
		// every later caller of this lister.
		cfg.Timeout = meshPeerAttemptTimeout
		client, err = meshPeerRESTClient(cfg)
	}
	return func(ctx context.Context) ([]netv1.MeshPeerSpec, error) {
		if err != nil {
			return nil, err
		}
		return listMeshPeers(ctx, client)
	}
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
// (CAs, tokens, node-passwords, enroller) are always set; the server-join deps
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
	// listen binds the supervisor's address. Nil is net.Listen — the shipped
	// value; it is a field so a test can drive the rebind retry without racing a
	// real port.
	listen listenFunc
}

// listenFunc binds a listening socket. It is the seam startBootstrapServer binds
// through instead of http.Server.ListenAndServeTLS, which folds the bind into the
// serve and so cannot be retried.
type listenFunc func(network, addr string) (net.Listener, error)

const (
	// joinListenerAttempts bounds the rebind retry. It is a BOUND, not a
	// supervisor that keeps trying: an address still busy after the whole window
	// is not transient, and reporting that is more useful than a goroutine
	// retrying forever behind a healthy-looking daemon.
	joinListenerAttempts = 8
	// joinListenerBackoff is the fixed wait between attempts. 8 attempts with 7
	// waits is about 10s — long enough to outlast the two transient causes seen
	// (a previous supervisor's socket still draining, a stale port-forward being
	// torn down), short enough that a worker retrying its join still finds the
	// endpoint on its next attempt.
	joinListenerBackoff = 1500 * time.Millisecond
)

// listenJoinAddr binds addr, retrying ONLY a transiently busy address.
//
// The discrimination is the whole point: EADDRINUSE on this port means something
// else holds it right now (the previous supervisor's socket draining through
// TIME_WAIT, a leftover forwarder), which clears on its own; any other bind error
// — a bad address, a permission denial — will not clear by waiting, so retrying it
// only delays the report. Before this, the bind was inside ListenAndServeTLS, so
// the transient case was terminal too: the supervisor goroutine logged once and
// the worker-join endpoint stayed dead until the daemon was restarted by hand.
func listenJoinAddr(ctx context.Context, listen listenFunc, addr string, attempts int, backoff time.Duration, log *slog.Logger) (net.Listener, error) {
	if listen == nil {
		listen = net.Listen
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		ln, err := listen("tcp", addr)
		if err == nil {
			if attempt > 1 {
				log.Info("worker-join listener bound after the address freed", "addr", addr, "attempts", attempt)
			}
			return ln, nil
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, fmt.Errorf("bind worker-join listener on %s: %w", addr, err)
		}
		lastErr = err
		log.Warn("worker-join listener address is busy; retrying", "addr", addr, "attempt", attempt, "attempts", attempts, "backoff", backoff, "err", err)
		if attempt == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("bind worker-join listener on %s: %w", addr, ctx.Err())
		case <-time.After(backoff):
		}
	}
	return nil, fmt.Errorf("bind worker-join listener on %s: still in use after %d attempts over %s: %w",
		addr, attempts, time.Duration(attempts-1)*backoff, lastErr)
}

// startBootstrapServer serves the worker-join endpoint (and, in HA, the CA-bundle
// endpoint) at bootstrapListenAddr over a TLS listener presenting [serving-leaf,
// cluster-CA] so a joining node's CA-hash pin verifies. The bind is retried for a
// bounded window when the address is transiently busy (listenJoinAddr). It blocks until ctx is
// cancelled, then shuts down. This is the live, mesh-bound supervisor — its end-to-end
// exercise is the two-Mac K3SM_LAB gate. The MeshPeer CRD the enroller's write lands
// in is ensured fail-closed by runServer's step 4a before this listener exists, so a
// join reaching it never meets a missing CRD.
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

	// The listener OPTIONALLY verifies a client certificate against the cluster's
	// client-identity (signing) CA — the same anchor a node's own :10250 uses. It
	// is what lets the endpoint-refresh verb authenticate a joined node by its
	// system:node certificate instead of the TTL-bounded join token, and it is
	// optional because /join, /cacert and /server-bootstrap are reached by nodes
	// that hold no certificate yet. It FAILS CLOSED on a missing CA
	// (bootstrap.ErrNoClientIdentityCA): a listener built with no pool would abort
	// every presented certificate, so the refresh verb would 401 forever while the
	// join path kept working — a fault that reads as a network problem.
	tlsCfg, err := bootstrap.ListenerTLSConfig(servingChain, h.Signing.CertPEM)
	if err != nil {
		return fmt.Errorf("bootstrap listener TLS: %w", err)
	}
	hs := &http.Server{
		Addr:              bootstrapListenAddr(meshIP),
		Handler:           srv.Handler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutCtx)
	}()
	// Bind first, with the bounded retry, THEN serve. ServeTLS is what
	// ListenAndServeTLS does once it holds a listener (same TLSConfig, same h2
	// NextProtos negotiation), so the served surface is unchanged — only the bind
	// is now survivable. The shutdown goroutine above is already armed, and an
	// http.Server whose Shutdown ran returns ErrServerClosed from Serve, so a ctx
	// cancelled during the retry window still ends in a clean exit.
	ln, err := listenJoinAddr(ctx, deps.listen, hs.Addr, joinListenerAttempts, joinListenerBackoff, log)
	if err != nil {
		return err
	}
	log.Info("bootstrap supervisor listening", "addr", hs.Addr)
	if err := hs.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("bootstrap server: %w", err)
	}
	return nil
}
