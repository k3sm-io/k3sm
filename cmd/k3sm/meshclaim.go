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
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/install"
)

// Range ownership. A node pod /24 belongs to exactly one node name, and the
// datastore decides which: every assignment first CREATES a claim object named for
// the range's index, and a create that answers AlreadyExists with another holder
// means the range is taken. Create-if-absent is atomic in the apiserver, so two
// enrollers — two servers of an HA pair, each serving joins — can never both win
// one range, and the loser never writes a MeshPeer.
//
// The claim is a coordination.k8s.io/v1 Lease because a Lease already says "this
// name is held by that identity" (spec.holderIdentity) and needs no CRD. It is not
// renewed and carries no duration: it is an ownership record, not a lease in the
// leader-election sense, and it lives exactly as long as the range is assigned.
// The enroller writes it with the server's admin client, the same identity that
// writes the MeshPeers, so no RBAC grant is involved.

// meshRangeClaimNamespace is where the range claims live. kube-system exists on
// every cluster and is never a workload namespace.
const meshRangeClaimNamespace = metav1.NamespaceSystem

// meshRangeClaimPrefix prefixes a claim's name; the suffix is the decimal index.
const meshRangeClaimPrefix = "meshrange-"

// meshRangeClaimLabel marks every range claim, so they can be listed as a set.
const meshRangeClaimLabel = "net.k3sm.io/mesh-range-claim"

// meshRangeClaimPodCIDRAnnotation records the claimed /24 on its claim, for an
// operator reading `kubectl -n kube-system get lease -o yaml`.
const meshRangeClaimPodCIDRAnnotation = "net.k3sm.io/pod-cidr"

// meshRangeClaimPeerHostAnnotation records, on a range a server's member-route
// reservation claimed, the host of that server's etcd peer URL — the one fact the
// abandoned-reservation sweep can match against the etcd member list before the
// member has started and published its name.
const meshRangeClaimPeerHostAnnotation = "net.k3sm.io/etcd-peer-host"

// meshPeerServerLabel marks a control-plane node's MeshPeer (value "true"). It is
// a CONVENTION the server write paths set, advisory to every reader but this
// enroller: old peers ignore it, the mesh programming never reads it, and a writer
// with admin rights could set it on anything. What it is FOR is the join path's
// overwrite guard and the API-server endpoint list. Index 0's arm in isServerPeer is
// permanent, so the rows written before the label existed stay covered.
const meshPeerServerLabel = "net.k3sm.io/control-plane"

// meshRangeClaimName is the claim object's name for a node index.
func meshRangeClaimName(index int) string {
	return meshRangeClaimPrefix + strconv.Itoa(index)
}

// isServerPeer reports whether p is a control-plane node's MeshPeer: labelled as
// one, or at the first server's index 0 (the rows written before the label).
func isServerPeer(clusterCIDR netip.Prefix, p netv1.MeshPeer) bool {
	if p.Labels[meshPeerServerLabel] == "true" {
		return true
	}
	idx, ok := nodeIndexOf(clusterCIDR, p.Spec.PodCIDR)
	return ok && idx == firstServerIndex
}

// rangeClaimMeta is what a new claim records beyond its holder.
type rangeClaimMeta struct {
	// server marks a server's range (its MeshPeer carries meshPeerServerLabel).
	server bool
	// peerHost is the member-route reservation's etcd peer host, when known.
	peerHost string
}

// claimRange takes, or finds already held, the claim on node index idx (the /24
// cidr) for nodeName. It returns the claim's HOLDER: nodeName when this call won
// it or already held it, another name when the range is taken. created reports a
// claim this call made, which the caller gives back if its write then fails.
func (e *meshEnroller) claimRange(ctx context.Context, idx int, cidr netip.Prefix, nodeName string, meta rangeClaimMeta) (holder string, created bool, err error) {
	name := meshRangeClaimName(idx)
	// A claim deleted between the losing create and the read is retried a few
	// times; a range churning that fast is a fault, not a contest to keep entering.
	for range 3 {
		holderID := nodeName
		now := metav1.NowMicro()
		lease := &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   meshRangeClaimNamespace,
				Labels:      map[string]string{meshRangeClaimLabel: "true"},
				Annotations: map[string]string{meshRangeClaimPodCIDRAnnotation: cidr.String()},
			},
			Spec: coordinationv1.LeaseSpec{HolderIdentity: &holderID, AcquireTime: &now},
		}
		if meta.server {
			lease.Labels[meshPeerServerLabel] = "true"
		}
		if meta.peerHost != "" {
			lease.Annotations[meshRangeClaimPeerHostAnnotation] = meta.peerHost
		}
		_, err := e.leases.Create(ctx, lease, metav1.CreateOptions{})
		if err == nil {
			return nodeName, true, nil
		}
		if !apierrors.IsAlreadyExists(err) {
			return "", false, fmt.Errorf("create the claim %s/%s on %s: %w", meshRangeClaimNamespace, name, cidr, err)
		}
		cur, err := e.leases.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return "", false, fmt.Errorf("read the claim %s/%s on %s: %w", meshRangeClaimNamespace, name, cidr, err)
		}
		return claimHolder(cur), false, nil
	}
	return "", false, fmt.Errorf("claim %s/%s on %s: the claim was created and removed repeatedly while this node tried to take it", meshRangeClaimNamespace, name, cidr)
}

// claimHolder is a claim's holder identity, "" when it records none.
func claimHolder(l *coordinationv1.Lease) string {
	if l.Spec.HolderIdentity == nil {
		return ""
	}
	return *l.Spec.HolderIdentity
}

// releaseClaim deletes the claim on index idx when nodeName holds it. A claim held
// by another name is KEPT (it is that name's range now), and an absent one is
// success. The delete is preconditioned on what was read, so a claim re-taken in
// between is never removed.
func (e *meshEnroller) releaseClaim(ctx context.Context, idx int, nodeName string) error {
	name := meshRangeClaimName(idx)
	cur, err := e.leases.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the claim %s/%s: %w", meshRangeClaimNamespace, name, err)
	}
	if claimHolder(cur) != nodeName {
		return nil
	}
	return e.deleteClaim(ctx, cur)
}

// deleteClaim deletes exactly the claim object read as cur.
func (e *meshEnroller) deleteClaim(ctx context.Context, cur *coordinationv1.Lease) error {
	pre := &metav1.Preconditions{ResourceVersion: &cur.ResourceVersion}
	if cur.UID != "" {
		pre.UID = &cur.UID
	}
	err := e.leases.Delete(ctx, cur.Name, metav1.DeleteOptions{Preconditions: pre})
	if err == nil || apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return nil
	}
	return fmt.Errorf("delete the claim %s/%s: %w", meshRangeClaimNamespace, cur.Name, err)
}

// listClaims lists every range claim.
func (e *meshEnroller) listClaims(ctx context.Context) ([]coordinationv1.Lease, error) {
	list, err := e.leases.List(ctx, metav1.ListOptions{LabelSelector: meshRangeClaimLabel + "=true"})
	if err != nil {
		return nil, fmt.Errorf("list the mesh range claims: %w", err)
	}
	return list.Items, nil
}

// releaseClaimsHeldBy deletes every range claim nodeName holds.
func (e *meshEnroller) releaseClaimsHeldBy(ctx context.Context, nodeName string) error {
	claims, err := e.listClaims(ctx)
	if err != nil {
		return err
	}
	for i := range claims {
		if claimHolder(&claims[i]) == nodeName {
			if err := e.deleteClaim(ctx, &claims[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

// claimLowestFreeIndex claims the lowest index ≥ 1 that no existing peer holds and
// whose claim this node wins, and returns its /24. An index whose claim another
// name holds is skipped — that is a concurrent enroller's win, or a server's
// reservation — so the loser of a race moves on instead of writing a duplicate.
func (e *meshEnroller) claimLowestFreeIndex(ctx context.Context, nodeName string, existing []netv1.MeshPeer) (netip.Prefix, error) {
	specs := make([]netv1.MeshPeerSpec, 0, len(existing))
	for _, p := range existing {
		specs = append(specs, p.Spec)
	}
	used := make(map[int]struct{}, len(specs))
	for _, p := range specs {
		if idx, ok := nodeIndexOf(e.clusterPod, p.PodCIDR); ok {
			used[idx] = struct{}{}
		}
	}
	start, err := lowestFreeNodeIndex(e.clusterPod, specs)
	if err != nil {
		return netip.Prefix{}, err
	}
	for index := start; ; index++ {
		if _, taken := used[index]; taken {
			continue
		}
		cidr, err := podnet.NodeCIDR(e.clusterPod, index)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("no free node index in %s: %w", e.clusterPod, err)
		}
		holder, _, err := e.claimRange(ctx, index, cidr, nodeName, rangeClaimMeta{})
		if err != nil {
			return netip.Prefix{}, err
		}
		if holder == nodeName {
			return cidr, nil
		}
	}
}

// meshRangeError is a server claim refusal with the facts its remedy names: the
// range, the node that holds it, and the claim object. It unwraps to
// ErrMeshIndexClaimed or bootstrap.ErrMeshClaimRefused.
type meshRangeError struct {
	sentinel error
	// cidr is the range the server asked for.
	cidr string
	// holder is the other node holding cidr, when that is the refusal.
	holder string
	// claim is the claim object, namespace/name.
	claim string
	// detail says what about this name's own row forbade the claim, when that is
	// the refusal.
	detail string
}

func (e *meshRangeError) Error() string {
	if e.holder != "" {
		return fmt.Sprintf("%v: %s is held by node %q (claim %s)", e.sentinel, e.cidr, e.holder, e.claim)
	}
	return fmt.Sprintf("%v: %s", e.sentinel, e.detail)
}

func (e *meshRangeError) Unwrap() error { return e.sentinel }

// serverClaimOrigin says which path is claiming a server's range.
type serverClaimOrigin struct {
	// memberRoute is the existing server reserving a JOINING server's range. It may
	// only (re)assert a row that already carries the joiner's public key: a key
	// change through this route would let any holder of the server token replace a
	// server's wireguard identity.
	memberRoute bool
	// peerHost is the joiner's etcd peer host (memberRoute only).
	peerHost string
}

// claimServerRange is the one server claim path, shared by EnrollSelf (a server
// claiming its own range) and ReserveServerMesh (the member route reserving a
// joiner's). The caller holds e.mu.
//
// It touches only nodeName's own server row, and never evicts or moves anything:
//   - another node's peer or claim at selfCIDR refuses (ErrMeshIndexClaimed);
//   - nodeName holding a WORKER row, a server row at a different range, or (on the
//     member route) a server row with a different key refuses
//     (bootstrap.ErrMeshClaimRefused).
//
// Otherwise the claim is taken, then the server-labelled MeshPeer written. Fresh in
// the returned Allocation means no row of this name existed before.
func (e *meshEnroller) claimServerRange(ctx context.Context, nodeName string, selfCIDR netip.Prefix, req netv1.MeshEnrollRequest, origin serverClaimOrigin) (bootstrap.Allocation, error) {
	selfCIDR = selfCIDR.Masked()
	idx, ok := nodeIndexOf(e.clusterPod, selfCIDR.String())
	if !ok {
		return bootstrap.Allocation{}, fmt.Errorf("%w: %s is not a node range of %s", bootstrap.ErrInvalidMeshClaim, selfCIDR, e.clusterPod)
	}
	claim := meshRangeClaimNamespace + "/" + meshRangeClaimName(idx)
	meshIP, err := podnet.MeshEgressIP(selfCIDR)
	if err != nil {
		return bootstrap.Allocation{}, fmt.Errorf("%w: derive the mesh-egress address of %s: %w", bootstrap.ErrInvalidMeshClaim, selfCIDR, err)
	}
	existing, err := e.listPeerObjects(ctx)
	if err != nil {
		return bootstrap.Allocation{}, fmt.Errorf("list mesh peers: %w", err)
	}
	var own *netv1.MeshPeer
	for i := range existing {
		p := existing[i]
		if p.Spec.NodeName == nodeName {
			own = &existing[i]
			continue
		}
		if samePrefix(p.Spec.PodCIDR, selfCIDR) {
			return bootstrap.Allocation{}, &meshRangeError{sentinel: ErrMeshIndexClaimed, cidr: selfCIDR.String(), holder: p.Spec.NodeName, claim: claim}
		}
	}
	if own != nil {
		switch {
		case !isServerPeer(e.clusterPod, *own):
			return bootstrap.Allocation{}, &meshRangeError{sentinel: bootstrap.ErrMeshClaimRefused, cidr: selfCIDR.String(),
				detail: fmt.Sprintf("the name %q holds a worker's MeshPeer at %s; a server never takes over a worker's row", nodeName, own.Spec.PodCIDR)}
		case !samePrefix(own.Spec.PodCIDR, selfCIDR):
			return bootstrap.Allocation{}, &meshRangeError{sentinel: bootstrap.ErrMeshClaimRefused, cidr: selfCIDR.String(),
				detail: fmt.Sprintf("the name %q holds %s, but its --mesh-ip names %s; a server's range is never moved automatically (re-addressing a server is the manual procedure in the HA guide)", nodeName, own.Spec.PodCIDR, selfCIDR)}
		case origin.memberRoute && own.Spec.PublicKey != req.PublicKey:
			return bootstrap.Allocation{}, &meshRangeError{sentinel: bootstrap.ErrMeshClaimRefused, cidr: selfCIDR.String(),
				detail: fmt.Sprintf("the name %q holds %s under a different wireguard public key; a server's key is not replaced through a join (restore its original mesh key file, or remove its MeshPeer and claim first)", nodeName, own.Spec.PodCIDR)}
		}
	}
	holder, created, err := e.claimRange(ctx, idx, selfCIDR, nodeName, rangeClaimMeta{server: true, peerHost: origin.peerHost})
	if err != nil {
		return bootstrap.Allocation{}, err
	}
	if holder != nodeName {
		return bootstrap.Allocation{}, &meshRangeError{sentinel: ErrMeshIndexClaimed, cidr: selfCIDR.String(), holder: holder, claim: claim}
	}
	giveBack := func() {
		if !created {
			return
		}
		if err := e.releaseClaim(ctx, idx, nodeName); err != nil {
			e.log.Error("could not release a range claim after the server row was not written", "node", nodeName, "claim", claim, "err", err)
		}
	}
	peer, err := bootstrap.BuildMeshPeer(nodeName, selfCIDR.String(), meshIP.String(), req)
	if err != nil {
		giveBack()
		return bootstrap.Allocation{}, fmt.Errorf("%w: %w", bootstrap.ErrInvalidMeshClaim, err)
	}
	peer.Labels = map[string]string{meshPeerServerLabel: "true"}
	enrollID, err := newEnrollID()
	if err != nil {
		giveBack()
		return bootstrap.Allocation{}, err
	}
	// Stamped like every other enroll, so no id an earlier enroll of this name
	// handed out survives this write — a release holding one must find a stranger's
	// peer and keep it, which is the invariant the fence rests on.
	stampEnrollID(peer, enrollID)
	if err := e.writePeer(ctx, peer, serverPeerWrite); err != nil {
		giveBack()
		return bootstrap.Allocation{}, fmt.Errorf("write mesh peer %q: %w", nodeName, err)
	}
	return bootstrap.Allocation{Fresh: own == nil, EnrollID: enrollID, PodCIDR: selfCIDR.String()}, nil
}

// samePrefix reports whether the CIDR string podCIDR is the prefix want.
func samePrefix(podCIDR string, want netip.Prefix) bool {
	p, err := netip.ParsePrefix(podCIDR)
	return err == nil && p.Masked() == want.Masked()
}

// ReserveServerMesh implements bootstrap.ServerMeshReserver: the existing server
// reserving a JOINING server's range on the etcd member route, before the member is
// added. The range is the one claim.MeshIP names (install.MeshNodePodCIDR, the same
// derivation the joiner's install, alias and netd seed use); a mesh IP that names
// no node range is ErrInvalidMeshClaim. Only the public key is ever written.
func (e *meshEnroller) ReserveServerMesh(ctx context.Context, nodeName string, claim bootstrap.MeshClaim) (bootstrap.Allocation, error) {
	cidr, err := install.MeshNodePodCIDR(claim.MeshIP)
	if err != nil {
		return bootstrap.Allocation{}, fmt.Errorf("%w: %w", bootstrap.ErrInvalidMeshClaim, err)
	}
	host, _, err := net.SplitHostPort(claim.Endpoint)
	if err != nil {
		return bootstrap.Allocation{}, fmt.Errorf("%w: endpoint %q: %w", bootstrap.ErrInvalidMeshClaim, claim.Endpoint, err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.claimServerRange(ctx, nodeName, cidr, netv1.MeshEnrollRequest{
		NodeName:  nodeName,
		PublicKey: claim.PublicKey,
		Endpoint:  claim.Endpoint,
	}, serverClaimOrigin{memberRoute: true, peerHost: host})
}

// ReleaseServerMesh implements bootstrap.ServerMeshReserver: the member route's undo
// of a FRESH reservation whose member add failed. It is ReleaseAllocation — the
// same enroll-id fence on the peer, the same holder fence on the claim.
func (e *meshEnroller) ReleaseServerMesh(ctx context.Context, nodeName string, alloc bootstrap.Allocation) error {
	return e.ReleaseAllocation(ctx, nodeName, alloc)
}

// BackfillClaims gives every existing MeshPeer its range claim, so a cluster whose
// peers predate claims is protected from the first start of this binary. It is
// idempotent (a claim already held by the peer's own name is left as it is) and
// never resolves a conflict: two peers at one /24, or a claim held by a name other
// than the peer's, is reported at ERROR and left for the operator.
func (e *meshEnroller) BackfillClaims(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	peers, err := e.listPeerObjects(ctx)
	if err != nil {
		return fmt.Errorf("list mesh peers: %w", err)
	}
	byIndex := map[int][]netv1.MeshPeer{}
	for _, p := range peers {
		if idx, ok := nodeIndexOf(e.clusterPod, p.Spec.PodCIDR); ok {
			byIndex[idx] = append(byIndex[idx], p)
		}
	}
	var errs []error
	for idx, holders := range byIndex {
		cidr, err := podnet.NodeCIDR(e.clusterPod, idx)
		if err != nil {
			continue
		}
		if len(holders) > 1 {
			names := make([]string, 0, len(holders))
			for _, p := range holders {
				names = append(names, p.Spec.NodeName)
			}
			slices.Sort(names)
			e.log.Error("two MeshPeers hold one pod range; pod IPs in it are not unique and this server will not choose between them. Delete the stale MeshPeer and its node",
				"podCIDR", cidr, "nodes", strings.Join(names, ","))
			continue
		}
		p := holders[0]
		holder, created, err := e.claimRange(ctx, idx, cidr, p.Spec.NodeName, rangeClaimMeta{server: isServerPeer(e.clusterPod, p)})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if holder != p.Spec.NodeName {
			e.log.Error("a pod range's claim and its MeshPeer name different nodes; this server will not choose between them",
				"podCIDR", cidr, "meshPeer", p.Spec.NodeName, "claimHolder", holder, "claim", meshRangeClaimNamespace+"/"+meshRangeClaimName(idx))
			continue
		}
		if created {
			e.log.Info("claimed the pod range of an existing MeshPeer", "node", p.Spec.NodeName, "podCIDR", cidr)
		}
	}
	return errors.Join(errs...)
}

// serverAPIEndpoints is the apiserver endpoint list a join is answered with: this
// server's own mesh IP first — so an agent that takes the first entry targets the
// server it joined through, exactly as before — then every OTHER server peer whose
// Node is Ready, sorted. A server whose Node is not Ready (a reservation that never
// started, a server parked on its data path) is left out. The list is informational
// for the agent; it does not make a worker fail over between servers.
//
// A MeshPeer list that fails answers with this server alone: a join must not fail
// because the list could not be widened.
func (e *meshEnroller) serverAPIEndpoints(ctx context.Context, selfName, selfMeshIP string, apiPort int, ready func(ctx context.Context, node string) bool) []string {
	port := strconv.Itoa(apiPort)
	out := []string{net.JoinHostPort(selfMeshIP, port)}
	peers, err := e.listPeerObjects(ctx)
	if err != nil {
		e.log.Warn("could not list the other servers for a join's apiserver list; advertising this server alone", "err", err)
		return out
	}
	var others []netip.Addr
	for _, p := range peers {
		if p.Spec.NodeName == selfName || !isServerPeer(e.clusterPod, p) || p.Spec.MeshIP == selfMeshIP {
			continue
		}
		addr, err := netip.ParseAddr(p.Spec.MeshIP)
		if err != nil {
			continue
		}
		if ready == nil || !ready(ctx, p.Spec.NodeName) {
			continue
		}
		others = append(others, addr)
	}
	slices.SortFunc(others, netip.Addr.Compare)
	for _, a := range others {
		out = append(out, net.JoinHostPort(a.String(), port))
	}
	return out
}
