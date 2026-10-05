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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/status"
)

// Abandoned claims. A joining server's range is reserved on the member route
// BEFORE its etcd member exists, so a join that never completes leaves a reserved
// range and a MeshPeer with a dead endpoint behind. That is the safe direction —
// nothing is evicted — but it must not linger forever. A claim is ABANDONED when it
// is older than abandonedClaimAge and either:
//
//   - it is a server's range whose holder has no Ready Node AND is not an etcd
//     member (by name, or by the peer host its reservation recorded, which is all an
//     unstarted learner has); or
//   - its holder has no MeshPeer at the range at all (an orphan claim).
//
// A worker's claim with a MeshPeer is never abandoned: a worker powered off for a
// week still owns its range. A server's own claim is never abandoned. The sweep
// runs once on server start; between starts the abandoned claims are only RECORDED
// for `k3sm status`.

// abandonedClaimAge is how old a claim must be before it can be abandoned. It is far
// longer than any join takes, so an in-flight join is never swept.
const abandonedClaimAge = 15 * time.Minute

// meshClaimRecordInterval is how often the running server re-records abandoned
// claims for `k3sm status`.
const meshClaimRecordInterval = 5 * time.Minute

// abandonedClaimInputs is everything abandonedClaims decides on, read once.
type abandonedClaimInputs struct {
	claims []coordinationv1.Lease
	peers  []netv1.MeshPeer
	// readyNodes is the set of node names whose Node is Ready.
	readyNodes map[string]bool
	// members is the etcd member list; membersKnown is false off the etcd posture
	// or when the list could not be read, and then no SERVER reservation is ever
	// judged abandoned (there is no member list to judge it against).
	members      []bootstrap.EtcdMember
	membersKnown bool
	self         string
	now          time.Time
}

// abandonedClaim is one claim the predicate selected, with the peer it reserves (nil
// for an orphan claim).
type abandonedClaim struct {
	claim *coordinationv1.Lease
	peer  *netv1.MeshPeer
	kind  string
}

// abandonedClaims applies the predicate. Pure.
func (e *meshEnroller) abandonedClaims(in abandonedClaimInputs) []abandonedClaim {
	var out []abandonedClaim
	for i := range in.claims {
		c := &in.claims[i]
		holder := claimHolder(c)
		if holder == "" || holder == in.self {
			continue
		}
		if c.Spec.AcquireTime == nil || in.now.Sub(c.Spec.AcquireTime.Time) < abandonedClaimAge {
			continue
		}
		claimed, err := netip.ParsePrefix(c.Annotations[meshRangeClaimPodCIDRAnnotation])
		if err != nil {
			// A claim this binary did not write; it is not judged at all.
			continue
		}
		var peer *netv1.MeshPeer
		for j := range in.peers {
			p := &in.peers[j]
			if p.Spec.NodeName == holder && samePrefix(p.Spec.PodCIDR, claimed) {
				peer = p
			}
		}
		if peer == nil {
			out = append(out, abandonedClaim{claim: c, kind: status.MeshClaimOrphan})
			continue
		}
		server := c.Labels[meshPeerServerLabel] == "true" || isServerPeer(e.clusterPod, *peer)
		if !server || in.readyNodes[holder] || !in.membersKnown {
			continue
		}
		if slices.ContainsFunc(in.members, func(m bootstrap.EtcdMember) bool {
			return m.Name == holder || memberOnHost(m, c.Annotations[meshRangeClaimPeerHostAnnotation])
		}) {
			continue
		}
		out = append(out, abandonedClaim{claim: c, peer: peer, kind: status.MeshClaimServerReservation})
	}
	return out
}

// memberOnHost reports whether one of m's peer URLs is on host.
func memberOnHost(m bootstrap.EtcdMember, host string) bool {
	if host == "" {
		return false
	}
	for _, p := range m.PeerURLs {
		if u, err := url.Parse(p); err == nil && u.Hostname() == host {
			return true
		}
	}
	return false
}

// readAbandonedClaimInputs reads the claims, peers and Ready nodes; members is the
// etcd member lister (nil off the etcd posture).
func (e *meshEnroller) readAbandonedClaimInputs(ctx context.Context, self string, members func(context.Context) ([]bootstrap.EtcdMember, error)) (abandonedClaimInputs, error) {
	in := abandonedClaimInputs{self: self, now: time.Now(), readyNodes: map[string]bool{}}
	var err error
	if in.claims, err = e.listClaims(ctx); err != nil {
		return in, err
	}
	if in.peers, err = e.listPeerObjects(ctx); err != nil {
		return in, fmt.Errorf("list mesh peers: %w", err)
	}
	if e.nodes == nil {
		return in, errors.New("no Node client")
	}
	nodes, err := e.nodes.List(ctx, metav1.ListOptions{})
	if err != nil {
		return in, fmt.Errorf("list nodes: %w", err)
	}
	for i := range nodes.Items {
		if nodeIsReady(&nodes.Items[i]) {
			in.readyNodes[nodes.Items[i].Name] = true
		}
	}
	if members != nil {
		ms, err := members(ctx)
		if err != nil {
			e.log.Warn("could not list the etcd members, so no server reservation is judged abandoned this time", "err", err)
		} else {
			in.members, in.membersKnown = ms, true
		}
	}
	return in, nil
}

// nodeIsReady reports whether n's Ready condition is True.
func nodeIsReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// SweepAbandonedClaims deletes every abandoned claim and, for a server
// reservation, the MeshPeer it reserved — each delete preconditioned on the object
// read, so anything re-written since is kept. It returns what it could not remove.
func (e *meshEnroller) SweepAbandonedClaims(ctx context.Context, self string, members func(context.Context) ([]bootstrap.EtcdMember, error)) ([]abandonedClaim, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	in, err := e.readAbandonedClaimInputs(ctx, self, members)
	if err != nil {
		return nil, err
	}
	var left []abandonedClaim
	var errs []error
	for _, a := range e.abandonedClaims(in) {
		if a.peer != nil {
			if err := e.deletePeerExactly(ctx, a.peer); err != nil {
				errs = append(errs, err)
				left = append(left, a)
				continue
			}
		}
		if err := e.deleteClaim(ctx, a.claim); err != nil {
			errs = append(errs, err)
			left = append(left, a)
			continue
		}
		e.log.Warn("swept an abandoned pod-range claim", "claim", meshRangeClaimNamespace+"/"+a.claim.Name,
			"holder", claimHolder(a.claim), "podCIDR", a.claim.Annotations[meshRangeClaimPodCIDRAnnotation], "kind", a.kind)
	}
	return left, errors.Join(errs...)
}

// deletePeerExactly deletes the MeshPeer read as p, preconditioned on its UID and
// resourceVersion; a peer re-written or already gone is kept or skipped.
func (e *meshEnroller) deletePeerExactly(ctx context.Context, p *netv1.MeshPeer) error {
	pre := &metav1.Preconditions{ResourceVersion: &p.ResourceVersion}
	if p.UID != "" {
		pre.UID = &p.UID
	}
	err := e.client.Delete().Resource(meshPeerResource).Name(p.Name).
		Body(&metav1.DeleteOptions{Preconditions: pre}).Do(ctx).Error()
	if err == nil || apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return nil
	}
	return fmt.Errorf("delete mesh peer %q: %w", p.Name, err)
}

// recordAbandonedClaims writes the abandoned-claim record `k3sm status` reads.
func (e *meshEnroller) recordAbandonedClaims(ctx context.Context, workDir, self string, members func(context.Context) ([]bootstrap.EtcdMember, error)) error {
	e.mu.Lock()
	in, err := e.readAbandonedClaimInputs(ctx, self, members)
	e.mu.Unlock()
	if err != nil {
		return err
	}
	rec := status.MeshClaimsRecord{UpdatedAt: in.now.UTC()}
	for _, a := range e.abandonedClaims(in) {
		var acquired time.Time
		if a.claim.Spec.AcquireTime != nil {
			acquired = a.claim.Spec.AcquireTime.UTC()
		}
		rec.Abandoned = append(rec.Abandoned, status.AbandonedMeshClaim{
			Claim:    meshRangeClaimNamespace + "/" + a.claim.Name,
			Holder:   claimHolder(a.claim),
			PodCIDR:  a.claim.Annotations[meshRangeClaimPodCIDRAnnotation],
			Kind:     a.kind,
			Acquired: acquired,
		})
	}
	return writeFileAtomic(status.MeshClaimsPath(workDir), rec)
}

// writeFileAtomic writes v as JSON to path through a temporary file and a rename,
// so a reader never sees a half-written record.
func writeFileAtomic(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// runMeshClaimJanitor sweeps abandoned claims once, then re-records them every
// meshClaimRecordInterval until ctx ends. Every failure is logged and survivable:
// the janitor is housekeeping, never a reason to stop a server.
func runMeshClaimJanitor(ctx context.Context, e *meshEnroller, workDir, self string, members func(context.Context) ([]bootstrap.EtcdMember, error), logger *slog.Logger) {
	if left, err := e.SweepAbandonedClaims(ctx, self, members); err != nil {
		logger.Error("could not sweep every abandoned pod-range claim", "left", len(left), "err", err, "remedy", status.MeshClaimsRemedy)
	}
	for {
		if err := e.recordAbandonedClaims(ctx, workDir, self, members); err != nil && ctx.Err() == nil {
			logger.Warn("could not record the abandoned pod-range claims for `k3sm status`", "err", err)
		}
		t := time.NewTimer(meshClaimRecordInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
