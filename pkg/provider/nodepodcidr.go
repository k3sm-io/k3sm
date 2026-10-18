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

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"k3sm.io/darwin-net/pkg/podnet"
)

// NodePodCIDRFieldManager is the field manager the start-time spec.podCIDR
// patch is written under.
const NodePodCIDRFieldManager = "k3sm-node-podcidr"

// nodePodCIDRPublishTimeout bounds the one get and the one patch Publish makes.
const nodePodCIDRPublishTimeout = 10 * time.Second

// NodeGetPatcher is the slice of the typed Nodes client Publish needs: one read
// and one patch of this node's own Node object (both granted to system:node by
// the Node authorizer).
type NodeGetPatcher interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Node, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (*corev1.Node, error)
}

// NodePodRange is the pod address range a node publishes on its Node object as
// spec.podCIDR and spec.podCIDRs, the way k3s nodes carry the range their pods
// are addressed from. The range is the node's own /24 that darwin-net's IPAM
// allocates pod /32s from (the enrolled MeshPeer range on a mesh node, the
// index-0 carve on a single node); this type never derives a range of its own.
//
// The zero value publishes nothing, and so does a range that failed validation
// in NewNodePodRange.
type NodePodRange struct {
	prefix netip.Prefix
	log    *slog.Logger
}

// NewNodePodRange validates cidr, the node's pod range, against the node's
// mesh address meshIP: it must parse, be IPv4, have the width darwin-net carves
// node ranges at (a /24), lie inside the cluster pod CIDR, and contain meshIP.
// A range that fails any check is logged at Warn and the returned value
// publishes nothing: an unpublished range is recoverable on the next start,
// a wrong one is not (spec.podCIDR is immutable once set). A nil log discards.
func NewNodePodRange(cidr, meshIP string, log *slog.Logger) NodePodRange {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	p, err := validNodePodCIDR(cidr, meshIP)
	if err != nil {
		log.Warn("not publishing this node's pod range as spec.podCIDR", "podCIDR", cidr, "meshIP", meshIP, "err", err)
		return NodePodRange{log: log}
	}
	return NodePodRange{prefix: p, log: log}
}

// Prefix returns the validated range, or the invalid zero prefix when none.
func (r NodePodRange) Prefix() netip.Prefix { return r.prefix }

// validNodePodCIDR is NewNodePodRange's check, returning the masked range.
func validNodePodCIDR(cidr, meshIP string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse pod range: %w", err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("pod range %s is not IPv4", p)
	}
	carve, err := podnet.NodeCIDR(podnet.ClusterPodCIDR, 0)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("read the node range width: %w", err)
	}
	if p.Bits() != carve.Bits() {
		return netip.Prefix{}, fmt.Errorf("pod range %s is not a /%d", p, carve.Bits())
	}
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("pod range %s has host bits set", p)
	}
	if !podnet.ClusterPodCIDR.Contains(p.Addr()) {
		return netip.Prefix{}, fmt.Errorf("pod range %s is outside the cluster pod CIDR %s", p, podnet.ClusterPodCIDR)
	}
	mesh, err := netip.ParseAddr(meshIP)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse mesh address: %w", err)
	}
	if !p.Contains(mesh) {
		return netip.Prefix{}, fmt.Errorf("pod range %s does not contain the node's mesh address %s", p, mesh)
	}
	return p, nil
}

// Stamp sets spec.podCIDR and spec.podCIDRs on n, the Node object a fresh
// registration creates. It is a no-op without a valid range.
func (r NodePodRange) Stamp(n *corev1.Node) {
	if !r.prefix.IsValid() {
		return
	}
	s := r.prefix.String()
	n.Spec.PodCIDR = s
	n.Spec.PodCIDRs = []string{s}
}

// Publish sets the range on an existing Node object that carries none, once:
// one get, then at most one patch, each bounded, never retried. A Node that
// already carries the same range is left alone. A Node that carries a different
// one is logged at Warn naming both and left alone, because spec.podCIDR is
// immutable once set and the apiserver would reject the change. It is a no-op
// without a valid range. The error is the get's or the patch's, for the caller
// to log; a rejected patch is not retried.
func (r NodePodRange) Publish(ctx context.Context, nodes NodeGetPatcher, name string) error {
	if !r.prefix.IsValid() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, nodePodCIDRPublishTimeout)
	defer cancel()
	n, err := nodes.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node %s: %w", name, err)
	}
	want := r.prefix.String()
	have := n.Spec.PodCIDR
	if have == "" && len(n.Spec.PodCIDRs) > 0 {
		have = n.Spec.PodCIDRs[0]
	}
	switch {
	case have == want:
		return nil
	case have != "":
		r.log.Warn("this Node already carries a different spec.podCIDR than the range its pods are addressed from; leaving it, spec.podCIDR is immutable once set",
			"node", name, "podCIDR", have, "nodePodRange", want)
		return nil
	}
	patch, err := json.Marshal(map[string]any{"spec": map[string]any{"podCIDR": want, "podCIDRs": []string{want}}})
	if err != nil {
		return fmt.Errorf("encode podCIDR patch: %w", err)
	}
	if _, err := nodes.Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{FieldManager: NodePodCIDRFieldManager}); err != nil {
		return fmt.Errorf("patch node %s spec.podCIDR %s: %w", name, want, err)
	}
	r.log.Info("published this node's pod range", "node", name, "podCIDR", want)
	return nil
}
