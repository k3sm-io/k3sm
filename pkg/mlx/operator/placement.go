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

package operator

import (
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/k3sm/pkg/mlx"
	"k3sm.io/k3sm/pkg/mlx/topology"
)

// Placement is a decided placement of a sharded model's ranks (see
// mlx.Placement; the type lives beside the render that consumes it).
type Placement = mlx.Placement

// RankPlacement is where one rank runs (see mlx.RankPlacement).
type RankPlacement = mlx.RankPlacement

// Topology supplies the direct-link graph placement and LinksHealthy read. It
// is defined here, at the consumer, so the controller's tests hand it a fake
// graph; the production source lists the resolver-written DirectLink objects.
type Topology interface {
	// Graph returns the current up-link graph. An empty graph is a valid
	// answer (no cables), never an error.
	Graph(ctx context.Context) (topology.Graph, error)
}

// TopologyFunc adapts a plain function to Topology.
type TopologyFunc func(ctx context.Context) (topology.Graph, error)

// Graph calls f.
func (f TopologyFunc) Graph(ctx context.Context) (topology.Graph, error) { return f(ctx) }

// StaticTopology returns a Topology that always reports g.
func StaticTopology(g topology.Graph) Topology {
	return TopologyFunc(func(context.Context) (topology.Graph, error) { return g, nil })
}

// PlacementError is a placement that could not be made. It is a STATUS, not a
// transient error: the reconcile reports it as ShardsPlaced=False with Reason
// and Message, applies no rank Pod, and tries again later because the cluster
// (its nodes, its cables) can change without the spec changing. There is never
// a single-node fallback: a sharding request served on one node would look
// like success.
type PlacementError struct {
	// Reason is mlx.ReasonNoDirectLinkTopology or mlx.ReasonInsufficientMemory.
	Reason string
	// Message names what was missing.
	Message string
}

// Error returns the message prefixed by the reason.
func (e *PlacementError) Error() string { return e.Reason + ": " + e.Message }

// Place decides where a sharded model's ranks run. It is pure: the graph and
// nodes are inputs, nothing is read or written, and the same inputs always give
// the same placement.
//
// The rules, in order:
//
//   - Each rank needs mlx.PerRankMemory of the model's memory (its share plus
//     the per-process floor). A share that cannot fund the minimum serving
//     context is InsufficientMemory before any node is looked at.
//   - A candidate node is Ready, schedulable, matches the guarded pod node
//     selector (spec.nodeSelector under the darwin and GPU-present guardrails,
//     the same selector the rank Pod carries), and advertises the
//     mlx.k3sm.io/gpu resource. Fewer than ranks candidates is
//     NoDirectLinkTopology; fewer than ranks candidates whose allocatable
//     memory holds the per-rank share is InsufficientMemory.
//   - jaccl needs a CLIQUE of ranks fitting nodes, every one labelled
//     k3sm.io/rdma, with RDMA at both ends of every link.
//   - ring prefers a CYCLE of ranks fitting nodes in the cable graph, so every
//     hop is a direct route; failing that it takes the first ranks fitting
//     nodes by name, and the hops without a cable ride the mesh.
//   - auto is jaccl when a jaccl placement exists, else ring.
//
// Among equal choices the lexicographically first wins (the topology searches
// are ordered), so a gang restart over an unchanged cluster lands every rank
// where it was.
func Place(model *mlxv1alpha1.MLXModel, graph topology.Graph, nodes []corev1.Node) (Placement, error) {
	d := model.Spec.Distributed
	if d == nil || d.Ranks < 2 {
		return Placement{}, &PlacementError{Reason: mlx.ReasonNoDirectLinkTopology, Message: "spec.distributed.ranks must be at least 2"}
	}
	n := int(d.Ranks)

	perRank, err := mlx.PerRankMemory(model.Spec.Memory, d.Ranks)
	if err != nil {
		return Placement{}, &PlacementError{Reason: mlx.ReasonInsufficientMemory, Message: err.Error()}
	}

	selector, err := mlx.PodNodeSelector(model.Spec.NodeSelector)
	if err != nil {
		return Placement{}, &PlacementError{Reason: mlx.ReasonNoDirectLinkTopology, Message: err.Error()}
	}
	sel := labels.SelectorFromSet(selector)

	sorted := slices.Clone(nodes)
	slices.SortFunc(sorted, func(a, b corev1.Node) int { return strings.Compare(a.Name, b.Name) })
	var candidates, fitting []string
	byName := map[string]*corev1.Node{}
	for i := range sorted {
		node := &sorted[i]
		if !nodeReady(node) || node.Spec.Unschedulable || !sel.Matches(labels.Set(node.Labels)) || !hasGPU(node) {
			continue
		}
		candidates = append(candidates, node.Name)
		byName[node.Name] = node
		if mem, ok := node.Status.Allocatable[corev1.ResourceMemory]; ok && mem.Cmp(perRank) >= 0 {
			fitting = append(fitting, node.Name)
		}
	}
	if len(candidates) < n {
		return Placement{}, &PlacementError{
			Reason: mlx.ReasonNoDirectLinkTopology,
			Message: fmt.Sprintf("%d ranks need %d Ready nodes with %s matching the node selector, found %d%s",
				n, n, mlxv1alpha1.ResourceGPU, len(candidates), nameList(candidates)),
		}
	}
	if len(fitting) < n {
		return Placement{}, &PlacementError{
			Reason: mlx.ReasonInsufficientMemory,
			Message: fmt.Sprintf("each of %d ranks needs %s of allocatable memory; %d of %d candidate nodes have it%s",
				n, perRank.String(), len(fitting), len(candidates), nameList(fitting)),
		}
	}

	switch d.Backend {
	case mlxv1alpha1.MLXDistributedBackendJACCL:
		return placeJACCL(graph, fitting, byName, n)
	case mlxv1alpha1.MLXDistributedBackendRing:
		return placeRing(graph, fitting, n), nil
	default: // auto, and the empty value the CRD defaults to auto
		if p, err := placeJACCL(graph, fitting, byName, n); err == nil {
			return p, nil
		}
		return placeRing(graph, fitting, n), nil
	}
}

// placeJACCL finds the first RDMA clique of n fitting nodes that all carry the
// k3sm.io/rdma label.
func placeJACCL(graph topology.Graph, fitting []string, byName map[string]*corev1.Node, n int) (Placement, error) {
	var rdma []string
	for _, name := range fitting {
		if _, ok := byName[name].Labels[netv1alpha1.LabelRDMA]; ok {
			rdma = append(rdma, name)
		}
	}
	for _, clique := range graph.Clique(n, true) {
		if !subset(clique, rdma) {
			continue
		}
		p := Placement{Backend: mlxv1alpha1.MLXDistributedBackendJACCL}
		for i, node := range clique {
			devices := make([]string, n)
			for j, peer := range clique {
				if j == i {
					continue
				}
				e, _ := graph.Edge(node, peer)
				devices[j] = e.LocalRDMA
			}
			p.Ranks = append(p.Ranks, RankPlacement{Rank: i, Node: node, RDMADevices: devices})
			for j := i + 1; j < n; j++ {
				p.Links = append(p.Links, pair(node, clique[j]))
			}
		}
		return p, nil
	}
	return Placement{}, &PlacementError{
		Reason: mlx.ReasonNoDirectLinkTopology,
		Message: fmt.Sprintf("no rdma clique of %d: jaccl needs %d nodes labelled %s joined pairwise by up RDMA links; %d fitting nodes carry the label%s",
			n, n, netv1alpha1.LabelRDMA, len(rdma), nameList(rdma)),
	}
}

// placeRing takes the first cycle of n fitting nodes, else the first n fitting
// nodes by name. It cannot fail: Place has already checked there are n.
func placeRing(graph topology.Graph, fitting []string, n int) Placement {
	order := fitting[:n]
	for _, cycle := range graph.Ring(n) {
		if subset(cycle, fitting) {
			order = cycle
			break
		}
	}
	p := Placement{Backend: mlxv1alpha1.MLXDistributedBackendRing}
	for i, node := range order {
		p.Ranks = append(p.Ranks, RankPlacement{Rank: i, Node: node})
	}
	hops := n
	if n == 2 {
		hops = 1 // a two-rank ring is one link, not two
	}
	for i := 0; i < hops; i++ {
		a, b := order[i], order[(i+1)%n]
		if _, ok := graph.Edge(a, b); ok {
			p.Links = append(p.Links, pair(a, b))
		}
	}
	return p
}

// nodeReady reads a node's Ready condition.
func nodeReady(node *corev1.Node) bool {
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// hasGPU reports whether the node advertises at least one unit of the MLX GPU
// extended resource.
func hasGPU(node *corev1.Node) bool {
	q, ok := node.Status.Allocatable[corev1.ResourceName(mlxv1alpha1.ResourceGPU)]
	return ok && q.Cmp(*resource.NewQuantity(1, resource.DecimalSI)) >= 0
}

// subset reports whether every element of a is in b.
func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// pair returns a sorted node pair.
func pair(a, b string) [2]string {
	if b < a {
		a, b = b, a
	}
	return [2]string{a, b}
}

// nameList renders a node list for a message: " (a, b)" or "".
func nameList(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return " (" + strings.Join(names, ", ") + ")"
}
