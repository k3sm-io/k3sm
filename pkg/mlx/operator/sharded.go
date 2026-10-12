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
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/k3sm/pkg/interconnect"
	"k3sm.io/k3sm/pkg/mlx"
	"k3sm.io/k3sm/pkg/mlx/topology"
)

// Sharded requeue cadences. Placement and link health depend on objects this
// controller does not watch (Nodes, the Interconnect), so a sharded model
// re-checks itself on a timer instead of waiting for the ten-minute resync.
const (
	// placementRetry is how soon a model that could not be placed tries again:
	// a cable armed or a node joining should not wait for a resync.
	placementRetry = 30 * time.Second
	// gangRetry is how soon a gang restart re-checks whether the survivors are
	// gone, so the re-placement follows the teardown promptly.
	gangRetry = 2 * time.Second
	// linkRecheck is how often a gang placed on the network re-reads its
	// status. It watches no link, so it has no loss budget to meet.
	linkRecheck = 30 * time.Second
	// interconnectRecheck is how often a gang placed on the thunderbolt path
	// re-reads the Interconnect for LinksHealthy. The resolver marks a dead
	// member within 20 s, and plan I10 starts the re-render within 30 s, so
	// this is the remaining 10 s.
	interconnectRecheck = 10 * time.Second
	// interconnectRestartLimit is the shortest interval between two
	// interconnect-driven gang restarts of one model (plan I10). A flapping
	// cable cannot turn into a restart loop that re-downloads weights.
	interconnectRestartLimit = 5 * time.Minute
)

// interconnectRestart is the controller's memory of a model's last
// interconnect-driven gang restart.
type interconnectRestart struct {
	// at is when the restart was started; the next waits for
	// interconnectRestartLimit after it.
	at time.Time
	// toNetwork means the re-placement that follows has not happened yet, and
	// must land on the network (fallback network: re-render on pod IPs).
	toNetwork bool
}

// readCable reads what interconnect path selection needs: the thunderbolt
// Interconnect through the operator's own dynamic client, and the node cluster
// indices through the injected source, turned into slot-1 addresses. A cluster
// without the Interconnect CRD or object has no cable, which is an empty
// graph, not an error; the returned object is nil then.
func (c *Controller) readCable(ctx context.Context) (Cable, *netv1alpha1.Interconnect, error) {
	ic, err := interconnect.Store{Client: c.dyn}.Get(ctx, interconnect.Name)
	if apierrors.IsNotFound(err) {
		ic, err = nil, nil
	}
	if err != nil {
		return Cable{}, nil, fmt.Errorf("read interconnect %s: %w", interconnect.Name, err)
	}
	cable := Cable{Graph: topology.FromInterconnect(ic), Addresses: map[string]netip.Addr{}}
	if c.indices == nil || ic == nil || !ic.Spec.Enabled {
		return cable, ic, nil
	}
	idx, err := c.indices(ctx)
	if err != nil {
		return Cable{}, nil, fmt.Errorf("read node cluster indices: %w", err)
	}
	for node, i := range idx.Index {
		// A node beyond the interconnect ceiling has no address and is left
		// out, never given an improvised one.
		if a, err := netv1alpha1.InterconnectSlotAddress(i, netv1alpha1.InterconnectSlotMLXRank); err == nil {
			cable.Addresses[node] = a
		}
	}
	return cable, ic, nil
}

// reconcileSharded is Reconcile for a model with spec.distributed: GANG
// semantics over operator-owned rank Pods.
//
// The gang is all or nothing. A rank Pod that is missing, terminating, ended
// (a rank exits rather than restarts: its restart policy is Never), on a node
// that is NotReady or gone, or rendered from an older spec, means the gang is
// lost: every surviving rank Pod is deleted, and only once none is left is the
// model placed again and every rank created afresh. MLX's collective init
// blocks until every rank joins, so a partial gang can never serve; restarting
// one rank into a collective its peers are stuck in would hang it too.
//
// A spec or a cluster that cannot be served is a status, never a transient
// error, as on the single-node path.
func (c *Controller) reconcileSharded(ctx context.Context, key string, raw *unstructured.Unstructured, model *mlxv1alpha1.MLXModel) error {
	if err := ValidateDistributed(model.Spec); err != nil {
		c.log.Warn("sharded mlxmodel spec refused; no objects applied", "mlxmodel", key, "err", err)
		return c.writeStatus(ctx, raw, model, invalidSpecStatus(model, err, c.now()))
	}
	// The single-node StatefulSet of an earlier spec would hold a GPU a rank
	// needs.
	if err := c.deleteOwnedStatefulSet(ctx, model); err != nil {
		return err
	}

	desired := model.Spec.Distributed.Ranks
	if model.Spec.Replicas != nil && *model.Spec.Replicas == 0 {
		if err := c.deleteRankPods(ctx, model, "spec.replicas is 0"); err != nil {
			return err
		}
		return c.writeShardedStatus(ctx, raw, model, mlx.ShardObservation{Desired: 0})
	}

	// Fit first, as on the single-node path, but per RANK: a sharded model
	// exists precisely to serve memory no one node holds, so the whole of
	// spec.memory is not what one GPU must fund.
	perRank, err := mlx.PerRankMemory(model.Spec.Memory, desired)
	if err != nil {
		return c.writeShardedStatus(ctx, raw, model, mlx.ShardObservation{
			Desired: desired, PlacementReason: mlx.ReasonInsufficientMemory, PlacementMessage: err.Error(),
		})
	}
	if fit := ValidateFit(perRank, c.gpuFacts(ctx)); fit.Blocks() {
		c.log.Warn("sharded mlxmodel rank does not fit this node's gpu; no objects applied",
			"mlxmodel", key, "reason", fit.Reason, "message", fit.Message)
		return c.writeStatus(ctx, raw, model, blockedStatus(model, fit, c.now()))
	}

	headless, clusterIP, err := mlx.RenderShardedServices(model, c.opts)
	if err != nil {
		c.log.Warn("sharded mlxmodel spec cannot be rendered; no objects applied", "mlxmodel", key, "err", err)
		return c.writeStatus(ctx, raw, model, invalidSpecStatus(model, err, c.now()))
	}
	hash, err := mlx.SpecHash(model, c.opts)
	if err != nil {
		return fmt.Errorf("hash mlxmodel %s spec: %w", key, err)
	}

	pods, err := c.rankPods(ctx, model)
	if err != nil {
		return err
	}
	if len(pods) > 0 {
		fault, err := c.gangFault(ctx, model, pods, hash)
		if err != nil {
			return err
		}
		if fault != "" {
			if err := c.deleteRankPods(ctx, model, fault); err != nil {
				return err
			}
			c.queue.AddAfter(key, gangRetry)
			return c.writeShardedStatus(ctx, raw, model, mlx.ShardObservation{
				Desired: desired, GangRestart: fault, Pods: c.observeRanks(ctx, model, pods),
			})
		}
		// The gang is whole: keep the Services current and report.
		if err := c.applyService(ctx, headless); err != nil {
			return err
		}
		if err := c.applyService(ctx, clusterIP); err != nil {
			return err
		}
		cable, ic, err := c.readCable(ctx)
		if err != nil {
			return fmt.Errorf("read interconnect for mlxmodel %s: %w", key, err)
		}
		obs := placedObservation(pods, cable.Graph, desired, hash, c.observeRanks(ctx, model, pods))
		if obs.Interconnect != mlxv1alpha1.MLXInterconnectThunderbolt {
			c.queue.AddAfter(key, linkRecheck)
			return c.writeShardedStatus(ctx, raw, model, obs)
		}
		return c.watchInterconnect(ctx, key, raw, model, ic, obs)
	}

	// No rank exists: place the gang.
	cable, _, err := c.readCable(ctx)
	if err != nil {
		return fmt.Errorf("read interconnect for mlxmodel %s: %w", key, err)
	}
	cable.ForceNetwork = c.icRestarts[key].toNetwork
	nodes, err := c.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list nodes for mlxmodel %s: %w", key, err)
	}
	// Every pod in the cluster, not only this namespace's: a GPU slot is a node
	// resource, and a model in another namespace holds it just the same.
	allPods, err := c.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list pods for mlxmodel %s gpu slots: %w", key, err)
	}
	placement, err := Place(model, cable, nodes.Items, HeldGPUSlots(model, allPods.Items))
	var refused *PlacementError
	if errors.As(err, &refused) {
		c.log.Info("sharded mlxmodel cannot be placed yet; no rank pod created",
			"mlxmodel", key, "reason", refused.Reason, "message", refused.Message)
		c.queue.AddAfter(key, placementRetry)
		return c.writeShardedStatus(ctx, raw, model, mlx.ShardObservation{
			Desired: desired, PlacementReason: refused.Reason, PlacementMessage: refused.Message,
		})
	}
	if err != nil {
		return fmt.Errorf("place mlxmodel %s: %w", key, err)
	}
	objs, err := mlx.RenderSharded(model, c.opts, placement)
	if err != nil {
		c.log.Warn("sharded mlxmodel spec cannot be rendered; no objects applied", "mlxmodel", key, "err", err)
		return c.writeStatus(ctx, raw, model, invalidSpecStatus(model, err, c.now()))
	}
	if c.pullSecretExists(ctx, model.Namespace) {
		for _, pod := range objs.Pods {
			addPullSecret(&pod.Spec, c.pullName)
		}
	}
	if err := c.applySharded(ctx, objs); err != nil {
		return err
	}
	c.log.Info("placed sharded mlxmodel", "mlxmodel", key, "backend", placement.Backend,
		"interconnect", placement.Path(), "nodes", placedNodes(placement))
	if r, ok := c.icRestarts[key]; ok && r.toNetwork {
		r.toNetwork = false
		c.icRestarts[key] = r
	}
	created := make([]corev1.Pod, len(objs.Pods))
	for i, p := range objs.Pods {
		created[i] = *p
	}
	if placement.Path() == mlxv1alpha1.MLXInterconnectThunderbolt {
		c.queue.AddAfter(key, interconnectRecheck)
	}
	return c.writeShardedStatus(ctx, raw, model, placedObservation(created, cable.Graph, desired, hash, c.observeRanks(ctx, model, created)))
}

// watchInterconnect is the whole-gang reconcile for a gang placed on the
// thunderbolt path: LinksHealthy, and what a lost member costs (plan §4 and
// I10).
//
// A placed member that is no longer up sets LinksHealthy=False. Under the
// Interconnect's fallback network the gang is re-rendered on pod IPs: every
// rank is deleted (the gang restart the spec-hash path uses) and the
// re-placement that follows is forced onto the network. That restart is
// limited to one per model per interconnectRestartLimit; inside the limit the
// gang is held and the message says until when. Under fallback none the gang
// is held and reported. A gang on the network is never restarted because the
// cable came back: only the next gang restart re-resolves the path.
func (c *Controller) watchInterconnect(ctx context.Context, key string, raw *unstructured.Unstructured, model *mlxv1alpha1.MLXModel, ic *netv1alpha1.Interconnect, obs mlx.ShardObservation) error {
	c.queue.AddAfter(key, interconnectRecheck)
	if len(obs.DownLinks) == 0 {
		return c.writeShardedStatus(ctx, raw, model, obs)
	}
	fallback := netv1alpha1.InterconnectFallbackNetwork
	if ic != nil {
		fallback = ic.Spec.EffectiveFallback()
	}
	if fallback == netv1alpha1.InterconnectFallbackNone {
		obs.DownLinkAction = "the Interconnect's fallback is none, so the gang is held on the interconnect until the link is back"
		c.log.Warn("sharded mlxmodel lost an interconnect link; fallback none, holding the gang",
			"mlxmodel", key, "down", obs.DownLinks)
		return c.writeShardedStatus(ctx, raw, model, obs)
	}
	now := c.now()
	if last, ok := c.icRestarts[key]; ok && now.Sub(last.at) < interconnectRestartLimit {
		next := last.at.Add(interconnectRestartLimit)
		obs.DownLinkAction = fmt.Sprintf("the Interconnect's fallback is network, but this model had an interconnect-driven gang restart at %s; the re-render on pod IPs waits until %s (at most one per %s)",
			last.at.UTC().Format(time.RFC3339), next.UTC().Format(time.RFC3339), interconnectRestartLimit)
		c.queue.AddAfter(key, next.Sub(now))
		return c.writeShardedStatus(ctx, raw, model, obs)
	}
	fault := fmt.Sprintf("interconnect link %s is down; re-rendering the gang on pod IPs (fallback network)", strings.Join(obs.DownLinks, ", "))
	if err := c.deleteRankPods(ctx, model, fault); err != nil {
		return err
	}
	c.icRestarts[key] = interconnectRestart{at: now, toNetwork: true}
	c.log.Warn("sharded mlxmodel lost an interconnect link; re-rendering on pod IPs", "mlxmodel", key, "down", obs.DownLinks)
	c.queue.AddAfter(key, gangRetry)
	obs.DownLinkAction = "the Interconnect's fallback is network, so the gang is re-rendered on pod IPs"
	return c.writeShardedStatus(ctx, raw, model, mlx.ShardObservation{
		Desired: obs.Desired, GangRestart: fault, Pods: obs.Pods, Interconnect: obs.Interconnect,
		PlacedLinks: obs.PlacedLinks, DownLinks: obs.DownLinks, DownLinkAction: obs.DownLinkAction,
	})
}

// applySharded applies the Services, creates the cache claims, then creates the
// rank Pods — Services first for the same reason the single-node apply puts the
// StatefulSet last: a rank resolves its peers through the headless Service the
// moment it starts.
//
// Claims and Pods are CREATED, not applied. A bound claim's spec is immutable
// and a Pod's spec nearly so, so a re-apply could only fail; an existing claim
// (AlreadyExists) is the node's weight cache from an earlier gang and is exactly
// what the new rank should mount.
func (c *Controller) applySharded(ctx context.Context, objs *mlx.ShardedObjects) error {
	if err := c.applyService(ctx, objs.HeadlessService); err != nil {
		return err
	}
	if err := c.applyService(ctx, objs.ClusterIPService); err != nil {
		return err
	}
	for _, claim := range objs.Claims {
		_, err := c.client.CoreV1().PersistentVolumeClaims(claim.Namespace).Create(ctx, claim, metav1.CreateOptions{FieldManager: FieldManager})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create cache claim %s/%s: %w", claim.Namespace, claim.Name, err)
		}
	}
	for _, pod := range objs.Pods {
		if _, err := c.client.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{FieldManager: FieldManager}); err != nil {
			// AlreadyExists here means a Pod by that name that this operator's
			// rank selector did not list — not ours, so not ours to replace.
			return fmt.Errorf("create rank pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return nil
}

// rankPods lists the model's rank Pods, sorted by name.
func (c *Controller) rankPods(ctx context.Context, model *mlxv1alpha1.MLXModel) ([]corev1.Pod, error) {
	list, err := c.client.CoreV1().Pods(model.Namespace).List(ctx, metav1.ListOptions{LabelSelector: mlx.ShardedSelector(model.Name)})
	if err != nil {
		return nil, fmt.Errorf("list rank pods for mlxmodel %s/%s: %w", model.Namespace, model.Name, err)
	}
	pods := list.Items
	slices.SortFunc(pods, func(a, b corev1.Pod) int { return strings.Compare(a.Name, b.Name) })
	return pods, nil
}

// gangFault returns why the gang is lost, or "" when it is whole: exactly
// ranks Pods with ranks 0..n-1, none terminating or ended, every one on the
// current spec hash and on a node that exists and is Ready.
func (c *Controller) gangFault(ctx context.Context, model *mlxv1alpha1.MLXModel, pods []corev1.Pod, hash string) (string, error) {
	n := int(model.Spec.Distributed.Ranks)
	seen := make([]bool, n)
	nodeReadyCache := map[string]bool{}
	for i := range pods {
		pod := &pods[i]
		rank, err := strconv.Atoi(pod.Labels[mlx.LabelRank])
		if err != nil || rank < 0 || rank >= n || seen[rank] || pod.Name != mlx.RankPodName(model.Name, rank) {
			return fmt.Sprintf("rank pod %s does not belong to a %d-rank gang", pod.Name, n), nil
		}
		seen[rank] = true
		switch {
		case pod.DeletionTimestamp != nil:
			return fmt.Sprintf("rank pod %s is terminating", pod.Name), nil
		case pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded:
			return fmt.Sprintf("rank pod %s ended (%s)", pod.Name, pod.Status.Phase), nil
		case pod.Annotations[mlx.AnnotationSpecHash] != hash:
			return fmt.Sprintf("rank pod %s was rendered from an older spec", pod.Name), nil
		}
		ready, ok := nodeReadyCache[pod.Spec.NodeName]
		if !ok {
			node, err := c.client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
			switch {
			case apierrors.IsNotFound(err):
				ready = false
			case err != nil:
				return "", fmt.Errorf("get node %s for rank pod %s: %w", pod.Spec.NodeName, pod.Name, err)
			default:
				ready = nodeReady(node)
			}
			nodeReadyCache[pod.Spec.NodeName] = ready
		}
		if !ready {
			return fmt.Sprintf("rank pod %s is on node %s, which is NotReady or gone", pod.Name, pod.Spec.NodeName), nil
		}
	}
	for rank, ok := range seen {
		if !ok {
			return fmt.Sprintf("rank pod %s is missing", mlx.RankPodName(model.Name, rank)), nil
		}
	}
	return "", nil
}

// deleteRankPods deletes every rank Pod of the model that is not already
// terminating. NotFound is success: the Pod is gone, which is the goal.
func (c *Controller) deleteRankPods(ctx context.Context, model *mlxv1alpha1.MLXModel, why string) error {
	pods, err := c.rankPods(ctx, model)
	if err != nil {
		return err
	}
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		err := c.client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: ptr.To(pod.UID)},
		})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete rank pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		c.log.Info("deleted rank pod for a gang restart", "pod", pod.Namespace+"/"+pod.Name, "why", why)
	}
	return nil
}

// deleteOwnedStatefulSet removes the single-node StatefulSet an earlier,
// unsharded spec of this model rendered — only when this model controls it.
func (c *Controller) deleteOwnedStatefulSet(ctx context.Context, model *mlxv1alpha1.MLXModel) error {
	sts, err := c.client.AppsV1().StatefulSets(model.Namespace).Get(ctx, mlx.StatefulSetName(model.Name), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get statefulset for mlxmodel %s/%s: %w", model.Namespace, model.Name, err)
	}
	if owner := metav1.GetControllerOfNoCopy(sts); owner == nil || owner.UID != model.UID {
		return nil
	}
	err = c.client.AppsV1().StatefulSets(model.Namespace).Delete(ctx, sts.Name, metav1.DeleteOptions{
		PropagationPolicy: ptr.To(metav1.DeletePropagationBackground),
	})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete single-node statefulset %s/%s: %w", sts.Namespace, sts.Name, err)
	}
	return nil
}

// observeRanks builds the per-rank PodStates, probing rank 0 when it runs but
// is not ready (it is the only rank with a serving surface).
func (c *Controller) observeRanks(ctx context.Context, model *mlxv1alpha1.MLXModel, pods []corev1.Pod) []mlx.PodState {
	out := make([]mlx.PodState, 0, len(pods))
	rank0 := mlx.RankPodName(model.Name, 0)
	for i := range pods {
		pod := &pods[i]
		state := mlx.PodState{
			Name:        pod.Name,
			Phase:       pod.Status.Phase,
			Ready:       podReady(pod),
			Revision:    pod.Annotations[mlx.AnnotationSpecHash],
			Terminating: pod.DeletionTimestamp != nil,
		}
		if pod.Name == rank0 && !state.Ready && state.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			state.Probe = c.probe(ctx, model, pod.Status.PodIP)
		}
		out = append(out, state)
	}
	return out
}

// placedObservation is the observation of a placed gang: placement facts read
// back from the rank Pods' own annotations (what the gang was placed for, not
// what a fresh placement would choose), and the placed links re-checked
// against the live interconnect graph.
func placedObservation(pods []corev1.Pod, graph topology.Graph, desired int32, hash string, states []mlx.PodState) mlx.ShardObservation {
	obs := mlx.ShardObservation{Desired: desired, Placed: true, SpecHash: hash, Pods: states}
	var nodes []string
	for i := range pods {
		nodes = append(nodes, pods[i].Spec.NodeName)
	}
	if len(pods) > 0 {
		obs.Backend = mlxv1alpha1.MLXDistributedBackend(pods[0].Annotations[mlx.AnnotationBackend])
		obs.Interconnect = mlx.Placement{Interconnect: mlxv1alpha1.MLXInterconnect(pods[0].Annotations[mlx.AnnotationInterconnect])}.Path()
		links := mlx.ParsePlacedLinks(pods[0].Annotations[mlx.AnnotationPlacedLinks])
		obs.PlacedLinks = len(links)
		for _, l := range links {
			if _, ok := graph.Edge(l[0], l[1]); !ok {
				obs.DownLinks = append(obs.DownLinks, l[0]+"/"+l[1])
			}
		}
	}
	obs.PlacementMessage = fmt.Sprintf("%d ranks placed on %s (%s over %s)", len(pods), strings.Join(nodes, ", "), obs.Backend, obs.Interconnect)
	return obs
}

// placedNodes lists a placement's nodes in rank order, for a log line.
func placedNodes(p Placement) []string {
	out := make([]string, len(p.Ranks))
	for i, r := range p.Ranks {
		out[i] = r.Node
	}
	return out
}

// writeShardedStatus derives and writes a sharded status.
func (c *Controller) writeShardedStatus(ctx context.Context, raw *unstructured.Unstructured, model *mlxv1alpha1.MLXModel, obs mlx.ShardObservation) error {
	status := mlx.DeriveShardedStatus(model, obs, mlx.StatusOptions{Options: c.opts, ClusterDomain: c.domain}, c.now())
	return c.writeStatus(ctx, raw, model, status)
}
