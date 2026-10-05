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

package mlx

import (
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

// The conditions a SHARDED MLXModel carries beside Ready. They are published
// here, beside the reasons, because apis publishes only the Ready condition
// type; a consumer reads them by these names.
const (
	// ConditionShardsPlaced reports whether the operator found a placement for
	// every rank. False means no rank Pod exists, and the reason says what the
	// cluster lacks.
	ConditionShardsPlaced = "ShardsPlaced"
	// ConditionLinksHealthy reports whether every direct link the placement
	// counted on is still up.
	ConditionLinksHealthy = "LinksHealthy"
)

// Reasons carried by ShardsPlaced (and, while no placement exists, by Ready).
const (
	// ReasonPlaced means every rank has a node and its Pod was created.
	ReasonPlaced = "Placed"
	// ReasonNoDirectLinkTopology means the cluster lacks the nodes or the
	// cables the requested backend needs (too few GPU nodes matching the
	// selector, or no RDMA clique for jaccl). It is never answered with a
	// single-node fallback.
	ReasonNoDirectLinkTopology = "NoDirectLinkTopology"
	// ReasonInsufficientMemory means the per-rank share of spec.memory does not
	// fit on enough candidate nodes, or cannot fund a serving context at all.
	ReasonInsufficientMemory = "InsufficientMemory"
)

// Reasons carried by LinksHealthy.
const (
	// ReasonLinksUp means every direct link the placement counted on is up (or
	// the placement counted on none, every hop riding the mesh).
	ReasonLinksUp = "LinksUp"
	// ReasonLinkDegraded means a placed direct link is no longer up. A ring
	// gang keeps serving, its hop now riding the mesh; a jaccl gang cannot,
	// because RDMA has no fallback path.
	ReasonLinkDegraded = "LinkDegraded"
)

// ShardObservation is the injected state one sharded status derivation reads.
// Like Observation it is a seam: the operator builds it from the API server, a
// test builds it by hand.
type ShardObservation struct {
	// Desired is the number of ranks that must be ready: spec.distributed.ranks,
	// or 0 when the model is scaled to zero.
	Desired int32
	// Placed reports whether a placement exists (every rank Pod was created
	// from one). When false, PlacementReason and PlacementMessage say why.
	Placed bool
	// PlacementReason is a ShardsPlaced reason: ReasonPlaced, or a refusal.
	PlacementReason string
	// PlacementMessage is the human half of the placement verdict: the nodes
	// and backend when placed, what was missing when not.
	PlacementMessage string
	// GangRestart, when non-empty, means the operator is tearing the gang down
	// to re-place it, and says why. A partial gang never serves.
	GangRestart string
	// Backend is the resolved backend of the placed gang (ring or jaccl).
	Backend mlxv1alpha1.MLXDistributedBackend
	// PlacedLinks is how many direct links the placement counted on.
	PlacedLinks int
	// DownLinks are the placed links ("nodeA/nodeB") that are no longer up.
	DownLinks []string
	// Pods are the rank Pods in rank order. Revision carries each Pod's
	// AnnotationSpecHash; only rank 0 is probed.
	Pods []PodState
	// SpecHash is the current spec hash (see SpecHash): a rank Pod on another
	// hash is stale.
	SpecHash string
	// ResolvedRevision is the model revision, when known (sticky, as in
	// DeriveStatus).
	ResolvedRevision string
}

// DeriveShardedStatus computes a sharded MLXModel's status. It is pure in the
// same way DeriveStatus is, and it keeps the same conditions-first contract:
// Ready is the condition a consumer branches on, Phase is projected from it,
// and the two sharded conditions sit beside it.
//
// Ready is True only when EVERY rank is ready on the current spec: a sharded
// model is one logical replica, and rank 0 cannot answer a request its peers
// are not there to compute. While no placement exists, Ready carries the
// placement refusal's reason, which projects to the Pending phase because the
// operator re-places on its own when the cluster changes.
func DeriveShardedStatus(m *mlxv1alpha1.MLXModel, obs ShardObservation, opts StatusOptions, now time.Time) mlxv1alpha1.MLXModelStatus {
	if m == nil {
		return mlxv1alpha1.MLXModelStatus{}
	}
	status := *m.Status.DeepCopy()
	status.ObservedGeneration = m.Generation
	set := func(typ string, ok bool, reason, message string) {
		cs := metav1.ConditionFalse
		if ok {
			cs = metav1.ConditionTrue
		}
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type: typ, Status: cs, Reason: reason, Message: message,
			ObservedGeneration: m.Generation, LastTransitionTime: metav1.NewTime(now),
		})
	}

	var counts replicaCounts
	switch {
	case obs.Desired <= 0:
		meta.RemoveStatusCondition(&status.Conditions, ConditionShardsPlaced)
		meta.RemoveStatusCondition(&status.Conditions, ConditionLinksHealthy)
		set(mlxv1alpha1.MLXModelConditionReady, false, ReasonScaledToZero, "spec.replicas is 0: no rank is serving")
	case obs.GangRestart != "":
		// ShardsPlaced and LinksHealthy keep their last values: they describe
		// the placement being torn down until a new one replaces it.
		counts.replicas = int32(len(obs.Pods))
		set(mlxv1alpha1.MLXModelConditionReady, false, ReasonPending, "gang restart: "+obs.GangRestart)
	case !obs.Placed:
		meta.RemoveStatusCondition(&status.Conditions, ConditionLinksHealthy)
		set(ConditionShardsPlaced, false, obs.PlacementReason, obs.PlacementMessage)
		set(mlxv1alpha1.MLXModelConditionReady, false, obs.PlacementReason, obs.PlacementMessage)
	default:
		set(ConditionShardsPlaced, true, ReasonPlaced, obs.PlacementMessage)
		linksOK, linkReason, linkMessage := linksVerdict(obs)
		set(ConditionLinksHealthy, linksOK, linkReason, linkMessage)
		pods := Observation{Pods: obs.Pods, CurrentRevision: obs.SpecHash}
		ready, c, reason, message := deriveReady(obs.Desired, pods, unitRanks)
		counts = c
		set(mlxv1alpha1.MLXModelConditionReady, ready, reason, message)
	}
	status.Replicas = counts.replicas
	status.UpdatedReplicas = counts.updated
	status.ReadyReplicas = counts.ready

	status.Phase = PhaseFromConditions(status.Conditions)
	if obs.ResolvedRevision != "" {
		status.ResolvedRevision = obs.ResolvedRevision
	}
	// No roll exception here: a sharded model has no rolling update. A spec
	// change is a gang restart, and nothing serves during one.
	status.Endpoint = ""
	if status.Phase == mlxv1alpha1.MLXModelPhaseReady {
		status.Endpoint = endpoint(m, opts)
	}
	return status
}

// linksVerdict is LinksHealthy for a placed gang.
func linksVerdict(obs ShardObservation) (ok bool, reason, message string) {
	if len(obs.DownLinks) == 0 {
		if obs.PlacedLinks == 0 {
			return true, ReasonLinksUp, "the placement counts on no direct link; every hop rides the mesh"
		}
		return true, ReasonLinksUp, fmt.Sprintf("all %d placed direct links are up", obs.PlacedLinks)
	}
	consequence := "the ring keeps serving with that hop over the mesh"
	if obs.Backend == mlxv1alpha1.MLXDistributedBackendJACCL {
		consequence = "jaccl has no fallback path, so the gang cannot serve until the link is back or the gang restarts"
	}
	return false, ReasonLinkDegraded, fmt.Sprintf("direct link %s is down (%d of %d placed links); %s",
		strings.Join(obs.DownLinks, ", "), len(obs.DownLinks), obs.PlacedLinks, consequence)
}
