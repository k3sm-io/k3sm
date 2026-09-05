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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/darwin-net/pkg/dns"
)

// Reasons carried by the Ready condition. They are the machine-readable part of
// the status: the Phase printer column is derived from them (see
// PhaseFromConditions), so a consumer that needs to know WHICH not-ready state a
// model is in reads the reason, never the phase.
//
// Every reason below is derivable from observed pod and probe state alone. There
// is deliberately no reason that would require a signal the operator does not
// have — a "VerifyingWeights" or "Restarting" reason would have to be guessed,
// and a guessed status is worse than a coarse one.
const (
	// ReasonServing means at least the desired number of replicas have a passing
	// readiness probe, which is exactly the condition under which the ClusterIP
	// Service carries traffic to them.
	ReasonServing = "Serving"
	// ReasonPending means no replica is running yet: the pods are unscheduled,
	// scheduled but not started, or gone.
	ReasonPending = "Pending"
	// ReasonScaledToZero means spec.replicas is 0. It is a distinct reason from
	// ReasonPending because it is a requested state, not a wait — nothing will
	// change until the spec does.
	ReasonScaledToZero = "ScaledToZero"
	// ReasonDownloading means a replica is running, is not ready, and its serving
	// surface has not answered at all. The first thing a serving container does
	// is fetch weights, and it answers nothing until that fetch is far enough
	// along to start the engine.
	ReasonDownloading = "Downloading"
	// ReasonLoading means a replica is running and its serving surface answers,
	// but readiness has not passed — the weights are on disk and the engine is
	// loading them into unified memory.
	ReasonLoading = "Loading"
	// ReasonPodFailed means a replica reached the terminal Failed phase while the
	// model is not serving. Under the StatefulSet's Always restart policy this
	// should not happen, which is why it is reported rather than waited out.
	ReasonPodFailed = "PodFailed"
)

// ProbeVerdict is one replica's serving-surface verdict as observed by the
// operator's own probe client — the OpenAI-compatible /health + /v1/models
// check, which lives outside this package. The verdict is INJECTED: nothing here
// opens a connection.
//
// It exists to split a single not-ready bit into two distinguishable states. The
// rendered pod carries a readiness probe and NOTHING else (no liveness, no
// startup — a kill mid-download restarts the download from zero), so readiness
// alone cannot tell "still fetching gigabytes" from "fetched, loading into
// memory". Reachability of the serving surface can.
type ProbeVerdict string

const (
	// ProbeUnknown means the replica has not been probed, or the probe did not
	// complete. It is the zero value, so a caller that has no probe client yet
	// gets Downloading rather than a wrong Loading.
	ProbeUnknown ProbeVerdict = ""
	// ProbeUnreachable means the serving port did not answer.
	ProbeUnreachable ProbeVerdict = "Unreachable"
	// ProbeLoading means the serving surface answered but does not yet offer the
	// model.
	ProbeLoading ProbeVerdict = "Loading"
	// ProbeServing means the serving surface answered and offers the model.
	ProbeServing ProbeVerdict = "Serving"
)

// PodState is one observed serving replica: what the pod lister said about it,
// and what the probe client said about it. It is the fake seam — a reconcile
// builds these from an informer, a test builds them by hand, and the derivation
// below cannot tell the difference.
type PodState struct {
	// Name is the pod name, used in condition messages so a not-ready model
	// names the replica holding it back.
	Name string
	// Phase is the pod's phase as reported by the kubelet.
	Phase corev1.PodPhase
	// Ready is the pod's Ready condition. This — not Probe — decides whether a
	// replica counts as serving, because it is what gates the replica's address
	// into the ClusterIP Service's endpoints. A probe verdict that disagrees with
	// readiness refines the not-ready reason and never overrides it.
	Ready bool
	// Probe is the serving-surface verdict for this replica, if one was taken.
	Probe ProbeVerdict
}

// Observation is the injected state one status derivation reads: the replicas
// and the model revision the operator has resolved so far.
//
// Pods are supplied in a STABLE order (an informer's lister returns them sorted
// by name); the derivation names the first matching replica in that order, so
// the same cluster state always produces the same message.
type Observation struct {
	// Pods are the serving replicas observed for this MLXModel.
	Pods []PodState
	// ResolvedRevision is the exact model revision the weights were fetched from,
	// once the operator knows it. Empty means "not known yet", never "none": the
	// derivation keeps any previously recorded value rather than erasing it (see
	// DeriveStatus).
	ResolvedRevision string
}

// StatusOptions carries what publishing an endpoint needs beyond the MLXModel
// itself. Options is embedded because the endpoint must name the SAME port the
// rendered Service exposes — resolving the port twice by two rules is how a
// status comes to advertise an address nothing listens on.
type StatusOptions struct {
	Options
	// ClusterDomain is the cluster DNS suffix used to build the endpoint. Empty
	// means dns.DefaultClusterDomain.
	ClusterDomain string
}

// DeriveStatus computes an MLXModel's status from observed pod and probe state.
//
// It is PURE: no IO, no cluster reads, no writes, no clock of its own (now is
// supplied), and m is not mutated. The status it returns is the WHOLE status —
// the caller applies it through the status subresource.
//
// The previous status matters and is read from m.Status:
//
//   - LastTransitionTime is preserved while a condition's Status is unchanged
//     (the standard meta.SetStatusCondition discipline), so a model that sits in
//     Downloading for forty minutes keeps the timestamp of when it stopped being
//     ready, which is the number an operator actually wants.
//   - ResolvedRevision is STICKY: once recorded it survives an observation that
//     no longer knows it (every replica restarting at once, say). Erasing it
//     would destroy the only record of what is really running, which for a
//     mutable default branch is the only thing that makes drift observable.
//
// Endpoint is published ONLY in the Ready phase and cleared otherwise. An
// endpoint on a model that is not serving is an address a client will connect
// to and hang on.
func DeriveStatus(m *mlxv1alpha1.MLXModel, obs Observation, opts StatusOptions, now time.Time) mlxv1alpha1.MLXModelStatus {
	if m == nil {
		return mlxv1alpha1.MLXModelStatus{}
	}
	status := *m.Status.DeepCopy()
	status.ObservedGeneration = m.Generation

	ready, reason, message := deriveReady(m, obs)
	condStatus := metav1.ConditionFalse
	if ready {
		condStatus = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               mlxv1alpha1.MLXModelConditionReady,
		Status:             condStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: m.Generation,
		LastTransitionTime: metav1.NewTime(now),
	})

	status.Phase = PhaseFromConditions(status.Conditions)

	if obs.ResolvedRevision != "" {
		status.ResolvedRevision = obs.ResolvedRevision
	}

	status.Endpoint = ""
	if status.Phase == mlxv1alpha1.MLXModelPhaseReady {
		status.Endpoint = endpoint(m, opts)
	}
	return status
}

// PhaseFromConditions derives the single-word printer column from the Ready
// condition. Phase is a projection of the conditions and never a second source
// of truth: derive it, do not compute it beside them, or the two disagree and
// the one a human reads is the one that is wrong.
//
// An absent or unrecognized Ready condition yields the empty phase — a blank
// column is honest about a status that has not been derived, where any concrete
// phase would be a guess.
func PhaseFromConditions(conds []metav1.Condition) mlxv1alpha1.MLXModelPhase {
	c := meta.FindStatusCondition(conds, mlxv1alpha1.MLXModelConditionReady)
	if c == nil {
		return ""
	}
	if c.Status == metav1.ConditionTrue {
		return mlxv1alpha1.MLXModelPhaseReady
	}
	switch c.Reason {
	case ReasonPending, ReasonScaledToZero:
		return mlxv1alpha1.MLXModelPhasePending
	case ReasonDownloading:
		return mlxv1alpha1.MLXModelPhaseDownloading
	case ReasonLoading:
		return mlxv1alpha1.MLXModelPhaseLoading
	case ReasonPodFailed:
		return mlxv1alpha1.MLXModelPhaseFailed
	default:
		return ""
	}
}

// replicaStage ranks how far one replica has progressed toward serving. The
// values are ORDERED, and the order is the contract: the derivation reports the
// LEAST advanced stage among the replicas that are not yet ready, because that
// replica is the one deciding when the model serves.
//
// Reporting the furthest-along replica instead would say "Loading" about a model
// whose second replica has not started downloading — a phase that overstates
// progress, which is the same class of error as publishing an endpoint before
// readiness. A replica the StatefulSet has not created yet counts as the most
// laggardly of all: it is stagePending, so a model missing a replica never
// reports the progress of the replicas it does have.
type replicaStage int

const (
	stagePending replicaStage = iota
	stageDownloading
	stageLoading
	stageReady
)

// stageOf ranks one observed replica. Readiness decides stageReady on its own:
// it is what puts the replica's address into the ClusterIP Service's endpoints,
// so a probe verdict may refine a not-ready replica's stage and never promote it.
func stageOf(p PodState) replicaStage {
	switch {
	case p.Ready:
		return stageReady
	case p.Phase == corev1.PodRunning && (p.Probe == ProbeLoading || p.Probe == ProbeServing):
		return stageLoading
	case p.Phase == corev1.PodRunning:
		return stageDownloading
	default:
		return stagePending
	}
}

// deriveReady is the whole state machine, in precedence order. The order is the
// contract, not an implementation detail:
//
//  1. scale-to-zero first — with no replicas requested, "0 of 0 ready" would
//     otherwise satisfy the serving test and publish an endpoint for a model
//     that is deliberately not running;
//  2. serving next — a model answering requests is Ready even if a stray replica
//     is Failed. A phase that says "stop, this will not recover" about a model
//     currently serving traffic is worse than one that omits a fault the owned
//     StatefulSet's own conditions still carry;
//  3. failure before progress — a terminal pod outranks a sibling that is merely
//     starting, because waiting on the sibling hides the fault;
//  4. otherwise the LAGGARD's stage, per replicaStage above.
func deriveReady(m *mlxv1alpha1.MLXModel, obs Observation) (ready bool, reason, message string) {
	desired := int32(1)
	if m.Spec.Replicas != nil {
		desired = *m.Spec.Replicas
	}

	var readyCount int32
	var failed, laggardName string
	laggard := stageReady
	for _, p := range obs.Pods {
		if p.Phase == corev1.PodFailed {
			if failed == "" {
				failed = p.Name
			}
			continue
		}
		s := stageOf(p)
		if s == stageReady {
			readyCount++
			continue
		}
		if s < laggard {
			laggard, laggardName = s, p.Name
		}
	}
	// A replica the StatefulSet has not created yet is observed by its absence.
	missing := desired - int32(len(obs.Pods))
	if missing > 0 && stagePending < laggard {
		laggard, laggardName = stagePending, ""
	}

	switch {
	case desired <= 0:
		return false, ReasonScaledToZero, "spec.replicas is 0: no replica is serving"
	case readyCount >= desired:
		return true, ReasonServing, fmt.Sprintf("%d of %d replicas ready", readyCount, desired)
	case failed != "":
		return false, ReasonPodFailed, fmt.Sprintf("replica %s failed (%d of %d replicas ready)", failed, readyCount, desired)
	case laggard == stageLoading:
		return false, ReasonLoading, fmt.Sprintf("replica %s is loading the model (%d of %d replicas ready)", laggardName, readyCount, desired)
	case laggard == stageDownloading:
		return false, ReasonDownloading, fmt.Sprintf("replica %s has not answered its serving surface yet (%d of %d replicas ready)", laggardName, readyCount, desired)
	case laggardName != "":
		return false, ReasonPending, fmt.Sprintf("replica %s is not running (%d of %d replicas ready)", laggardName, readyCount, desired)
	default:
		return false, ReasonPending, fmt.Sprintf("%d of %d replicas ready, %d not created yet", readyCount, desired, missing)
	}
}

// endpoint builds the in-cluster address clients use: the stable ClusterIP
// Service's fully qualified DNS name and the serving port, both taken from the
// render's own naming so the status cannot name an object the render did not
// create. An unresolvable port yields no endpoint rather than a hostname with a
// port of zero appended.
func endpoint(m *mlxv1alpha1.MLXModel, opts StatusOptions) string {
	port := resolvePort(m, opts.Options)
	if port == 0 {
		return ""
	}
	domain := opts.ClusterDomain
	if domain == "" {
		domain = dns.DefaultClusterDomain
	}
	return fmt.Sprintf("%s.%s.svc.%s:%d", ServiceName(m.Name), m.Namespace, domain, port)
}
