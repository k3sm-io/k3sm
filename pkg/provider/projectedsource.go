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
	"errors"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
)

// ErrProjectedSourceUnsupported is the sentinel for a pod refused because one of
// its projected volumes names a source this node cannot materialize. It is
// errors.Is-able so a caller can distinguish "this node will never run that pod"
// from a transient create failure.
var ErrProjectedSourceUnsupported = errors.New("projected volume source is not supported on this node")

// Fixed source-kind tokens a refusal names. They are constants, never anything
// read from the pod: a ClusterTrustBundle name, a signer name or a label selector
// is user text, and the Event is namespace-readable.
const (
	projectedKindClusterTrustBundle = "clusterTrustBundle"
	projectedKindPodCertificate     = "podCertificate"
	projectedKindUnmodeled          = "unmodeled"
)

// preflightProjectedSources refuses, BEFORE the CreatePod RPC, a pod whose
// projected volume carries a source the translation does not model.
//
// WHY A REFUSAL AND NOT A BEST EFFORT: toVolumeProjection maps an unmodeled
// source to nil and toProjectedVolumeSource drops it, so before this check the
// pod started with the file missing from its volume and nothing anywhere said
// why. A workload that reads its trust bundle or its certificate from that path
// then fails at use, far from the cause.
//
// THE CHECK IS A CLOSED SET, deliberately inverted, and shared with
// toVolumeProjection: a source is supported iff exactly one of configMap, secret,
// downwardAPI or serviceAccountToken is set. clusterTrustBundle, podCertificate,
// a projection with no field set, and any source upstream adds later are all
// refused, so a new source cannot inherit the silent drop.
//
// `optional: true` IS NOT AN EXEMPTION. Optional describes cluster state (the
// named object may be absent), not node capability: a node that can never
// project the source would serve an empty volume even when the object exists.
//
// EVERY BACKEND, unlike preflightEmptyDirMedium: the vm path stages the same
// translated volume into its guest, so it drops the same sources.
func (r *runtimedRuntime) preflightProjectedSources(pod *corev1.Pod) error {
	for i := range pod.Spec.Volumes {
		v := &pod.Spec.Volumes[i]
		if v.Projected == nil {
			continue
		}
		for j := range v.Projected.Sources {
			kind, ok := projectedSourceKind(&v.Projected.Sources[j])
			if ok {
				continue
			}
			r.log.Error("CreatePod: projected volume source is not supported on this node",
				"namespace", pod.Namespace, "name", pod.Name,
				"volume", v.Name, "source", kind)
			r.recorder.Event(pod, corev1.EventTypeWarning, reasonFailedProjectedSource,
				msgFailedProjectedSource(v.Name, kind))
			return fmt.Errorf("create pod %s/%s: volume %q projects a source of kind %s: %w",
				pod.Namespace, pod.Name, v.Name, kind, ErrProjectedSourceUnsupported)
		}
	}
	return nil
}

// projectedSourceKind reports whether p is a source toVolumeProjection models
// and, when it is not, the fixed kind token a refusal names.
//
// The set fields are counted by reflection over every POINTER-typed field of the
// struct, not over the four modeled ones, so a pointer-typed source field
// upstream adds later is seen even beside a modeled one and refused as unmodeled.
// A non-pointer field would not be counted. Server-side API validation already
// requires exactly one source per projection; this count is the node's own check.
func projectedSourceKind(p *corev1.VolumeProjection) (string, bool) {
	switch {
	case p.ClusterTrustBundle != nil:
		return projectedKindClusterTrustBundle, false
	case p.PodCertificate != nil:
		return projectedKindPodCertificate, false
	}
	modeled := p.ConfigMap != nil || p.Secret != nil || p.DownwardAPI != nil || p.ServiceAccountToken != nil
	if !modeled || setProjectionFields(p) != 1 {
		return projectedKindUnmodeled, false
	}
	return "", true
}

// setProjectionFields counts the non-nil pointer-typed fields of p.
func setProjectionFields(p *corev1.VolumeProjection) int {
	v := reflect.ValueOf(p).Elem()
	n := 0
	for i := 0; i < v.NumField(); i++ {
		if f := v.Field(i); f.Kind() == reflect.Pointer && !f.IsNil() {
			n++
		}
	}
	return n
}
