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
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
)

// ErrVolumeSourceUnsupported is the sentinel for a pod refused because a
// container mounts a volume whose source this node does not model (hostPath,
// nfs, csi, a generic ephemeral volume, every other in-tree kind, and any
// source upstream adds later). errors.Is-able, so a caller can tell "this node
// will never run that pod" from a transient create failure.
var ErrVolumeSourceUnsupported = errors.New("volume source is not supported on this node")

// ErrImageVolumeRegistry is the sentinel for a pod refused because an image
// volume's reference does not name the cluster registry, or because this node
// maps no cluster registry at all.
var ErrImageVolumeRegistry = errors.New("image volume reference does not name the cluster registry")

// volumeKindNone is the kind token for a volume with no source set. API
// validation refuses such a volume; the node refuses it again if mounted.
const volumeKindNone = "none"

// volumeRefusal is a translation refusal of one volume. reason is the stable
// Event reason CreatePod records for it (recordVolumeRefusal); volume is the
// pod's own volume name and kind a fixed token, never other text from the pod.
type volumeRefusal struct {
	reason string
	volume string
	kind   string
	err    error
}

func (e *volumeRefusal) Error() string {
	return fmt.Sprintf("volume %q (%s): %v", e.volume, e.kind, e.err)
}

func (e *volumeRefusal) Unwrap() error { return e.err }

// unmodeledVolume refuses a mounted volume the translation does not model.
//
// WHY A MOUNTED VOLUME IS REFUSED: before this, toVolume returned nil and the
// volume vanished from the box, so the runtime failed the container later with
// "volume_mount references undefined volume", naming the mount and never the
// source. Such a pod never ran, so refusing it at the provider breaks nothing
// and says why.
//
// WHY AN UNMOUNTED ONE IS NOT: a volume no container mounts reaches nothing,
// and a pod that declares one (a chart that templates the volume
// unconditionally and the mount conditionally) runs today. Refusing it would
// stop a working pod; a translate failure in the startup re-attach would even
// tear a running one down.
func unmodeledVolume(v *corev1.Volume) error {
	kind := volumeSourceKind(&v.VolumeSource)
	return &volumeRefusal{
		reason: reasonFailedVolumeSource,
		volume: v.Name,
		kind:   kind,
		err:    fmt.Errorf("a container mounts it, and its source of kind %s is not one this node models: %w", kind, ErrVolumeSourceUnsupported),
	}
}

// volumeSourceKind is the JSON field name of the first source set on src
// ("hostPath", "nfs", "csi", ...), or volumeKindNone. The token comes from the
// struct's own tags, never from the pod, so it is safe in a namespace-readable
// Event; and walking every pointer field names a source upstream adds later
// without a change here.
func volumeSourceKind(src *corev1.VolumeSource) string {
	v := reflect.ValueOf(src).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if f := v.Field(i); f.Kind() == reflect.Pointer && !f.IsNil() {
			kind, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			return kind
		}
	}
	return volumeKindNone
}

// mountedVolumes is the set of volume names an init or regular container
// mounts. Ephemeral containers are left out on purpose: they arrive by update
// to a pod that already runs, and a refusal there would fail the update of a
// running pod rather than the debug container alone, as the runtime does today.
func mountedVolumes(pod *corev1.Pod) map[string]bool {
	out := map[string]bool{}
	for _, cs := range [][]corev1.Container{pod.Spec.InitContainers, pod.Spec.Containers} {
		for i := range cs {
			for j := range cs[i].VolumeMounts {
				out[cs[i].VolumeMounts[j].Name] = true
			}
		}
	}
	return out
}

// checkImageVolumeRegistry refuses an image volume whose reference does not
// name clusterRegistry, the cluster's one registry authority, exactly.
//
// WHY THE PROVIDER REFUSES: the root runtime daemon fetches the artifact, so a
// reference the pod author chose would otherwise make it contact any host. The
// runtime refuses again; this is the first of the two checks.
//
// EXACT MATCH, AND NOTHING ELSE: a bare name (which would default to a public
// registry), a loopback spelling of a registry, another port and a lookalike
// host are all refused. clusterRegistry "" (a node that maps no cluster
// registry) refuses every image volume. The reference is parsed with no default
// registry, so a missing host stays missing rather than becoming docker.io.
func checkImageVolumeRegistry(v *corev1.Volume, clusterRegistry string) error {
	refuse := func(why error) error {
		return &volumeRefusal{
			reason: reasonArtifactPullRefused,
			volume: v.Name,
			kind:   "image",
			err:    fmt.Errorf("%w: %w", ErrImageVolumeRegistry, why),
		}
	}
	if clusterRegistry == "" {
		return refuse(errors.New("this node maps no cluster registry"))
	}
	ref, err := name.ParseReference(v.Image.Reference, name.WithDefaultRegistry(""))
	if err != nil {
		return refuse(fmt.Errorf("the reference does not parse: %w", err))
	}
	if reg := ref.Context().RegistryStr(); reg != clusterRegistry {
		return refuse(fmt.Errorf("the reference names registry %q, not %q", reg, clusterRegistry))
	}
	return nil
}

// recordVolumeRefusal records the Warning Event for a create refused because
// of one volume (toVolume). It is a no-op for any other error.
func (r *runtimedRuntime) recordVolumeRefusal(pod *corev1.Pod, err error) {
	var vr *volumeRefusal
	if !errors.As(err, &vr) {
		return
	}
	msg := msgFailedVolumeSource(vr.volume, vr.kind)
	if vr.reason == reasonArtifactPullRefused {
		msg = msgArtifactPullRefused(vr.volume, r.clusterRegistry)
	}
	r.recorder.Event(pod, corev1.EventTypeWarning, vr.reason, msg)
}
