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
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	"k3sm.io/k3sm/pkg/runtimeclass"
)

// projectedPod builds a one-container pod with one projected volume per source
// list, named projectedVolumeNames[i] in declaration order.
func projectedPod(name string, volumes ...[]corev1.VolumeProjection) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "c0", Image: "registry/web:1", Command: []string{"/web"}},
			},
		},
	}
	for i, srcs := range volumes {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: projectedVolumeNames[i],
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{Sources: srcs},
			},
		})
	}
	return pod
}

var projectedVolumeNames = []string{"proj-a", "proj-b"}

// TestUnsupportedProjectionSourceFailsClosed is the gate for the projected-source
// preflight: a pod whose projected volume names a source the translation does not
// model (clusterTrustBundle, podCertificate, a projection with no source set, or
// any future source) is refused at CreatePod, before the runtimed RPC, with a
// Warning Event naming the volume and a fixed kind token.
//
// WHY A REFUSAL IS THE ASSERTED BEHAVIOR: toVolumeProjection maps an unmodeled
// source to nil and the volume is materialized without it, so before this gate
// the pod started with the file silently missing.
//
// BOTH LEGS ARE LOAD-BEARING: each row asserts the CreatePod RPC count in both
// directions, so the check cannot decay into a refuse-everything gate. Every row
// runs on the native and the vm backend, because both stage the same translated
// volume and both drop the same sources.
func TestUnsupportedProjectionSourceFailsClosed(t *testing.T) {
	t.Parallel()

	const (
		bundleName = "secret-bundle-name-xyz"
		signerName = "example.com/secret-signer-xyz"
	)
	optional := true
	strp := func(s string) *string { return &s }
	cm := corev1.VolumeProjection{ConfigMap: &corev1.ConfigMapProjection{
		LocalObjectReference: corev1.LocalObjectReference{Name: "cfg"},
	}}
	sat := corev1.VolumeProjection{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}}
	dapi := corev1.VolumeProjection{DownwardAPI: &corev1.DownwardAPIProjection{
		Items: []corev1.DownwardAPIVolumeFile{{Path: "name", FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
	}}
	ctbByName := corev1.VolumeProjection{ClusterTrustBundle: &corev1.ClusterTrustBundleProjection{
		Name: strp(bundleName), Path: "ca.pem",
	}}
	ctbBySigner := corev1.VolumeProjection{ClusterTrustBundle: &corev1.ClusterTrustBundleProjection{
		SignerName:    strp(signerName),
		LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"trust": "secret-label-xyz"}},
		Path:          "ca.pem",
	}}
	ctbOptional := corev1.VolumeProjection{ClusterTrustBundle: &corev1.ClusterTrustBundleProjection{
		Name: strp(bundleName), Optional: &optional, Path: "ca.pem",
	}}
	ctbSignerOptional := corev1.VolumeProjection{ClusterTrustBundle: &corev1.ClusterTrustBundleProjection{
		SignerName:    strp(signerName),
		LabelSelector: &metav1.LabelSelector{},
		Optional:      &optional,
		Path:          "ca.pem",
	}}
	podCert := corev1.VolumeProjection{PodCertificate: &corev1.PodCertificateProjection{
		SignerName: signerName, KeyType: "ED25519", CredentialBundlePath: "cred.pem",
	}}

	secretOnly := corev1.VolumeProjection{Secret: &corev1.SecretProjection{
		LocalObjectReference: corev1.LocalObjectReference{Name: "creds"},
	}}
	cmOptional := corev1.VolumeProjection{ConfigMap: &corev1.ConfigMapProjection{
		LocalObjectReference: corev1.LocalObjectReference{Name: "cfg"}, Optional: &optional,
	}}

	tests := []struct {
		name       string
		volumes    [][]corev1.VolumeProjection
		wantVolume string // empty ⇒ admitted
		wantKind   string
	}{
		// ---- accept leg -------------------------------------------------------
		{
			name:    "modeled_sources_admitted",
			volumes: [][]corev1.VolumeProjection{{cm, sat, dapi}},
		},

		{
			name:    "secret_only_admitted",
			volumes: [][]corev1.VolumeProjection{{secretOnly}},
		},
		{
			// optional on a MODELED source is ordinary: the node can serve it.
			name:    "optional_configmap_admitted",
			volumes: [][]corev1.VolumeProjection{{cmOptional}},
		},

		// ---- reject leg -------------------------------------------------------
		{
			name: "cluster_trust_bundle_by_name", volumes: [][]corev1.VolumeProjection{{ctbByName}},
			wantVolume: "proj-a", wantKind: projectedKindClusterTrustBundle,
		},
		{
			name: "cluster_trust_bundle_by_signer", volumes: [][]corev1.VolumeProjection{{ctbBySigner}},
			wantVolume: "proj-a", wantKind: projectedKindClusterTrustBundle,
		},
		{
			// optional describes cluster state, not node capability: no exemption.
			name: "cluster_trust_bundle_by_name_optional", volumes: [][]corev1.VolumeProjection{{ctbOptional}},
			wantVolume: "proj-a", wantKind: projectedKindClusterTrustBundle,
		},
		{
			name: "cluster_trust_bundle_by_signer_optional", volumes: [][]corev1.VolumeProjection{{ctbSignerOptional}},
			wantVolume: "proj-a", wantKind: projectedKindClusterTrustBundle,
		},
		{
			name: "pod_certificate", volumes: [][]corev1.VolumeProjection{{podCert}},
			wantVolume: "proj-a", wantKind: projectedKindPodCertificate,
		},
		{
			name: "zero_field_projection", volumes: [][]corev1.VolumeProjection{{{}}},
			wantVolume: "proj-a", wantKind: projectedKindUnmodeled,
		},
		{
			// The refusal names the OFFENDING volume, not the first projected one.
			name:       "mixed_modeled_and_unmodeled",
			volumes:    [][]corev1.VolumeProjection{{cm, sat}, {dapi, ctbByName, cm}},
			wantVolume: "proj-b", wantKind: projectedKindClusterTrustBundle,
		},
	}

	// Parity: the preflight's modeled set and toVolumeProjection's switch must
	// agree on every fixture, or a source could pass the preflight and still be
	// dropped by translation (or be refused while translation serves it).
	t.Run("parity_with_toVolumeProjection", func(t *testing.T) {
		t.Parallel()
		for _, tc := range tests {
			for i, vol := range tc.volumes {
				for j := range vol {
					kind, ok := projectedSourceKind(&vol[j])
					translated := toVolumeProjection(&vol[j]) != nil
					if ok != translated {
						t.Errorf("%s volume %d source %d: projectedSourceKind ok=%v (kind %q), toVolumeProjection non-nil=%v",
							tc.name, i, j, ok, kind, translated)
					}
				}
			}
		}
	})

	backends := []struct {
		name         string
		runtimeClass string
	}{
		{"native", ""},
		{"vm", runtimeclass.Name},
	}

	for _, tc := range tests {
		for _, be := range backends {
			t.Run(tc.name+"/"+be.name, func(t *testing.T) {
				t.Parallel()
				f := &platformFake{
					fakeRuntimeServer: newFakeRuntimeServer(),
					info:              capabilityInfo(NodeCapabilities{VMBackend: true}),
				}
				rec := record.NewFakeRecorder(8)
				r := newRuntimedWith(f, RuntimedConfig{
					NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
				}, nil, nil)

				pod := projectedPod("proj", tc.volumes...)
				if be.runtimeClass != "" {
					rc := be.runtimeClass
					pod.Spec.RuntimeClassName = &rc
				}

				err := r.CreatePod(context.Background(), pod)
				_, createCalls := f.counts()

				if tc.wantVolume == "" {
					if err != nil {
						t.Fatalf("CreatePod = %v, want the pod admitted (a reject-only gate is a refuse-everything gate)", err)
					}
					if createCalls != 1 {
						t.Errorf("CreatePod RPC calls = %d, want 1: an admitted pod must reach runtimed", createCalls)
					}
					if ev := nextLifecycleEvent(rec.Events, 0); strings.Contains(ev, reasonFailedProjectedSource) {
						t.Errorf("admitted pod recorded %q, want no %s event", ev, reasonFailedProjectedSource)
					}
					return
				}

				if !errors.Is(err, ErrProjectedSourceUnsupported) {
					t.Fatalf("CreatePod error = %v, want one wrapping ErrProjectedSourceUnsupported", err)
				}
				if !strings.Contains(err.Error(), tc.wantVolume) || !strings.Contains(err.Error(), tc.wantKind) {
					t.Errorf("CreatePod error %q does not name volume %q and kind %q", err, tc.wantVolume, tc.wantKind)
				}
				if createCalls != 0 {
					t.Errorf("CreatePod RPC calls = %d, want 0: the refusal must land BEFORE the RPC", createCalls)
				}
				if r.trackByID(string(pod.UID)) != nil {
					t.Error("a refused pod was tracked; it must leave no bookkeeping behind")
				}

				var events []string
				for {
					select {
					case ev := <-rec.Events:
						events = append(events, ev)
						continue
					default:
					}
					break
				}
				var refusals []string
				for _, ev := range events {
					if strings.HasPrefix(ev, corev1.EventTypeWarning+" "+reasonFailedProjectedSource+" ") {
						refusals = append(refusals, ev)
					}
				}
				if len(refusals) != 1 {
					t.Fatalf("events = %q, want exactly one %s %s event", events, corev1.EventTypeWarning, reasonFailedProjectedSource)
				}
				ev := refusals[0]
				if !strings.Contains(ev, `"`+tc.wantVolume+`"`) {
					t.Errorf("Event %q does not name the offending volume %q", ev, tc.wantVolume)
				}
				if !strings.Contains(ev, "of kind "+tc.wantKind+",") {
					t.Errorf("Event %q does not name the kind token %q", ev, tc.wantKind)
				}
				// User strings never reach the namespace-readable Event or the error.
				for _, leak := range []string{bundleName, signerName, "secret-label-xyz"} {
					if strings.Contains(ev, leak) || strings.Contains(err.Error(), leak) {
						t.Errorf("refusal echoes user string %q: event %q, error %q", leak, ev, err)
					}
				}
			})
		}
	}
}
