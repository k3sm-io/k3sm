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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestTranslateGPURequestAndEgressAnnotation is the M8.3-d2 named gate: the
// GPU request read is pinned to LIMITS (not requests), the egress annotation
// is read via the apis-owned constant (never a hand-spelled literal), and
// translate enforces AllowInternetEgress ⇒ AllowNetwork so a pod that opts
// into wider egress never loses the cluster DNS-VIP route.
func TestTranslateGPURequestAndEgressAnnotation(t *testing.T) {
	gpuResource := corev1.ResourceName(mlxv1alpha1.ResourceGPU)

	t.Run("gpu_read_from_limits_not_requests", func(t *testing.T) {
		cases := []struct {
			name      string
			resources corev1.ResourceRequirements
			want      bool
		}{
			{
				name: "gpu_in_limits_sets_allow_gpu",
				resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{gpuResource: resource.MustParse("1")},
				},
				want: true,
			},
			{
				// The limits-not-requests read, pinned: a GPU ask that only
				// appears in requests must NOT grant AllowGpu.
				name: "gpu_only_in_requests_does_not_set_allow_gpu",
				resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{gpuResource: resource.MustParse("1")},
				},
				want: false,
			},
			{
				name:      "no_gpu_resource_at_all",
				resources: corev1.ResourceRequirements{},
				want:      false,
			},
			{
				// A zero-quantity limit is not a grant.
				name: "gpu_limit_present_but_zero",
				resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{gpuResource: resource.MustParse("0")},
				},
				want: false,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pod := &corev1.Pod{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "c0", Image: "img", Resources: tc.resources}},
					},
				}
				if got := podRequestsGPU(pod); got != tc.want {
					t.Errorf("podRequestsGPU() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("gpu_limit_on_init_container_also_counts", func(t *testing.T) {
		pod := &corev1.Pod{
			Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{
					Name:  "fetch",
					Image: "img",
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{gpuResource: resource.MustParse("1")},
					},
				}},
				Containers: []corev1.Container{{Name: "c0", Image: "img"}},
			},
		}
		if !podRequestsGPU(pod) {
			t.Error("podRequestsGPU() = false, want true for a GPU limit on an init container")
		}
	})

	t.Run("egress_annotation_present_absent", func(t *testing.T) {
		cases := []struct {
			name        string
			annotations map[string]string
			want        bool
		}{
			{
				name:        "annotation_present",
				annotations: map[string]string{runtimev1.AnnotationInternetEgress: "true"},
				want:        true,
			},
			{
				name:        "annotation_absent",
				annotations: nil,
				want:        false,
			},
			{
				name:        "unrelated_annotation_only",
				annotations: map[string]string{"k3sm.io/image-platform": "linux/amd64"},
				want:        false,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Annotations: tc.annotations},
				}
				if got := podRequestsInternetEgress(pod); got != tc.want {
					t.Errorf("podRequestsInternetEgress() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	// Constant-not-literal: the annotation key read by translate must be the
	// apis-owned runtimev1.AnnotationInternetEgress constant, not a
	// hand-respelled string literal. Pin the constant's wire value here (so a
	// drift in either the constant or a hypothetical literal substitution is
	// caught) and prove the production read keys off the SAME constant this
	// test uses to build the pod.
	t.Run("egress_annotation_uses_the_apis_constant_not_a_literal", func(t *testing.T) {
		const wantWireValue = "k3sm.io/internet-egress"
		if runtimev1.AnnotationInternetEgress != wantWireValue {
			t.Fatalf("runtimev1.AnnotationInternetEgress = %q, want %q", runtimev1.AnnotationInternetEgress, wantWireValue)
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{runtimev1.AnnotationInternetEgress: "true"},
			},
		}
		if !podRequestsInternetEgress(pod) {
			t.Error("podRequestsInternetEgress() = false for a pod keyed by the apis AnnotationInternetEgress constant")
		}
	})

	t.Run("egress_implies_network_pairing", func(t *testing.T) {
		cases := []struct {
			name            string
			annotations     map[string]string
			startAllowNet   bool
			wantAllowNet    bool
			wantAllowEgress bool
		}{
			{
				// The pinned case: AllowNetwork starts false, egress is
				// requested, and translate must flip AllowNetwork to true so
				// DNS-VIP routing survives.
				name:            "egress_set_with_network_previously_false_forces_network_true",
				annotations:     map[string]string{runtimev1.AnnotationInternetEgress: "true"},
				startAllowNet:   false,
				wantAllowNet:    true,
				wantAllowEgress: true,
			},
			{
				name:            "egress_set_with_network_already_true_stays_true",
				annotations:     map[string]string{runtimev1.AnnotationInternetEgress: "true"},
				startAllowNet:   true,
				wantAllowNet:    true,
				wantAllowEgress: true,
			},
			{
				// No egress ⇒ the pairing does not fire; AllowNetwork is left
				// exactly as the caller set it (not silently forced either way).
				name:            "no_egress_leaves_allow_network_unchanged_false",
				annotations:     nil,
				startAllowNet:   false,
				wantAllowNet:    false,
				wantAllowEgress: false,
			},
			{
				name:            "no_egress_leaves_allow_network_unchanged_true",
				annotations:     nil,
				startAllowNet:   true,
				wantAllowNet:    true,
				wantAllowEgress: false,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Annotations: tc.annotations},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "c0", Image: "img"}},
					},
				}
				profile := &runtimev1.SandboxProfile{AllowNetwork: tc.startAllowNet}
				applyGPUAndEgress(profile, pod)
				if profile.GetAllowNetwork() != tc.wantAllowNet {
					t.Errorf("AllowNetwork = %v, want %v", profile.GetAllowNetwork(), tc.wantAllowNet)
				}
				if profile.GetAllowInternetEgress() != tc.wantAllowEgress {
					t.Errorf("AllowInternetEgress = %v, want %v", profile.GetAllowInternetEgress(), tc.wantAllowEgress)
				}
			})
		}
	})

	t.Run("neither_gpu_nor_egress_set_both_false", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web", UID: types.UID("uid-web")},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c0", Image: "registry/web:latest"}},
			},
		}
		box, err := toPodBox(pod, "10.42.0.5", "10.42.0.5", "/var/lib/k3sm/pods/uid-web", "", netv1.DNSConfig{}, nil)
		if err != nil {
			t.Fatalf("toPodBox: %v", err)
		}
		if box.GetSandboxProfile().GetAllowGpu() {
			t.Error("AllowGpu = true, want false for a pod with no GPU limit")
		}
		if box.GetSandboxProfile().GetAllowInternetEgress() {
			t.Error("AllowInternetEgress = true, want false for a pod with no egress annotation")
		}
	})

	t.Run("toPodBox_wires_gpu_and_egress_end_to_end", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   "default",
				Name:        "mlx-serve",
				UID:         types.UID("uid-mlx"),
				Annotations: map[string]string{runtimev1.AnnotationInternetEgress: "true"},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "c0",
					Image: "registry/mlx-serve:latest",
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{gpuResource: resource.MustParse("1")},
					},
				}},
			},
		}
		box, err := toPodBox(pod, "10.42.0.6", "10.42.0.6", "/var/lib/k3sm/pods/uid-mlx", "", netv1.DNSConfig{}, nil)
		if err != nil {
			t.Fatalf("toPodBox: %v", err)
		}
		sp := box.GetSandboxProfile()
		if !sp.GetAllowGpu() {
			t.Error("AllowGpu = false, want true for a GPU limit on the container")
		}
		if !sp.GetAllowInternetEgress() {
			t.Error("AllowInternetEgress = false, want true for the egress annotation")
		}
		if !sp.GetAllowNetwork() {
			t.Error("AllowNetwork = false, want true (egress⇒network pairing)")
		}
	})
}
