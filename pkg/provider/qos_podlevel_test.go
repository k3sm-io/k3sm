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
)

func TestComputePodQOSPodLevelResources(t *testing.T) {
	rl := func(cpu, mem string) corev1.ResourceList {
		l := corev1.ResourceList{}
		if cpu != "" {
			l[corev1.ResourceCPU] = resource.MustParse(cpu)
		}
		if mem != "" {
			l[corev1.ResourceMemory] = resource.MustParse(mem)
		}
		return l
	}
	guaranteedC := corev1.Container{Name: "c", Resources: corev1.ResourceRequirements{Requests: rl("1", "1Gi"), Limits: rl("1", "1Gi")}}
	burstableC := corev1.Container{Name: "c", Resources: corev1.ResourceRequirements{Requests: rl("1", "")}}
	bareC := corev1.Container{Name: "c"}

	tests := []struct {
		name       string
		pod        *corev1.ResourceRequirements
		containers []corev1.Container
		want       corev1.PodQOSClass
	}{
		{"pod-level guaranteed over bare containers", &corev1.ResourceRequirements{Requests: rl("1", "1Gi"), Limits: rl("1", "1Gi")}, []corev1.Container{bareC}, corev1.PodQOSGuaranteed},
		{"pod-level guaranteed overrides burstable containers", &corev1.ResourceRequirements{Requests: rl("1", "1Gi"), Limits: rl("1", "1Gi")}, []corev1.Container{burstableC}, corev1.PodQOSGuaranteed},
		{"pod-level requests only is burstable", &corev1.ResourceRequirements{Requests: rl("1", "1Gi")}, []corev1.Container{guaranteedC}, corev1.PodQOSBurstable},
		{"pod-level cpu-only limit is burstable", &corev1.ResourceRequirements{Limits: rl("1", "")}, []corev1.Container{guaranteedC}, corev1.PodQOSBurstable},
		{"pod-level mismatched request/limit is burstable", &corev1.ResourceRequirements{Requests: rl("1", "1Gi"), Limits: rl("2", "1Gi")}, []corev1.Container{guaranteedC}, corev1.PodQOSBurstable},
		{"empty pod resources fall through to guaranteed containers", &corev1.ResourceRequirements{}, []corev1.Container{guaranteedC}, corev1.PodQOSGuaranteed},
		{"empty requests map falls through", &corev1.ResourceRequirements{Requests: corev1.ResourceList{}}, []corev1.Container{guaranteedC}, corev1.PodQOSGuaranteed},
		{"empty limits map falls through", &corev1.ResourceRequirements{Limits: corev1.ResourceList{}}, []corev1.Container{guaranteedC}, corev1.PodQOSGuaranteed},
		{"empty pod resources over bare containers is besteffort", &corev1.ResourceRequirements{}, []corev1.Container{bareC}, corev1.PodQOSBestEffort},
		{"empty limits map over burstable containers is burstable", &corev1.ResourceRequirements{Limits: corev1.ResourceList{}}, []corev1.Container{burstableC}, corev1.PodQOSBurstable},
		{"nil pod resources, guaranteed containers", nil, []corev1.Container{guaranteedC}, corev1.PodQOSGuaranteed},
		{"nil pod resources, burstable containers", nil, []corev1.Container{burstableC}, corev1.PodQOSBurstable},
		{"nil pod resources, bare containers", nil, []corev1.Container{bareC}, corev1.PodQOSBestEffort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{Spec: corev1.PodSpec{Resources: tt.pod, Containers: tt.containers}}
			if got := computePodQOS(pod); got != tt.want {
				t.Errorf("computePodQOS = %q, want %q", got, tt.want)
			}
		})
	}
}
