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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// runAsNonRootTable is testdata/runasnonroot_composition.json.
type runAsNonRootTable struct {
	Rows []runAsNonRootRow `json:"rows"`
}

type runAsNonRootRow struct {
	Name       string                  `json:"name"`
	Pod        *bool                   `json:"pod"`
	Containers []runAsNonRootContainer `json:"containers"`
	PodField   *bool                   `json:"podField"`
}

type runAsNonRootContainer struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Own       *bool  `json:"own"`
	Stamp     *bool  `json:"stamp"`
	Effective bool   `json:"effective"`
	// FailClosed marks the one deliberate divergence from the kubelet: an
	// ephemeral container's opt-out under a pod-level true is still enforced.
	FailClosed bool `json:"failClosed"`
}

// TestRunAsNonRootEffectivePerContainer pins the producer rule the apis
// runtime.proto states on PodSecurityContext.run_as_non_root, end to end through
// toPodBox, for init (sidecars included), regular and ephemeral containers.
//
// Each row is checked twice. First the producer: the exact per-container stamp
// and pod field the box must carry, including "no message at all" where the pod
// sets nothing. Then the CONSUMER: the composition the proto states and runtimed
// applies, c.GetSecurityContext().GetRunAsNonRoot() ||
// box.GetPodSecurityContext().GetRunAsNonRoot() (runtimed pkg/runtime/pod.go:2711,
// effectiveRunAsNonRoot), must equal the kubelet's per-container verdict. The
// second check is what proves the stamps close the proto3 presence gap: a
// container's explicit false under a pod-level true survives the OR only because
// the pod field is lowered and the siblings carry their own true.
//
// runtimed has no copy of this table to read; its own test pins the OR side.
//
// Non-vacuity: before the resolver, toPodSecurityContext dropped a
// runAsNonRoot-only pod context entirely and nothing stamped the containers, so
// every "pod true, container unset" row composed to false.
func TestRunAsNonRootEffectivePerContainer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "runasnonroot_composition.json"))
	if err != nil {
		t.Fatalf("read table: %v", err)
	}
	var table runAsNonRootTable
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatalf("parse table: %v", err)
	}
	if len(table.Rows) == 0 {
		t.Fatal("the composition table has no rows")
	}

	for _, row := range table.Rows {
		t.Run(row.Name, func(t *testing.T) {
			pod := runAsNonRootPod(t, row)
			box, err := toPodBox(pod, "10.0.0.5", "10.0.0.5", "/var/lib/k3sm/pods/uid-rnr", "", netv1.DNSConfig{}, nil)
			if err != nil {
				t.Fatalf("toPodBox: %v", err)
			}

			psc := box.GetPodSecurityContext()
			switch {
			case row.PodField == nil && psc != nil:
				t.Errorf("PodSecurityContext = %v, want none (the pod sets nothing)", psc)
			case row.PodField != nil && psc == nil:
				t.Errorf("PodSecurityContext = nil, want run_as_non_root=%v", *row.PodField)
			case row.PodField != nil && psc.GetRunAsNonRoot() != *row.PodField:
				t.Errorf("PodSecurityContext.run_as_non_root = %v, want %v", psc.GetRunAsNonRoot(), *row.PodField)
			}

			for _, want := range row.Containers {
				rc := boxContainer(box, want.Kind, want.Name)
				if rc == nil {
					t.Fatalf("container %s (%s) is not on the box", want.Name, want.Kind)
				}
				sc := rc.GetSecurityContext()
				switch {
				case want.Stamp == nil && sc != nil:
					t.Errorf("%s: SecurityContext = %v, want none", want.Name, sc)
				case want.Stamp != nil && sc == nil:
					t.Errorf("%s: SecurityContext = nil, want run_as_non_root=%v stamped", want.Name, *want.Stamp)
				case want.Stamp != nil && sc.GetRunAsNonRoot() != *want.Stamp:
					t.Errorf("%s: stamped run_as_non_root = %v, want %v", want.Name, sc.GetRunAsNonRoot(), *want.Stamp)
				}
				// The consumer composition (runtimed pkg/runtime/pod.go:2711).
				composed := rc.GetSecurityContext().GetRunAsNonRoot() || box.GetPodSecurityContext().GetRunAsNonRoot()
				switch {
				case want.FailClosed && (want.Kind != "ephemeral" || want.Effective):
					t.Fatalf("%s: failClosed marks only an ephemeral opt-out (effective false)", want.Name)
				case want.FailClosed && !composed:
					t.Errorf("%s: consumer composition = false, want true (an ephemeral opt-out is enforced, fail closed)", want.Name)
				case !want.FailClosed && composed != want.Effective:
					t.Errorf("%s: consumer composition = %v, want the kubelet's effective %v", want.Name, composed, want.Effective)
				}
			}
		})
	}
}

// TestRunAsNonRootStampsAContainerWithNoSpec pins the fail-closed arm: a box
// container the pod spec does not name is stamped with the pod value rather
// than left unresolved.
func TestRunAsNonRootStampsAContainerWithNoSpec(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)}}}
	box := &runtimev1.PodBox{EphemeralContainers: []*runtimev1.Container{{Name: "ghost"}}}
	resolveRunAsNonRoot(pod, box)
	if !box.GetEphemeralContainers()[0].GetSecurityContext().GetRunAsNonRoot() {
		t.Error("ghost run_as_non_root = false, want the pod value (true) stamped")
	}
}

// runAsNonRootPod builds the pod a table row describes. Every container runs a
// host binary so the translation needs no image facts.
func runAsNonRootPod(t *testing.T, row runAsNonRootRow) *corev1.Pod {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rnr", UID: types.UID("uid-rnr")},
	}
	if row.Pod != nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: row.Pod}
	}
	always := corev1.ContainerRestartPolicyAlways
	for _, c := range row.Containers {
		var sc *corev1.SecurityContext
		if c.Own != nil {
			sc = &corev1.SecurityContext{RunAsNonRoot: c.Own}
		}
		spec := corev1.Container{Name: c.Name, Image: "native", Command: []string{"/bin/sleep", "60"}, SecurityContext: sc}
		switch c.Kind {
		case "init":
			pod.Spec.InitContainers = append(pod.Spec.InitContainers, spec)
		case "sidecar":
			spec.RestartPolicy = &always
			pod.Spec.InitContainers = append(pod.Spec.InitContainers, spec)
		case "regular":
			pod.Spec.Containers = append(pod.Spec.Containers, spec)
		case "ephemeral":
			pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers,
				corev1.EphemeralContainer{EphemeralContainerCommon: corev1.EphemeralContainerCommon(spec)})
		default:
			t.Fatalf("row %q: unknown container kind %q", row.Name, c.Kind)
		}
	}
	return pod
}

// boxContainer finds a translated container by the list its kind lands in.
func boxContainer(box *runtimev1.PodBox, kind, name string) *runtimev1.Container {
	var list []*runtimev1.Container
	switch kind {
	case "init", "sidecar":
		list = box.GetInitContainers()
	case "regular":
		list = box.GetContainers()
	case "ephemeral":
		list = box.GetEphemeralContainers()
	}
	for _, c := range list {
		if c.GetName() == name {
			return c
		}
	}
	return nil
}
