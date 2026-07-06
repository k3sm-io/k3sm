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

package policy

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestDefaultLimitRangeMemoryOnly pins the M10.0 default-LimitRange shape
// (Res.5): the object lands in the `default` namespace ONLY, is type Container
// with memory defaults present, carries NO cpu key under ANY field (default/
// defaultRequest/max/min/maxLimitRequestRatio — CPU is best-effort on Darwin,
// so a CPU row would over-claim a guarantee k3sm cannot keep), and is
// create-if-absent (a pre-existing, operator-tuned object is NEVER updated).
func TestDefaultLimitRangeMemoryOnly(t *testing.T) {
	ctx := context.Background()

	t.Run("shape: default namespace, container memory defaults, no cpu anywhere", func(t *testing.T) {
		cs := fake.NewClientset()
		if err := EnsureDefaultLimitRange(ctx, cs); err != nil {
			t.Fatalf("EnsureDefaultLimitRange: %v", err)
		}

		lr, err := cs.CoreV1().LimitRanges("default").Get(ctx, defaultLimitRangeName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("LimitRange must land in the default namespace: %v", err)
		}
		// No other namespace gets one (spot-check kube-system — there is no
		// namespace-watching controller by design).
		if list, _ := cs.CoreV1().LimitRanges("kube-system").List(ctx, metav1.ListOptions{}); len(list.Items) != 0 {
			t.Errorf("LimitRange must exist in the default namespace ONLY, found %d in kube-system", len(list.Items))
		}

		if len(lr.Spec.Limits) != 1 || lr.Spec.Limits[0].Type != corev1.LimitTypeContainer {
			t.Fatalf("limits = %+v, want exactly one type: Container item", lr.Spec.Limits)
		}
		item := lr.Spec.Limits[0]
		if got, want := item.Default[corev1.ResourceMemory], resource.MustParse(defaultMemoryLimit); got.Cmp(want) != 0 {
			t.Errorf("default.memory = %s, want %s", got.String(), want.String())
		}
		if got, want := item.DefaultRequest[corev1.ResourceMemory], resource.MustParse(defaultMemoryRequest); got.Cmp(want) != 0 {
			t.Errorf("defaultRequest.memory = %s, want %s", got.String(), want.String())
		}

		// Grep every field of every item for ANY cpu key (or anything non-memory).
		for i, it := range lr.Spec.Limits {
			for field, list := range map[string]corev1.ResourceList{
				"default":              it.Default,
				"defaultRequest":       it.DefaultRequest,
				"max":                  it.Max,
				"min":                  it.Min,
				"maxLimitRequestRatio": it.MaxLimitRequestRatio,
			} {
				for name := range list {
					if name != corev1.ResourceMemory {
						t.Errorf("limits[%d].%s carries %q — the LimitRange must be MEMORY-ONLY (no cpu key anywhere)", i, field, name)
					}
				}
			}
		}
	})

	t.Run("create-if-absent: a pre-existing object is never updated", func(t *testing.T) {
		cs := fake.NewClientset()
		tuned := &corev1.LimitRange{
			ObjectMeta: metav1.ObjectMeta{Name: defaultLimitRangeName, Namespace: "default"},
			Spec: corev1.LimitRangeSpec{
				Limits: []corev1.LimitRangeItem{{
					Type: corev1.LimitTypeContainer,
					Default: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("2Gi"), // operator-tuned marker
					},
				}},
			},
		}
		if _, err := cs.CoreV1().LimitRanges("default").Create(ctx, tuned, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed tuned LimitRange: %v", err)
		}

		if err := EnsureDefaultLimitRange(ctx, cs); err != nil {
			t.Fatalf("EnsureDefaultLimitRange with pre-existing object: %v (AlreadyExists must be success)", err)
		}
		got, err := cs.CoreV1().LimitRanges("default").Get(ctx, defaultLimitRangeName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if mem, want := got.Spec.Limits[0].Default[corev1.ResourceMemory], resource.MustParse("2Gi"); mem.Cmp(want) != 0 {
			t.Errorf("operator-tuned default.memory = %s, want the untouched 2Gi (in-cluster objects are operator-space — never update)", mem.String())
		}
	})
}
