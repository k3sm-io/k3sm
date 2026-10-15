//go:build e2e

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

package e2e

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"k3sm.io/k3sm/pkg/policy"
)

// TestDaemonSetTolerationReachesTheController proves the provider toleration lands
// in the stored DaemonSet TEMPLATE, which is what the DaemonSet controller reads when
// it decides where daemon pods go. Every k3sm node carries the
// k3sm.io/provider:NoSchedule taint, so a template without the toleration leaves
// desiredNumberScheduled at 0 however the pods themselves would be mutated.
//
//   - a DaemonSet with no tolerations is scheduled on every eligible Ready darwin
//     node, and its stored template carries exactly one provider toleration;
//   - a template that already tolerates the taint is stored unchanged, and a
//     no-op UPDATE leaves its generation at 1;
//   - a template with a different-key toleration keeps it and gains the provider one.
func TestDaemonSetTolerationReachesTheController(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	dss := c.Client.AppsV1().DaemonSets(conformanceNS)
	suffix := time.Now().Unix()
	provider := corev1.Toleration{Key: policy.ProviderTaintKey, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}

	create := func(t *testing.T, name string, tolerations []corev1.Toleration) *appsv1.DaemonSet {
		t.Helper()
		got, err := dss.Create(ctx, b566DaemonSet(name, tolerations), metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("create daemonset %s: %v", name, err)
		}
		t.Cleanup(func() {
			bg := metav1.DeletePropagationBackground
			_ = dss.Delete(context.Background(), name, metav1.DeleteOptions{PropagationPolicy: &bg})
		})
		return got
	}

	t.Run("no tolerations: scheduled on every eligible darwin node", func(t *testing.T) {
		want := b566EligibleNodes(t, c)
		if want == 0 {
			t.Fatal("no Ready darwin node without a foreign NoSchedule/NoExecute taint; the leg cannot be judged")
		}
		name := fmt.Sprintf("b566-bare-%d", suffix)
		stored := create(t, name, nil)
		if n := countProvider(stored.Spec.Template.Spec.Tolerations); n != 1 || len(stored.Spec.Template.Spec.Tolerations) != 1 {
			t.Errorf("stored template tolerations = %+v, want exactly one provider toleration", stored.Spec.Template.Spec.Tolerations)
		}
		deadline := time.Now().Add(90 * time.Second)
		var got int32
		for {
			ds, err := dss.Get(ctx, name, metav1.GetOptions{})
			if err == nil {
				got = ds.Status.DesiredNumberScheduled
				if got == int32(want) {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("status.desiredNumberScheduled = %d after 90s, want %d (the controller does not see the toleration in the template); last err %v", got, want, err)
			}
			time.Sleep(2 * time.Second)
		}
		t.Logf("daemonset %s: desiredNumberScheduled = %d", name, got)
	})

	t.Run("already tolerating: stored unchanged, no-op UPDATE keeps generation 1", func(t *testing.T) {
		name := fmt.Sprintf("b566-tolerating-%d", suffix)
		in := []corev1.Toleration{{Key: policy.ProviderTaintKey, Operator: corev1.TolerationOpExists}}
		stored := create(t, name, in)
		if !reflect.DeepEqual(stored.Spec.Template.Spec.Tolerations, in) {
			t.Errorf("stored tolerations = %+v, want unchanged %+v", stored.Spec.Template.Spec.Tolerations, in)
		}
		if stored.Generation != 1 {
			t.Errorf("generation after create = %d, want 1", stored.Generation)
		}
		// Re-read before the no-op UPDATE: the DaemonSet controller writes status
		// after create, so the created object's resourceVersion is already stale.
		var updated *appsv1.DaemonSet
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			fresh, err := dss.Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			updated, err = dss.Update(ctx, fresh, metav1.UpdateOptions{})
			return err
		})
		if err != nil {
			t.Fatalf("no-op update: %v", err)
		}
		if updated.Generation != 1 {
			t.Errorf("generation after a no-op UPDATE = %d, want 1 (the policy must not mutate a tolerating template)", updated.Generation)
		}
		if !reflect.DeepEqual(updated.Spec.Template.Spec.Tolerations, in) {
			t.Errorf("tolerations after a no-op UPDATE = %+v, want unchanged %+v", updated.Spec.Template.Spec.Tolerations, in)
		}
	})

	t.Run("different-key toleration: kept, provider appended", func(t *testing.T) {
		name := fmt.Sprintf("b566-otherkey-%d", suffix)
		other := corev1.Toleration{Key: "example.com/b566", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}
		stored := create(t, name, []corev1.Toleration{other})
		want := []corev1.Toleration{other, provider}
		if !reflect.DeepEqual(stored.Spec.Template.Spec.Tolerations, want) {
			t.Errorf("stored tolerations = %+v, want %+v", stored.Spec.Template.Spec.Tolerations, want)
		}
	})
}

// b566DaemonSet is a native sleep DaemonSet on darwin nodes with the given template
// tolerations (nil: none).
func b566DaemonSet(name string, tolerations []corev1.Toleration) *appsv1.DaemonSet {
	labels := map[string]string{"app": name}
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: conformanceNS},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{"kubernetes.io/os": "darwin"},
					Tolerations:  tolerations,
					Containers: []corev1.Container{{
						Name:    "sleep",
						Image:   "native",
						Command: []string{"/bin/sh", "-c", "exec /bin/sleep 3600"},
					}},
				},
			},
		},
	}
}

// b566EligibleNodes counts the Ready darwin nodes the DaemonSet controller should
// place a daemon pod on: no NoSchedule/NoExecute taint other than the provider one
// and the node.kubernetes.io/* taints a DaemonSet tolerates on its own.
func b566EligibleNodes(t *testing.T, c *Cluster) int {
	t.Helper()
	nodes, err := c.Client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: "kubernetes.io/os=darwin"})
	if err != nil {
		t.Fatalf("list darwin nodes: %v", err)
	}
	n := 0
	for i := range nodes.Items {
		node := &nodes.Items[i]
		ready := false
		for _, cond := range node.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
				ready = true
			}
		}
		foreign := false
		for _, taint := range node.Spec.Taints {
			if taint.Effect == corev1.TaintEffectPreferNoSchedule || taint.Key == policy.ProviderTaintKey ||
				strings.HasPrefix(taint.Key, "node.kubernetes.io/") {
				continue
			}
			foreign = true
		}
		if ready && !foreign {
			n++
		} else {
			t.Logf("node %s not counted: ready=%v, foreign taint=%v", node.Name, ready, foreign)
		}
	}
	return n
}

// countProvider counts the tolerations keyed to the provider taint.
func countProvider(tols []corev1.Toleration) int {
	n := 0
	for _, tol := range tols {
		if tol.Key == policy.ProviderTaintKey {
			n++
		}
	}
	return n
}
