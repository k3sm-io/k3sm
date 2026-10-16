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

package updatectl

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
)

// mirrorPodAnnotation marks a static pod's API mirror (kubectl drain skips
// those: deleting a mirror does not stop the static pod).
const mirrorPodAnnotation = "kubernetes.io/config.mirror"

// drain evicts every pod on the node that a drain moves and returns the ones
// still present, sorted as namespace/name. It never waits: the caller polls
// until nothing remains or its timeout passes.
//
// Before any eviction it lists the bare pods (no controller owner): evicting
// one deletes it for good, so drain returns them in bare and evicts nothing,
// and the caller fails the node with the list rather than delete them.
//
// Evictions go through the eviction API, so a PodDisruptionBudget that cannot
// lose a pod answers 429 and the pod stays for a later pass, as kubectl drain
// retries it. DaemonSet-owned pods (the DaemonSet controller would recreate
// them on the cordoned node regardless) and mirror pods are left in place, as
// are pods that have already finished.
func (c *Controller) drain(ctx context.Context, node string) (remaining, bare []string, err error) {
	pods, err := c.cfg.Client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", node).String(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("list pods on %s: %w", node, err)
	}
	var moved []*corev1.Pod
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Spec.NodeName != node || !drained(p) {
			continue
		}
		if metav1.GetControllerOf(p) == nil {
			bare = append(bare, p.Namespace+"/"+p.Name)
		}
		moved = append(moved, p)
	}
	if len(bare) > 0 {
		sort.Strings(bare)
		return nil, bare, nil
	}
	for _, p := range moved {
		key := p.Namespace + "/" + p.Name
		if p.DeletionTimestamp != nil {
			remaining = append(remaining, key) // already going
			continue
		}
		err := c.cfg.Client.PolicyV1().Evictions(p.Namespace).Evict(ctx, &policyv1.Eviction{
			ObjectMeta: metav1.ObjectMeta{Name: p.Name, Namespace: p.Namespace},
		})
		switch {
		case err == nil:
			remaining = append(remaining, key) // evicted; gone once it terminates
		case apierrors.IsNotFound(err):
		case apierrors.IsTooManyRequests(err):
			remaining = append(remaining, key) // a PodDisruptionBudget holds it
		default:
			c.log.Warn("update controller: evict pod", "pod", key, "node", node, "err", err)
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)
	return remaining, nil, nil
}

// drained reports whether a drain moves p.
func drained(p *corev1.Pod) bool {
	if _, mirror := p.Annotations[mirrorPodAnnotation]; mirror {
		return false
	}
	if ref := metav1.GetControllerOf(p); ref != nil && ref.Kind == "DaemonSet" {
		return false
	}
	switch p.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
		return false
	}
	return true
}
