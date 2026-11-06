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

package vkadapter

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

// replacingHandler keeps a same-name re-create from being read as an update of the pod
// it replaces. Virtual Kubelet's queue is keyed by namespace/name, so a delete with no
// deletion stamp (a force delete) and a re-create can reach it as one sync, which finds
// the new object in its lister and asks GetPod. Answered with the old pod, it compares
// specs without the UID: the same spec makes no provider call at all, and another makes
// UpdatePod under a UID the provider has never created. No DeletePod comes either way.
//
// Only here do the two UIDs meet, so the old pod is read as gone to Virtual Kubelet,
// whose next call is then the successor's CreatePod, and that create stops the old pod
// first as a kubelet would: through the provider's own DeletePod, so its preStop hooks
// and grace period are honoured, on the queue's worker, so nothing else of this key runs
// until the stop is over. A failed stop fails the create, and Virtual Kubelet retries it.
type replacingHandler struct {
	PodLifecycleHandler
	pods corev1listers.PodLister
}

// replacingNotifier is a replacingHandler over a provider that pushes pod status:
// Virtual Kubelet polls a provider that does not, so the wrapper must not claim to.
type replacingNotifier struct {
	replacingHandler
	PodNotifier
}

// ReplaceRecreatedPods returns h with a re-created pod replacing, on Virtual Kubelet's
// queue, the pod of its name that h still holds under another UID. pods is the lister
// Virtual Kubelet's pod controller reads.
func ReplaceRecreatedPods(h PodLifecycleHandler, pods corev1listers.PodLister) PodLifecycleHandler {
	r := replacingHandler{PodLifecycleHandler: h, pods: pods}
	if n, ok := h.(PodNotifier); ok {
		return replacingNotifier{replacingHandler: r, PodNotifier: n}
	}
	return r
}

// GetPod answers NotFound for a pod the lister holds under another UID. With the name
// gone from the lister it answers as ever: that read is how Virtual Kubelet finds a
// deleted pod to delete.
func (r replacingHandler) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	held, err := r.PodLifecycleHandler.GetPod(ctx, namespace, name)
	if err != nil || held == nil {
		return held, err
	}
	if current, err := r.pods.Pods(namespace).Get(name); err == nil && current.UID != held.UID {
		return nil, NotFoundf("pod %s/%s: UID %s is replaced by %s", namespace, name, held.UID, current.UID)
	}
	return held, nil
}

// CreatePod stops the pod the name holds under another UID, then creates pod.
func (r replacingHandler) CreatePod(ctx context.Context, pod *corev1.Pod) error {
	held, err := r.PodLifecycleHandler.GetPod(ctx, pod.Namespace, pod.Name)
	if err != nil && !IsNotFound(err) {
		return fmt.Errorf("read the pod %s/%s replaces: %w", pod.Namespace, pod.Name, err)
	}
	if err == nil && held != nil && held.UID != pod.UID {
		if err := r.PodLifecycleHandler.DeletePod(ctx, held); err != nil && !IsNotFound(err) {
			return fmt.Errorf("stop UID %s of pod %s/%s before its successor: %w", held.UID, pod.Namespace, pod.Name, err)
		}
	}
	return r.PodLifecycleHandler.CreatePod(ctx, pod)
}
