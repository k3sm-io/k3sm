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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	coordclientset "k8s.io/client-go/kubernetes/typed/coordination/v1"
)

// podFieldSelector selects the pods bound to nodeName: spec.nodeName equal to
// it, one term, the selector the pod controller's informer lists and watches with.
func podFieldSelector(nodeName string) fields.Selector {
	return fields.OneTermEqualSelector("spec.nodeName", nodeName)
}

// podInformerFilter scopes a shared informer factory's list and watch calls to
// the pods bound to nodeName.
// Ported from virtual-kubelet v1.14.0 nodeutil/client.go (Apache-2.0).
func podInformerFilter(nodeName string) informers.SharedInformerOption {
	return informers.WithTweakListOptions(func(options *metav1.ListOptions) {
		options.FieldSelector = podFieldSelector(nodeName).String()
	})
}

// nodeLeaseV1Client returns the coordination/v1 Lease client for the
// kube-node-lease namespace, where the node controller keeps its heartbeat Lease.
// Ported from virtual-kubelet v1.14.0 nodeutil/client.go (Apache-2.0).
func nodeLeaseV1Client(client kubernetes.Interface) coordclientset.LeaseInterface {
	return client.CoordinationV1().Leases(corev1.NamespaceNodeLease)
}
