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

package runtimeclass

import (
	"context"
	"fmt"

	nodev1 "k8s.io/api/node/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Name is the name (and handler) of the node.k8s.io/v1 RuntimeClass k3sm
// provisions for the Virtualization.framework micro-VM backend. A pod opts in with
// spec.runtimeClassName: vm. It is sourced from the apis handler constant so the
// RuntimeClass, its handler, and the apis handler→backend table never drift.
const Name = string(runtimev1.HandlerVM)

// LabelVirtualization is the node label the vm RuntimeClass pins its
// scheduling.nodeSelector to: a node carries it (value LabelTrue) iff it can run
// the Virtualization.framework micro-VM backend. Absent ⇒ no VZ node ⇒ a vm pod
// stays Unschedulable (the fail-closed posture for a non-VZ cluster). cmd/k3sm sets
// the node label from the node's VZ availability; this package and the node command
// share the key so the RuntimeClass selector and the node label never drift.
const LabelVirtualization = "k3sm.io/virtualization"

// LabelTrue is the value LabelVirtualization carries on a VZ-capable node — and the
// value this RuntimeClass's nodeSelector requires.
const LabelTrue = "true"

// managedLabel marks the RuntimeClass this package provisions, matching pkg/rbac /
// pkg/policy so k3sm-managed objects are greppable and distinct from operator- or
// apiserver-authored ones.
const managedLabel = "k3sm.io/managed"

// Provision idempotently provisions the vm RuntimeClass: a node.k8s.io/v1
// RuntimeClass named "vm" with handler "vm" and a scheduling.nodeSelector requiring
// LabelVirtualization=LabelTrue, so a pod with spec.runtimeClassName: vm is
// scheduled ONLY onto a node that advertises the Virtualization.framework backend
// (the kube RuntimeClass admission plugin merges the selector into the pod). It is
// safe to call on every server start (AlreadyExists is success) and authors only
// the k3sm-named "vm" object.
//
// It is Create-tolerate-AlreadyExists and never LISTs to decide what to provision
// (matching pkg/rbac under the pinned kine, where ConsistentListFromCache is
// GA-locked true and a watch-cache LIST can read stale). A missing RuntimeClass is
// itself fail-closed — a vm pod referencing an absent RuntimeClass is rejected at
// admission — so unlike pkg/rbac the caller may treat an error as log-and-continue.
func Provision(ctx context.Context, cs kubernetes.Interface) error {
	rc := &nodev1.RuntimeClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:   Name,
			Labels: map[string]string{managedLabel: "true"},
		},
		Handler: string(runtimev1.HandlerVM),
		Scheduling: &nodev1.Scheduling{
			NodeSelector: map[string]string{LabelVirtualization: LabelTrue},
		},
	}
	if _, err := cs.NodeV1().RuntimeClasses().Create(ctx, rc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create vm runtime class: %w", err)
	}
	return nil
}
