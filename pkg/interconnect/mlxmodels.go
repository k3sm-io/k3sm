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

package interconnect

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// mlxModelGVR is the MLXModel resource the resolver lists (read-only, with the
// server's in-process client).
var mlxModelGVR = mlxv1alpha1.SchemeGroupVersion.WithResource("mlxmodels")

// MLXModelLister returns the resolver's MLXModels source over dyn: the
// namespace, name and UID of every MLXModel, in any namespace, that shards
// across ranks (spec.distributed is set) over a path other than "network"
// (empty means auto). Only such a model's rank may take slot 1. A NotFound list (the
// MLXModel CRD is not served) is a successful read of none; every other error
// is returned, so the resolver writes nothing new on it.
func MLXModelLister(dyn dynamic.Interface) func(ctx context.Context) ([]netv1alpha1.InterconnectModelRef, error) {
	return func(ctx context.Context) ([]netv1alpha1.InterconnectModelRef, error) {
		list, err := dyn.Resource(mlxModelGVR).List(ctx, metav1.ListOptions{})
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("list mlxmodels: %w", err)
		}
		var out []netv1alpha1.InterconnectModelRef
		for i := range list.Items {
			m := &list.Items[i]
			if usesInterconnect(m) {
				out = append(out, netv1alpha1.InterconnectModelRef{Namespace: m.GetNamespace(), Name: m.GetName(), UID: string(m.GetUID())})
			}
		}
		return out, nil
	}
}

// usesInterconnect reports whether u is a sharded MLXModel whose
// spec.distributed.interconnect is not "network".
func usesInterconnect(u *unstructured.Unstructured) bool {
	dist, ok, err := unstructured.NestedMap(u.Object, "spec", "distributed")
	if err != nil || !ok || dist == nil {
		return false
	}
	path, _, err := unstructured.NestedString(dist, "interconnect")
	if err != nil {
		return false
	}
	return path != string(mlxv1alpha1.MLXInterconnectNetwork)
}

// watchMLXModels starts an MLXModel informer over dyn that calls nudge on
// every add and delete, and on every update that changes the generation (a
// spec change, such as a new spec.distributed.interconnect): the desired
// annotation must list a model that moves onto the interconnect before the
// operator places its ranks. A status-only update nudges nothing. The returned
// shutdown waits for the informer to stop, which happens once stop closes. It
// does not wait for the informer to sync: the nudges only bring forward a
// reconcile that lists the MLXModels itself.
func watchMLXModels(dyn dynamic.Interface, nudge func(), stop <-chan struct{}) (shutdown func(), synced cache.InformerSynced) {
	f := dynamicinformer.NewDynamicSharedInformerFactory(dyn, 0)
	inf := f.ForResource(mlxModelGVR).Informer()
	_, _ = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(any) { nudge() },
		UpdateFunc: func(oldObj, newObj any) {
			o, ok1 := oldObj.(*unstructured.Unstructured)
			n, ok2 := newObj.(*unstructured.Unstructured)
			if !ok1 || !ok2 || o.GetGeneration() != n.GetGeneration() || o.GetUID() != n.GetUID() {
				nudge()
			}
		},
		DeleteFunc: func(any) { nudge() },
	})
	f.Start(stop)
	return f.Shutdown, inf.HasSynced
}
