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
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// FieldManager is the field manager of every write this package makes.
const FieldManager = "k3sm-interconnect"

// ownNodeResync is the own-node informer's resync period.
const ownNodeResync = 10 * time.Minute

// OwnNode is this node's view of its own Node object: a single-object informer
// (field selector on its name, which the Node authorizer allows a node to watch)
// and merge-patch writes of its own annotations (which NodeRestriction allows).
type OwnNode struct {
	client   kubernetes.Interface
	name     string
	informer cache.SharedIndexInformer
	changed  chan struct{}
}

// NewOwnNode returns an OwnNode over client for the Node named name.
func NewOwnNode(client kubernetes.Interface, name string) *OwnNode {
	f := informers.NewSharedInformerFactoryWithOptions(client, ownNodeResync,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
		}))
	o := &OwnNode{client: client, name: name, informer: f.Core().V1().Nodes().Informer(), changed: make(chan struct{}, 1)}
	_, _ = o.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { o.signal() },
		UpdateFunc: func(_, _ any) { o.signal() },
		DeleteFunc: func(any) { o.signal() },
	})
	return o
}

// Run runs the informer until ctx ends.
func (o *OwnNode) Run(ctx context.Context) { o.informer.Run(ctx.Done()) }

// Changed delivers a signal after every change to the Node (coalesced).
func (o *OwnNode) Changed() <-chan struct{} { return o.changed }

func (o *OwnNode) signal() {
	select {
	case o.changed <- struct{}{}:
	default:
	}
}

// Annotation returns the named annotation from the cache; ok is false until
// the informer has synced and while the Node is not in it.
func (o *OwnNode) Annotation(key string) (string, bool) {
	if !o.informer.HasSynced() {
		return "", false
	}
	obj, exists, err := o.informer.GetStore().GetByKey(o.name)
	if err != nil || !exists {
		return "", false
	}
	n, ok := obj.(*corev1.Node)
	if !ok {
		return "", false
	}
	return n.Annotations[key], true
}

// SetAnnotation merge-patches one annotation on this node's own Node; value ""
// deletes it.
func (o *OwnNode) SetAnnotation(ctx context.Context, key, value string) error {
	return PatchNodeAnnotation(ctx, o.client, o.name, key, value)
}

// For returns an Annotator over one key.
func (o *OwnNode) For(key string) Annotator { return ownAnnotation{o: o, key: key} }

type ownAnnotation struct {
	o   *OwnNode
	key string
}

func (a ownAnnotation) Current() (string, bool) { return a.o.Annotation(a.key) }

func (a ownAnnotation) Set(ctx context.Context, value string) error {
	return a.o.SetAnnotation(ctx, a.key, value)
}

// PatchNodeAnnotation merge-patches one annotation on the named Node; value ""
// deletes it.
func PatchNodeAnnotation(ctx context.Context, client kubernetes.Interface, node, key, value string) error {
	var v any
	if value != "" {
		v = value
	}
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]any{key: v}}})
	if err != nil {
		return fmt.Errorf("encode the annotation patch: %w", err)
	}
	if _, err := client.CoreV1().Nodes().Patch(ctx, node, types.MergePatchType, patch, metav1.PatchOptions{FieldManager: FieldManager}); err != nil {
		return fmt.Errorf("patch annotation %s on node %s: %w", key, node, err)
	}
	return nil
}
