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

package linkgraph

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// Resource is the DirectLink CRD's resource name within net.k3sm.io/v1alpha1.
const Resource = "directlinks"

// RESTClient builds a typed REST client for net.k3sm.io/v1alpha1 DirectLinks (the
// construction the MeshPeer client uses for v1).
func RESTClient(cfg *rest.Config) (rest.Interface, error) {
	scheme := runtime.NewScheme()
	if err := netv1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register net.k3sm.io/v1alpha1 scheme: %w", err)
	}
	codecs := serializer.NewCodecFactory(scheme)
	rc := rest.CopyConfig(cfg)
	rc.GroupVersion = &netv1alpha1.SchemeGroupVersion
	rc.APIPath = "/apis"
	rc.NegotiatedSerializer = codecs.WithoutConversion()
	return rest.RESTClientFor(rc)
}

// Store reads and writes DirectLink objects. The node never writes them itself:
// the server's own client does, after the publish verb authenticated the node.
type Store struct {
	Client rest.Interface
}

// List returns every DirectLink.
func (s Store) List(ctx context.Context) ([]netv1alpha1.DirectLink, error) {
	var list netv1alpha1.DirectLinkList
	if err := s.Client.Get().Resource(Resource).Do(ctx).Into(&list); err != nil {
		return nil, fmt.Errorf("list direct links: %w", err)
	}
	return list.Items, nil
}

// Get returns one node's DirectLink, and false when it does not exist.
func (s Store) Get(ctx context.Context, node string) (*netv1alpha1.DirectLink, bool, error) {
	var dl netv1alpha1.DirectLink
	err := s.Client.Get().Resource(Resource).Name(node).Do(ctx).Into(&dl)
	if apierrors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read direct link %q: %w", node, err)
	}
	return &dl, true, nil
}

// NodeOwner is the Node a DirectLink is owned by: its name and UID. A zero UID
// means the Node does not exist yet; the object is then written without an owner
// and gains one on a later write.
type NodeOwner struct {
	Name string
	UID  types.UID
}

func (o NodeOwner) reference() []metav1.OwnerReference {
	if o.UID == "" {
		return nil
	}
	return []metav1.OwnerReference{{APIVersion: "v1", Kind: "Node", Name: o.Name, UID: o.UID}}
}

// ApplySpec creates the node's DirectLink, or replaces the spec of the existing
// one, leaving its status alone (the status subresource is the resolver's). It
// first refuses a domain UUID another node lists (CheckDomainUUIDs). The caller
// serializes concurrent writers.
func (s Store) ApplySpec(ctx context.Context, spec netv1alpha1.DirectLinkSpec, owner NodeOwner) error {
	all, err := s.List(ctx)
	if err != nil {
		return err
	}
	if err := CheckDomainUUIDs(spec, all); err != nil {
		return err
	}
	var cur *netv1alpha1.DirectLink
	for i := range all {
		if all[i].Name == spec.NodeName {
			cur = &all[i]
		}
	}
	if cur == nil {
		obj := &netv1alpha1.DirectLink{
			TypeMeta:   metav1.TypeMeta{APIVersion: netv1alpha1.SchemeGroupVersion.String(), Kind: "DirectLink"},
			ObjectMeta: metav1.ObjectMeta{Name: spec.NodeName, OwnerReferences: owner.reference()},
			Spec:       spec,
		}
		if err := s.Client.Post().Resource(Resource).Body(obj).Do(ctx).Error(); err != nil {
			return fmt.Errorf("create direct link %q: %w", spec.NodeName, err)
		}
		return nil
	}
	cur.Spec = spec
	if len(cur.OwnerReferences) == 0 {
		cur.OwnerReferences = owner.reference()
	}
	cur.TypeMeta = metav1.TypeMeta{APIVersion: netv1alpha1.SchemeGroupVersion.String(), Kind: "DirectLink"}
	if err := s.Client.Put().Resource(Resource).Name(spec.NodeName).Body(cur).Do(ctx).Error(); err != nil {
		return fmt.Errorf("update direct link %q: %w", spec.NodeName, err)
	}
	return nil
}

// UpdateStatus writes a DirectLink's status through the status subresource.
func (s Store) UpdateStatus(ctx context.Context, dl *netv1alpha1.DirectLink) error {
	obj := dl.DeepCopy()
	obj.TypeMeta = metav1.TypeMeta{APIVersion: netv1alpha1.SchemeGroupVersion.String(), Kind: "DirectLink"}
	if err := s.Client.Put().Resource(Resource).Name(obj.Name).SubResource("status").Body(obj).Do(ctx).Error(); err != nil {
		return fmt.Errorf("update direct link %q status: %w", obj.Name, err)
	}
	return nil
}

// Delete removes a node's DirectLink; an absent one is success.
func (s Store) Delete(ctx context.Context, node string) error {
	if err := s.Client.Delete().Resource(Resource).Name(node).Do(ctx).Error(); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete direct link %q: %w", node, err)
	}
	return nil
}
