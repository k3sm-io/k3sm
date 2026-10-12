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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// GVR is the Interconnect resource.
var GVR = schema.GroupVersionResource{Group: netv1alpha1.SchemeGroupVersion.Group, Version: netv1alpha1.SchemeGroupVersion.Version, Resource: "interconnects"}

// Name is the one Interconnect object this version manages: one per medium,
// named for it.
const Name = netv1alpha1.MediumThunderbolt

// Store reads and writes Interconnect objects through a dynamic client; the
// apis module ships the Go type but no typed clientset.
type Store struct {
	Client dynamic.Interface
}

func (s Store) res() dynamic.ResourceInterface { return s.Client.Resource(GVR) }

// Get returns the named Interconnect.
func (s Store) Get(ctx context.Context, name string) (*netv1alpha1.Interconnect, error) {
	u, err := s.res().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return fromUnstructured(u)
}

// Create creates ic.
func (s Store) Create(ctx context.Context, ic *netv1alpha1.Interconnect) (*netv1alpha1.Interconnect, error) {
	u, err := toUnstructured(ic)
	if err != nil {
		return nil, err
	}
	out, err := s.res().Create(ctx, u, metav1.CreateOptions{FieldManager: FieldManager})
	if err != nil {
		return nil, err
	}
	return fromUnstructured(out)
}

// UpdateStatus writes ic's status through the status subresource, guarded by
// ic's resourceVersion (a conflict is returned, never overwritten).
func (s Store) UpdateStatus(ctx context.Context, ic *netv1alpha1.Interconnect) (*netv1alpha1.Interconnect, error) {
	u, err := toUnstructured(ic)
	if err != nil {
		return nil, err
	}
	out, err := s.res().UpdateStatus(ctx, u, metav1.UpdateOptions{FieldManager: FieldManager})
	if err != nil {
		return nil, err
	}
	return fromUnstructured(out)
}

// Patch merge-patches the named Interconnect, or its status when subresource
// is "status".
func (s Store) Patch(ctx context.Context, name string, patch []byte, subresource ...string) (*netv1alpha1.Interconnect, error) {
	out, err := s.res().Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{FieldManager: FieldManager}, subresource...)
	if err != nil {
		return nil, err
	}
	return fromUnstructured(out)
}

func toUnstructured(ic *netv1alpha1.Interconnect) (*unstructured.Unstructured, error) {
	c := ic.DeepCopy()
	c.APIVersion = netv1alpha1.SchemeGroupVersion.String()
	c.Kind = "Interconnect"
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(c)
	if err != nil {
		return nil, fmt.Errorf("convert interconnect %s: %w", ic.Name, err)
	}
	return &unstructured.Unstructured{Object: m}, nil
}

func fromUnstructured(u *unstructured.Unstructured) (*netv1alpha1.Interconnect, error) {
	var ic netv1alpha1.Interconnect
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &ic); err != nil {
		return nil, fmt.Errorf("decode interconnect %s: %w", u.GetName(), err)
	}
	return &ic, nil
}
