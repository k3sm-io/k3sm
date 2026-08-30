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

package operator

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

// toModel decodes the unstructured object an informer or a dynamic Get returned
// into the typed MLXModel.
//
// It round-trips through JSON rather than using the reflective unstructured
// converter, because the spec carries resource.Quantity values whose ONLY exact
// representation is their own string form ("24Gi"). JSON is the encoding those
// types define round-trip behaviour for; anything else risks a quantity that
// re-serializes to a different scale than the user wrote, which would then look
// like the operator edited the spec.
func toModel(u *unstructured.Unstructured) (*mlxv1alpha1.MLXModel, error) {
	raw, err := u.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("encode unstructured mlxmodel: %w", err)
	}
	var m mlxv1alpha1.MLXModel
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode mlxmodel: %w", err)
	}
	return &m, nil
}

// toUnstructured encodes a typed MLXModel back for the dynamic client, filling in
// the TypeMeta the dynamic client requires and the typed object does not carry
// after a decode.
func toUnstructured(m *mlxv1alpha1.MLXModel) (*unstructured.Unstructured, error) {
	out := m.DeepCopy()
	out.APIVersion = mlxv1alpha1.SchemeGroupVersion.String()
	out.Kind = "MLXModel"

	raw, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("encode mlxmodel: %w", err)
	}
	u := &unstructured.Unstructured{}
	if err := u.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("decode mlxmodel into unstructured: %w", err)
	}
	return u, nil
}

// statusEqual reports whether two statuses are semantically identical, so an
// unchanged status is not rewritten on every resync.
//
// equality.Semantic, not reflect.DeepEqual: it knows that two resource.Quantity
// values with different internal caches are the same number, and that a nil slice
// and an empty one mean the same thing here. A byte-exact comparison would find a
// difference on most passes and defeat the skip entirely.
func statusEqual(a, b mlxv1alpha1.MLXModelStatus) bool {
	return equality.Semantic.DeepEqual(a, b)
}
