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

package controller

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	helmv1 "k3sm.io/apis/helm/v1"
)

// toChart decodes an unstructured HelmChart through JSON, the encoding the
// types define round-trip behaviour for (the IntOrString set values and the
// Duration timeout).
func toChart(u *unstructured.Unstructured) (*helmv1.HelmChart, error) {
	raw, err := u.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("encode unstructured helmchart: %w", err)
	}
	var c helmv1.HelmChart
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("decode helmchart: %w", err)
	}
	return &c, nil
}

// toConfig decodes an unstructured HelmChartConfig.
func toConfig(u *unstructured.Unstructured) (*helmv1.HelmChartConfig, error) {
	raw, err := u.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("encode unstructured helmchartconfig: %w", err)
	}
	var c helmv1.HelmChartConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("decode helmchartconfig: %w", err)
	}
	return &c, nil
}

// toUnstructured encodes a HelmChart for the dynamic client, with the TypeMeta
// the dynamic client requires.
func toUnstructured(c *helmv1.HelmChart) (*unstructured.Unstructured, error) {
	out := c.DeepCopy()
	out.APIVersion = helmv1.SchemeGroupVersion.String()
	out.Kind = "HelmChart"
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("encode helmchart: %w", err)
	}
	u := &unstructured.Unstructured{}
	if err := u.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("decode helmchart into unstructured: %w", err)
	}
	return u, nil
}
