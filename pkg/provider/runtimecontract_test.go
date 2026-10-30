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

package provider

import (
	"testing"

	"k3sm.io/apis/k3smtest/runtimecontract"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestRuntimeContract runs the shared runtime/v1 contract suite against the
// in-memory runtime the provider's tests drive, so the fake keeps the same
// seam contract the real daemon keeps (the daemon runs this suite in its own
// repository). A provider test that passes against a fake breaking the
// contract would prove nothing about the daemon.
func TestRuntimeContract(t *testing.T) {
	runtimecontract.RunRuntimeContract(t, runtimecontract.RuntimeContract{
		Client: runtimecontract.ServeRuntime(t, newFakeRuntimeServer()),
		Pod: func(id string) *runtimev1.PodBox {
			return &runtimev1.PodBox{
				PodId:      id,
				Namespace:  "default",
				Name:       "p",
				Containers: []*runtimev1.Container{{Name: "c0", Image: "web"}},
			}
		},
	})
}
