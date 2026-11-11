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

package mlx

import (
	"errors"
	"testing"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

// TestRenderRefusesHubFetchArgsForClusterStoreModels pins that a cluster-store
// model, which runs with the Hub switched off, is refused at render when
// spec.runtime.args names a second Hub repository through --adapter-path or
// --draft-model, in either flag form; that an absolute path and unrelated args
// pass; that an unambiguous abbreviation is refused while an option merely
// sharing leading letters is not; that the sharded path refuses alike; and
// that a Hub model keeps passing a repo id through unchecked.
func TestRenderRefusesHubFetchArgsForClusterStoreModels(t *testing.T) {
	tests := []struct {
		name    string
		model   func() *mlxv1alpha1.MLXModel
		args    []string
		refused bool
	}{
		{"hub_adapter_repo_id", newModel, []string{"--adapter-path", "org/adapter"}, false},
		{"hub_draft_repo_id_equals", newModel, []string{"--draft-model=org/draft"}, false},
		{"store_adapter_repo_id", artifactModel, []string{"--adapter-path", "org/adapter"}, true},
		{"store_adapter_repo_id_equals", artifactModel, []string{"--adapter-path=org/adapter"}, true},
		{"store_draft_repo_id", artifactModel, []string{"--draft-model", "org/draft"}, true},
		{"store_draft_repo_id_equals", artifactModel, []string{"--draft-model=org/draft"}, true},
		{"store_adapter_missing_value", artifactModel, []string{"--adapter-path"}, true},
		{"store_adapter_absolute", artifactModel, []string{"--adapter-path", "/models/adapter"}, false},
		{"store_draft_absolute_equals", artifactModel, []string{"--draft-model=/models/draft"}, false},
		{"store_unrelated_args", artifactModel, []string{"--log-level", "DEBUG", "--trust-remote-code"}, false},
		{"store_adapter_abbreviated", artifactModel, []string{"--adapter", "org/a"}, true},
		{"store_draft_abbreviated", artifactModel, []string{"--draft-m", "org/d"}, true},
		{"store_adapter_rank_shares_letters", artifactModel, []string{"--adapter-rank", "8"}, false},
		{"store_decode_concurrency_shares_letters", artifactModel, []string{"--decode-concurrency", "2"}, false},
		{"store_dtype_shares_letters", artifactModel, []string{"--dtype", "float16"}, false},
		// A relative path resolves against a working directory the spec does
		// not name, and the engine falls back to the Hub when nothing is there.
		{"store_adapter_relative", artifactModel, []string{"--adapter-path", "adapters/v2"}, true},
		{"sharded_store_adapter_repo_id", shardedArtifactModel, []string{"--adapter-path", "org/adapter"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.model()
			m.Spec.Runtime.Args = tc.args
			err := renderEither(m)
			if tc.refused {
				if !errors.Is(err, ErrClusterStoreHubArg) {
					t.Fatalf("render error = %v, want %v", err, ErrClusterStoreHubArg)
				}
				return
			}
			if err != nil {
				t.Fatalf("render: %v", err)
			}
		})
	}
}
