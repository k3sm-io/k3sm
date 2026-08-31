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

package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/mlx/operator"
)

// stubRuntimeInfo answers the one RPC the MLX GPU source reads.
type stubRuntimeInfo struct {
	resp *runtimev1.GetRuntimeInfoResponse
}

func (s stubRuntimeInfo) GetRuntimeInfo(context.Context, *runtimev1.GetRuntimeInfoRequest) (*runtimev1.GetRuntimeInfoResponse, error) {
	return s.resp, nil
}

// TestServerMLXOperatorConfigWiresALiveGPUSource is the cmd half of the B195
// gate: the Config the SERVER path builds carries a live GPU source, and that
// source reports the node runtime's facts once the node publishes it.
//
// It exists because a dropped GPU wiring is silent by design. A nil GPUSource is
// a legal, documented value meaning "skip the fit check", so a regression that
// stopped setting it would produce no error, no warning and no failing reconcile
// — only models applied unchecked that die at load time. This is the assertion
// that makes that regression mechanical instead of a review question.
func TestServerMLXOperatorConfigWiresALiveGPUSource(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	gpu := operator.NewRuntimeGPU(log)
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{{Group: "mlx.k3sm.io", Version: "v1alpha1", Resource: "mlxmodels"}: "MLXModelList"})

	cfg := mlxOperatorConfig(fake.NewClientset(), dyn, nil, gpu, "cluster.local", log)

	if cfg.GPU == nil {
		t.Fatal("the server path's MLX operator Config carries no GPU source; the pre-render fit check would be skipped in production")
	}
	if cfg.Client == nil || cfg.Dynamic == nil {
		t.Fatal("the Config is missing a required client")
	}
	if cfg.ClusterDomain != "cluster.local" {
		t.Errorf("ClusterDomain = %q, want cluster.local", cfg.ClusterDomain)
	}
	if _, err := operator.New(cfg); err != nil {
		t.Fatalf("the assembled Config does not build an operator: %v", err)
	}

	// Nothing is known before the node publishes its runtime — the documented
	// skip — and the live facts arrive through the SAME callback runServer hands
	// to the node (nodeOptions.attachRuntimeInfo).
	if got := cfg.GPU.GPUFacts(t.Context()); got != nil {
		t.Errorf("GPU facts %v were reported before any runtime was attached", got)
	}
	attach := gpu.Attach // the exact value runServer stores in nodeOptions
	attach(stubRuntimeInfo{resp: &runtimev1.GetRuntimeInfoResponse{
		Gpu: &runtimev1.GPUFacts{MetalAvailable: true, SandboxGpuSupported: true, MemBytes: 64 << 30},
	}})
	got := cfg.GPU.GPUFacts(t.Context())
	if got == nil || !got.GetMetalAvailable() {
		t.Fatalf("after the node published its runtime the operator still reads no gpu facts: %v", got)
	}
}

// TestStandaloneNodeOptionsPublishNoRuntime pins that the runtime-publish hook is
// OPT-IN: every bring-up that is not `k3sm server` leaves it nil and behaves
// exactly as before.
func TestStandaloneNodeOptionsPublishNoRuntime(t *testing.T) {
	if (nodeOptions{}).attachRuntimeInfo != nil {
		t.Error("the zero nodeOptions publishes a runtime; the standalone node and agent paths must be unchanged")
	}
	if agentNodeOptions(agentOptions{}, &bootstrap.JoinResult{}, "kubeconfig", hostnet.Mode{}, nil).attachRuntimeInfo != nil {
		t.Error("the agent path publishes a runtime; only `k3sm server` runs an MLX operator in the same process")
	}
}
