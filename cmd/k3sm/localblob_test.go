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
	"log/slog"
	"path/filepath"
	"testing"

	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// TestRegistryStoreRootReachesOnlyTheServerRuntime pins the wiring through
// the real option builders: the store root a started registry reports reaches
// the server's runtime config, a server whose registry did not start carries
// none, and an agent never does.
func TestRegistryStoreRootReachesOnlyTheServerRuntime(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "data", "server")
	base := serverOptions{workDir: workDir, nodeName: "n1"}
	if _, err := certs.EnsureHierarchy(workDir, base.role(), base.posture()); err != nil {
		t.Fatalf("EnsureHierarchy: %v", err)
	}
	server := func(w registryPullerWiring) string {
		t.Helper()
		opts, err := serverNodeOptions(serverPlan{opts: base}, &rest.Config{Host: "https://127.0.0.1:6443"}, nodeOptions{},
			serverNodeWiring{registryPuller: w}, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("serverNodeOptions: %v", err)
		}
		return runtimedConfig(opts, nil).RegistryStoreRoot
	}

	root := ingestRegistry{workDir: workDir}.storeRoot()
	if want := registrysvc.StateDir(workDir); root != want {
		t.Fatalf("storeRoot = %q, want the registry's store %q", root, want)
	}
	if got := (ingestRegistry{}).storeRoot(); got != "" {
		t.Fatalf("storeRoot with no work dir = %q, want empty", got)
	}
	if got := server(registryPullerWiring{StoreRoot: root}); got != root {
		t.Errorf("server RegistryStoreRoot = %q, want %q", got, root)
	}
	if got := server(registryPullerWiring{}); got != "" {
		t.Errorf("server with no registry: RegistryStoreRoot = %q, want empty", got)
	}

	join := &bootstrap.JoinResult{PodCIDR: "100.64.2.0/24", MeshIP: "100.64.2.1"}
	agent := agentNodeOptions(agentOptions{workDir: filepath.Join(t.TempDir(), "agent")}, join, "", hostnet.Mode{Backend: hostnet.BackendHelper}, nil)
	if got := runtimedConfig(agent, nil).RegistryStoreRoot; got != "" {
		t.Errorf("agent RegistryStoreRoot = %q, want empty", got)
	}
}
