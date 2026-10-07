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
	"log/slog"
	"path/filepath"
	"testing"

	"k8s.io/client-go/rest"
)

// TestServerPhaseStopsAreNeverNil pins the contract runServer's unconditional
// `defer stop()` depends on: a phase that started nothing — disabled by its flag,
// or failed to build — still returns a callable stop. A nil one would panic on
// the way out of every bring-up that took that path, masking the real exit.
//
// Only the disabled and failed paths are driven: each enabled path starts a real
// goroutine (a registry child, the worker-join listener, the MLX reconcile).
// startJoinSupervisor's HA path with an unreachable etcd member also starts the
// join listener, so it is not driven here; it shares the same `stop = noStop`
// default as the disabled path below.
func TestServerPhaseStopsAreNeverNil(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A REST config whose client cannot be built: the CA file does not exist.
	badREST := &rest.Config{Host: "https://127.0.0.1:1", TLSClientConfig: rest.TLSClientConfig{
		CAFile: filepath.Join(t.TempDir(), "absent-ca.crt"),
	}}

	for _, tc := range []struct {
		name  string
		start func() func()
	}{
		{"registry disabled (--registry-port 0)", func() func() {
			stop, _ := startServerRegistry(ctx, serverPlan{opts: serverOptions{registryPort: 0}}, nil, false, logger)
			return stop
		}},
		{"registry failed to build (no work dir)", func() func() {
			stop, _ := startServerRegistry(ctx, serverPlan{opts: serverOptions{registryPort: 5000}}, nil, false, logger)
			return stop
		}},
		{"join supervisor disabled (no mesh enroller)", func() func() {
			return startJoinSupervisor(ctx, serverPlan{}, nil, serverMesh{}, logger)
		}},
		{"mlx operator failed to build its clients", func() func() {
			gpu, stop := startMLXOperator(ctx, serverPlan{}, badREST, nil, logger)
			if gpu == nil {
				t.Error("startMLXOperator returned a nil GPU source; the node's attachRuntimeInfo would panic")
			}
			return stop
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stop := tc.start()
			if stop == nil {
				t.Fatal("stop is nil; runServer's `defer stop()` would panic on this path")
			}
			stop()
		})
	}
}
