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
	"flag"
	"io"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// TestAPIServerLoopbackLockstep pins that the executor's loopback decision (the
// --endpoint-reconciler-type=none flag) and the proxy's static kubernetes-VIP
// backend pin can never disagree: both are evaluated from the real flag set,
// through the same mesh rewrite runServer applies, for the default, a mesh
// server, an explicit routable --node-ip, and the `k3sm dev` argv.
func TestAPIServerLoopbackLockstep(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want bool
	}{
		{"default single server", nil, true},
		{"dev tier argv", []string{"--node-ip", "127.0.0.1"}, true},
		{"explicit loopback node-ip", []string{"--node-ip", "127.0.0.2"}, true},
		{"explicit routable node-ip", []string{"--node-ip", "192.0.2.10"}, false},
		{"mesh server", []string{"--mesh-ip", "100.64.0.1"}, false},
		{"mesh server with explicit node-ip", []string{"--mesh-ip", "100.64.0.1", "--node-ip", "100.64.0.1"}, false},
		{"mesh server with a loopback node-ip", []string{"--mesh-ip", "100.64.0.1", "--node-ip", "127.0.0.2"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts serverOptions
			fs := flag.NewFlagSet("server", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			if err := registerServerFlags(fs, &opts); err != nil {
				t.Fatalf("registerServerFlags: %v", err)
			}
			if err := fs.Parse(tt.argv); err != nil {
				t.Fatalf("parse %v: %v", tt.argv, err)
			}
			cfg := opts.executorConfig(nil)
			if opts.meshIP != "" {
				// The mesh bring-up rewrite (serverprovision.go).
				opts.nodeIP = meshNodeIP(opts)
				cfg.NodeIP = opts.meshIP
			}
			exec := executor.IsLoopbackNodeIP(cfg.NodeIP)
			pin := apiServerLoopback(opts)
			if exec != pin {
				t.Fatalf("executor loopback decision %v != static-pin decision %v (cfg.NodeIP=%q opts.nodeIP=%q)", exec, pin, cfg.NodeIP, opts.nodeIP)
			}
			if pin != tt.want {
				t.Errorf("loopback decision = %v, want %v", pin, tt.want)
			}
		})
	}
}
