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

package vkadapter

import (
	"crypto/tls"
	"testing"
)

// TestProviderRoutesEnabledGate pins the security-load-bearing invariant that the
// kubelet HTTP provider routes (logs/exec/attach/port-forward) are served ONLY when
// TLS is configured. NewNode consults this single predicate for both wiring
// branches, so a future edit that would expose exec/attach on the plain-HTTP (M0)
// path — an unauthenticated shell into the root-owned runtime over cleartext — flips
// this test red.
func TestProviderRoutesEnabledGate(t *testing.T) {
	tests := []struct {
		name string
		cfg  NodeConfig
		want bool
	}{
		{"nil TLS (M0 plain HTTP) serves NO provider routes", NodeConfig{}, false},
		{"configured TLS serves the provider routes", NodeConfig{TLSConfig: &tls.Config{}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := providerRoutesEnabled(tt.cfg); got != tt.want {
				t.Errorf("providerRoutesEnabled(%+v) = %v, want %v", tt.cfg, got, tt.want)
			}
		})
	}
}

// TestNewNodeRequiresConfigureNode proves NewNode fast-fails on a nil ConfigureNode
// (a constructor error) instead of deferring a nil-call panic into VK's node
// bring-up goroutine at startup.
func TestNewNodeRequiresConfigureNode(t *testing.T) {
	if _, err := NewNode("node0", NodeConfig{}); err == nil {
		t.Fatal("NewNode with a nil ConfigureNode must return an error, got nil")
	}
}
