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

package executor

import "testing"

// TestAPIServerArgsForLoopbackNodeIP pins the loopback-advertise posture: the
// lease endpoint reconciler rejects a loopback --advertise-address (the
// apiserver fails to start at kubernetes v1.37.1), so a loopback NodeIP renders
// --endpoint-reconciler-type=none and every other NodeIP renders no such flag,
// while the bind address, service range and trust flags are unchanged.
func TestAPIServerArgsForLoopbackNodeIP(t *testing.T) {
	const reconciler = "--endpoint-reconciler-type=none"
	tests := []struct {
		name     string
		nodeIP   string
		bind     string
		wantNone bool
	}{
		{"ipv4 loopback", "127.0.0.1", "", true},
		{"other 127/8 address", "127.0.0.2", "", true},
		{"ipv6 loopback", "::1", "", true},
		{"mesh ip", "100.64.0.1", "100.64.0.1", false},
		{"routable node ip", "192.0.2.10", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{WorkDir: "/var/lib/k3sm/server", KinePort: 2379, APIServerPort: 6444, NodeIP: tt.nodeIP, BindAddress: tt.bind}
			args := apiServerArgs(cfg)
			if got := hasArg(args, reconciler); got != tt.wantNone {
				t.Errorf("%s present = %v, want %v\nargs: %v", reconciler, got, tt.wantNone, args)
			}
			if got := flagValue(args, "--advertise-address"); got != tt.nodeIP {
				t.Errorf("--advertise-address = %q, want %q", got, tt.nodeIP)
			}
			wantBind := tt.bind
			if wantBind == "" {
				wantBind = tt.nodeIP
			}
			if got := flagValue(args, "--bind-address"); got != wantBind {
				t.Errorf("--bind-address = %q, want %q", got, wantBind)
			}
			if got := flagValue(args, "--service-cluster-ip-range"); got != "10.43.0.0/16" {
				t.Errorf("--service-cluster-ip-range = %q", got)
			}
			if got := flagValue(args, "--authorization-mode"); got != DefaultAuthorizationMode {
				t.Errorf("--authorization-mode = %q, want %q", got, DefaultAuthorizationMode)
			}
			if !hasArg(args, "--enable-admission-plugins=NodeRestriction") {
				t.Errorf("NodeRestriction admission missing")
			}
		})
	}
}

func TestIsLoopbackNodeIP(t *testing.T) {
	for ip, want := range map[string]bool{"127.0.0.1": true, "127.1.2.3": true, "::1": true, "": false, "garbage": false, "100.64.0.1": false, "0.0.0.0": false} {
		if got := IsLoopbackNodeIP(ip); got != want {
			t.Errorf("IsLoopbackNodeIP(%q) = %v, want %v", ip, got, want)
		}
	}
}
