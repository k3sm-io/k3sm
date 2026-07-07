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
	"errors"
	"flag"
	"fmt"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/hostnet"
)

// TestDefaultRuntimeIsRuntimed pins THE M10.1 default-runtime flip: the shared
// --runtime registration (addRuntimeFlag — the ONE default `k3sm node`, `k3sm
// agent`, and `k3sm server` all use) defaults to runtimed, an empty value
// resolves to it, and the single-node podCIDR derivation matches the enroller's
// reserved index-0 /24.
//
// Fails-before: the three commands each hardcoded "hostprocess" as the default.
func TestDefaultRuntimeIsRuntimed(t *testing.T) {
	t.Parallel()

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var rt string
	addRuntimeFlag(fs, &rt)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rt != runtimeRuntimed {
		t.Errorf("shared --runtime default = %q, want %q (the M10.1 flip)", rt, runtimeRuntimed)
	}
	if got := resolveRuntime(""); got != runtimeRuntimed {
		t.Errorf("resolveRuntime(\"\") = %q, want %q", got, runtimeRuntimed)
	}
	if got := resolveRuntime(runtimeHostProcess); got != runtimeHostProcess {
		t.Errorf("resolveRuntime(hostprocess) = %q, want the explicit opt-out preserved", got)
	}
	if got := defaultNodePodCIDR(); got != "100.64.0.0/24" {
		t.Errorf("defaultNodePodCIDR() = %q, want 100.64.0.0/24 (the enroller's reserved index-0 /24)", got)
	}
}

// TestRuntimePreflight pins the flip's fail-fast contract: a runtimed node with
// a datapath posture it cannot reach REFUSES to start with the NAMED
// errRuntimedPosture error (actionable: `sudo k3sm install` or `--runtime
// hostprocess`), the explicit hostprocess opt-out bypasses the probe entirely,
// and the explicit no-datapath backend (--network none) needs no helper. Never
// a silent degrade.
func TestRuntimePreflight(t *testing.T) {
	helperMode := hostnet.Mode{Backend: hostnet.BackendHelper, Socket: "/tmp/nope.sock"}

	// swapProbe installs a fake probe seam and restores it after the subtest.
	swapProbe := func(t *testing.T, fn func(context.Context, hostnet.Mode) error) *int {
		t.Helper()
		calls := 0
		orig := probeNetdHelper
		probeNetdHelper = func(ctx context.Context, m hostnet.Mode) error {
			calls++
			return fn(ctx, m)
		}
		t.Cleanup(func() { probeNetdHelper = orig })
		return &calls
	}

	t.Run("posture miss refuses to start with the named error", func(t *testing.T) {
		_ = swapProbe(t, func(context.Context, hostnet.Mode) error {
			return fmt.Errorf("dial unix /tmp/nope.sock: no such file or directory")
		})
		err := runtimePreflight(context.Background(), nodeOptions{runtime: runtimeRuntimed, netMode: helperMode})
		if err == nil {
			t.Fatal("runtimePreflight = nil on a posture miss, want the named refuse-to-start error")
		}
		if !errors.Is(err, errRuntimedPosture) {
			t.Errorf("err = %v, want errors.Is errRuntimedPosture", err)
		}
		for _, want := range []string{"sudo k3sm install", "--runtime hostprocess"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err %q missing the operator action %q", err, want)
			}
		}
	})

	t.Run("empty runtime resolves to runtimed and preflights", func(t *testing.T) {
		calls := swapProbe(t, func(context.Context, hostnet.Mode) error { return errors.New("unreachable") })
		err := runtimePreflight(context.Background(), nodeOptions{runtime: "", netMode: helperMode})
		if !errors.Is(err, errRuntimedPosture) || *calls != 1 {
			t.Errorf("empty runtime: err = %v (probe calls %d), want the named error after one probe", err, *calls)
		}
	})

	t.Run("hostprocess bypasses the preflight", func(t *testing.T) {
		calls := swapProbe(t, func(context.Context, hostnet.Mode) error { return errors.New("must not fire") })
		if err := runtimePreflight(context.Background(), nodeOptions{runtime: runtimeHostProcess, netMode: helperMode}); err != nil {
			t.Errorf("hostprocess preflight = %v, want nil (explicit rootless opt-out)", err)
		}
		if *calls != 0 {
			t.Errorf("probe fired %d times for hostprocess, want 0", *calls)
		}
	})

	t.Run("network none needs no helper", func(t *testing.T) {
		calls := swapProbe(t, func(context.Context, hostnet.Mode) error { return errors.New("must not fire") })
		none := hostnet.Mode{Backend: hostnet.BackendNone}
		if err := runtimePreflight(context.Background(), nodeOptions{runtime: runtimeRuntimed, netMode: none}); err != nil {
			t.Errorf("--network none preflight = %v, want nil (explicit no-datapath backend)", err)
		}
		if *calls != 0 {
			t.Errorf("probe fired %d times for --network none, want 0", *calls)
		}
	})

	t.Run("reachable posture passes", func(t *testing.T) {
		_ = swapProbe(t, func(context.Context, hostnet.Mode) error { return nil })
		if err := runtimePreflight(context.Background(), nodeOptions{runtime: runtimeRuntimed, netMode: helperMode}); err != nil {
			t.Errorf("preflight = %v, want nil when the probe succeeds", err)
		}
	})
}
