//go:build integration && darwin

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
	"errors"
	"net"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// canaryPort is a privileged (<1024) port with no standard service on it, so a
// live listener there is anomalous rather than routine.
const canaryPort = 1023

// TestWildcardPrivilegedBindPremise is the PREMISE CANARY for B116.
//
// The entire design — LoadBalancer and ingress listeners binding 0.0.0.0 with the
// root netd helper off the datapath, no privileged binder anywhere — rests on ONE
// undocumented XNU behaviour, INVERTED from Linux:
//
//	0.0.0.0:<1024   binds fine as an ordinary uid
//	127.0.0.1:<1024 returns EACCES
//
// If a macOS release changes either half, the failure must be LOUD and testable
// rather than a silent regression to EXTERNAL-IP <pending>.
//
// It is TWO-ARMED on purpose. One-armed (wildcard only) it would stay green if
// macOS RELAXED the specific-address rule — silently retiring the whole privilege
// premise while looking healthy. And it discriminates by ERRNO via errors.Is, never
// by string matching, so EADDRINUSE stays distinguishable from EACCES.
func TestWildcardPrivilegedBindPremise(t *testing.T) {
	if os.Geteuid() == 0 {
		// LOUD, not a quiet skip: `hack/ci.sh --integration` IS the darwin/root/cgo
		// tier, so the canary guarding the whole privilege premise would otherwise
		// silently skip in the only harness that ever runs it.
		t.Skipf("PRIVILEGE PREMISE UNVERIFIED (run non-root): euid is 0, so BOTH binds would trivially succeed and prove nothing")
	}

	t.Run("wildcard privileged bind SUCCEEDS as an ordinary uid", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "0.0.0.0:"+strconv.Itoa(canaryPort))
		if err != nil {
			// A stray process on 1023 must not read as "XNU changed": that is an
			// environment fact, not a premise failure.
			if errors.Is(err, unix.EADDRINUSE) {
				t.Skipf("port %d is already in use by another process; the premise is untested here, not disproven (lsof -nP -iTCP:%d -sTCP:LISTEN)", canaryPort, canaryPort)
			}
			t.Fatalf("PREMISE BROKEN: binding 0.0.0.0:%d as euid %d failed with %v. "+
				"k3sm's LoadBalancer/ingress listeners rely on an unprivileged wildcard bind at any port; "+
				"if macOS now requires privilege here, every <1024 LoadBalancer port and both ingress listeners are unbindable.",
				canaryPort, os.Geteuid(), err)
		}
		_ = ln.Close()
	})

	t.Run("specific-address privileged bind returns EACCES", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(canaryPort))
		if err == nil {
			_ = ln.Close()
			t.Fatalf("PREMISE CHANGED: binding 127.0.0.1:%d as euid %d SUCCEEDED. "+
				"macOS appears to have relaxed the specific-address privileged-bind rule, which retires the reason "+
				"k3sm binds the wildcard instead of the node address; re-derive the design rather than leaving this test green.",
				canaryPort, os.Geteuid())
		}
		if errors.Is(err, unix.EADDRINUSE) {
			t.Skipf("port %d is already in use by another process; the premise is untested here, not disproven", canaryPort)
		}
		if !errors.Is(err, unix.EACCES) {
			t.Fatalf("binding 127.0.0.1:%d failed with %v, want EACCES: the errno is the assertion, not the failure", canaryPort, err)
		}
	})
}
