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
	"net/netip"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/hostnet"
)

// recordingAliasOps builds meshAliasOps whose legs are observable: present
// answers from a fixed verdict and plumb records the addresses it was asked for.
func recordingAliasOps(have bool, presentErr, plumbErr error, plumbable bool) (meshAliasOps, *[]netip.Addr) {
	var got []netip.Addr
	ops := meshAliasOps{
		present: func(netip.Addr) (bool, error) { return have, presentErr },
	}
	if plumbable {
		ops.plumb = func(_ context.Context, ip netip.Addr) error {
			got = append(got, ip)
			return plumbErr
		}
	}
	return ops, &got
}

// TestEnsureMeshIPAliasDecision pins the whole decision the apiserver's bind
// depends on.
//
// The defect: the apiserver is handed --mesh-ip as its BindAddress at step 1 of
// bring-up, while the only code that ever plumbed that address was mesh.Start at
// step 4b. The first real `--mesh-ip 100.64.0.1` boot died with `listen tcp
// 100.64.0.1:6444: bind: can't assign requested address`, and the operator had to
// run `ifconfig lo0 alias 100.64.0.1/32` by hand to get past it. The M14.2 lab
// tier booted --mesh-ip 127.0.0.1, an address every host already answers on, so no
// gate could see it.
//
// The legs are injected rather than exercised: this must be provable without root
// and without a live k3sm-netd, and an environment-sensed "is 100.64.0.1 present?"
// would pass or fail depending on whether the lab Mac still carries the hand-run
// alias.
func TestEnsureMeshIPAliasDecision(t *testing.T) {
	t.Parallel()
	boom := errors.New("ifconfig: permission denied")
	for _, tc := range []struct {
		name       string
		meshIP     string
		have       bool
		presentErr error
		plumbErr   error
		plumbable  bool
		wantPlumbs int
		wantErr    string
	}{
		{
			name: "no mesh touches nothing at all", meshIP: "", plumbable: true,
		},
		{
			name:   "an absent mesh IP is plumbed before the control plane binds it",
			meshIP: "100.64.0.1", plumbable: true, wantPlumbs: 1,
		},
		{
			name:   "an address the host already answers on is left alone",
			meshIP: "127.0.0.1", have: true, plumbable: true,
		},
		{
			name:   "no privileged datapath fails fast and says what to run",
			meshIP: "100.64.0.1", plumbable: false,
			wantErr: "ifconfig lo0 alias 100.64.0.1/32",
		},
		{
			name:   "a failing plumb fails fast and says what to run",
			meshIP: "100.64.0.1", plumbable: true, plumbErr: boom, wantPlumbs: 1,
			wantErr: "ifconfig lo0 alias 100.64.0.1/32",
		},
		{
			name:   "a mesh IP that is not an address is rejected",
			meshIP: "not-an-ip", plumbable: true,
			wantErr: "not an IP address",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ops, plumbed := recordingAliasOps(tc.have, tc.presentErr, tc.plumbErr, tc.plumbable)
			err := ensureMeshIPAliasWith(context.Background(), tc.meshIP, ops, nil)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("ensureMeshIPAliasWith(%q) = %v, want nil", tc.meshIP, err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("ensureMeshIPAliasWith(%q) = nil, want an error mentioning %q", tc.meshIP, tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("ensureMeshIPAliasWith(%q) = %q, want it to name %q so the operator knows what to run",
					tc.meshIP, err, tc.wantErr)
			}
			if got := len(*plumbed); got != tc.wantPlumbs {
				t.Fatalf("plumbed %d addresses %v, want %d", got, *plumbed, tc.wantPlumbs)
			}
			if tc.wantPlumbs == 1 && (*plumbed)[0].String() != tc.meshIP {
				t.Errorf("plumbed %s, want the mesh IP %s", (*plumbed)[0], tc.meshIP)
			}
		})
	}
}

// TestHostAliasOpsMirrorsTheNetworkBackendSplit pins that the ensure reaches lo0
// through the SAME split every other privileged lo0 operation in this binary uses
// — the root helper when unprivileged, the direct ifconfig-equivalent as root —
// rather than acquiring a second, mode-blind idiom that would bypass k3sm-netd.
//
// `--network none` is the one mode with no privileged path; its plumb must be nil
// so the ensure reports "there is no datapath here, run this yourself" instead of
// shelling out an ifconfig that a `_k3sm` process cannot execute.
func TestHostAliasOpsMirrorsTheNetworkBackendSplit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		network   string
		euid      int
		plumbable bool
	}{
		{"unprivileged auto routes through the k3sm-netd helper", hostnet.NetworkAuto, 501, true},
		{"helper routes through the k3sm-netd helper", hostnet.NetworkHelper, 0, true},
		{"root direct plumbs lo0 itself", hostnet.NetworkDirect, 0, true},
		{"none has no privileged path to lo0", hostnet.NetworkNone, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mode, err := hostnet.ResolveFor(tc.network, tc.euid)
			if err != nil {
				t.Fatalf("hostnet.ResolveFor(%q, %d): %v", tc.network, tc.euid, err)
			}
			ops := hostAliasOps(mode)
			if ops.present == nil {
				t.Error("hostAliasOps left present nil — every mode must be able to short-circuit on an address the host already answers on")
			}
			if got := ops.plumb != nil; got != tc.plumbable {
				t.Errorf("hostAliasOps(--network %s).plumb != nil = %v, want %v", tc.network, got, tc.plumbable)
			}
		})
	}
}

// TestAddrIsLocalSeesLoopback is the one leg that touches the real host, and it
// asserts only what every macOS host guarantees: 127.0.0.1 is assigned, and an
// address from the documentation range (RFC 5737 TEST-NET-1) is not. It is what
// makes the short-circuit above trustworthy — a present() that answered false for
// everything would re-plumb loopback on every single-host boot.
func TestAddrIsLocalSeesLoopback(t *testing.T) {
	t.Parallel()
	if have, err := addrIsLocal(netip.MustParseAddr("127.0.0.1")); err != nil || !have {
		t.Errorf("addrIsLocal(127.0.0.1) = %v, %v; want true, nil", have, err)
	}
	if have, err := addrIsLocal(netip.MustParseAddr("192.0.2.1")); err != nil || have {
		t.Errorf("addrIsLocal(192.0.2.1) = %v, %v; want false, nil (TEST-NET-1 is not a host address)", have, err)
	}
}
