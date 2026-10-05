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

package pairing

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

func openBeacon(pin string) netv1alpha1.Beacon {
	return netv1alpha1.Beacon{Version: netv1alpha1.BeaconVersion, ClusterPin: pin, NodeName: "server", JoinPort: 9345, PairingOpen: true}
}

// TestJoinerUnarmedIsInert pins that an unarmed joiner neither reads a beacon nor
// asks any server anything.
func TestJoinerUnarmedIsInert(t *testing.T) {
	beacons := make(chan Heard) // unbuffered: a read would block the sender below
	asked := false
	j := Joiner{Arm: Arm{}, NodeName: "new-mac", Pair: func(context.Context, Heard, string) (netv1alpha1.PairResponse, error) {
		asked = true
		return netv1alpha1.PairResponse{}, nil
	}}
	_, err := j.Run(context.Background(), beacons)
	if !errors.Is(err, ErrNotArmed) {
		t.Fatalf("Run = %v, want ErrNotArmed", err)
	}
	if asked {
		t.Fatal("an unarmed joiner asked a server for a token")
	}
}

// TestJoinerIgnoresAPinMismatch pins that, armed with --cluster, the joiner skips
// a beacon carrying another pin and pairs with the one carrying its own.
func TestJoinerIgnoresAPinMismatch(t *testing.T) {
	mine, other := testPin, strings.Repeat("a", 64)
	beacons := make(chan Heard, 2)
	beacons <- Heard{Beacon: openBeacon(other), Src: netip.MustParseAddr("fe80::9"), Iface: "bridge0"}
	beacons <- Heard{Beacon: openBeacon(mine), Src: netip.MustParseAddr("fe80::1"), Iface: "bridge0"}
	var asked []string
	j := Joiner{
		Arm:      Arm{Until: time.Now().Add(time.Minute), Cluster: mine},
		NodeName: "new-mac",
		Pair: func(_ context.Context, h Heard, node string) (netv1alpha1.PairResponse, error) {
			asked = append(asked, h.Beacon.ClusterPin)
			if node != "new-mac" {
				t.Errorf("asked for node %q", node)
			}
			return netv1alpha1.PairResponse{Version: netv1alpha1.PairVersion, Token: "K10" + mine + "::pair-1:s", ServerLinkIP: "169.254.0.1"}, nil
		},
	}
	res, err := j.Run(context.Background(), beacons)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(asked) != 1 || asked[0] != mine {
		t.Fatalf("asked servers with pins %v, want only the matching one", asked)
	}
	if res.Server != "fe80::1%bridge0" || res.Iface != "bridge0" || res.ServerLinkIP != "169.254.0.1" || res.ClusterPin != mine {
		t.Fatalf("result = %+v", res)
	}
}

// TestJoinerStopsWhenTheArmingExpires pins the bounded arming window.
func TestJoinerStopsWhenTheArmingExpires(t *testing.T) {
	j := Joiner{Arm: Arm{Until: time.Now().Add(50 * time.Millisecond)}, Pair: func(context.Context, Heard, string) (netv1alpha1.PairResponse, error) {
		t.Fatal("asked a server with no beacon")
		return netv1alpha1.PairResponse{}, nil
	}}
	start := time.Now()
	_, err := j.Run(context.Background(), make(chan Heard))
	if !errors.Is(err, ErrNotArmed) {
		t.Fatalf("Run = %v, want ErrNotArmed after expiry", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the joiner outlived its arming window")
	}
}

// TestJoinerKeepsListeningAfterARefusal pins that a server that refuses (a closed
// window raced, a rate limit) does not end the arming: the next beacon is asked.
func TestJoinerKeepsListeningAfterARefusal(t *testing.T) {
	beacons := make(chan Heard, 2)
	beacons <- Heard{Beacon: openBeacon(testPin), Src: netip.MustParseAddr("fe80::1"), Iface: "en2"}
	beacons <- Heard{Beacon: openBeacon(testPin), Src: netip.MustParseAddr("fe80::1"), Iface: "en2"}
	calls := 0
	j := Joiner{Arm: Arm{Until: time.Now().Add(time.Minute)}, NodeName: "n", Pair: func(context.Context, Heard, string) (netv1alpha1.PairResponse, error) {
		calls++
		if calls == 1 {
			return netv1alpha1.PairResponse{}, errors.New("pair request refused (429): rate-limited")
		}
		return netv1alpha1.PairResponse{Token: "t"}, nil
	}}
	if _, err := j.Run(context.Background(), beacons); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestArmRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), ArmFile)
	if _, ok, err := LoadArm(path); err != nil || ok {
		t.Fatalf("LoadArm on no file = ok %v err %v, want unarmed", ok, err)
	}
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	if _, err := WriteArm(path, now, 10*time.Minute, "  "+strings.ToUpper(testPin)+" "); err != nil {
		t.Fatal(err)
	}
	a, ok, err := LoadArm(path)
	if err != nil || !ok {
		t.Fatalf("LoadArm = ok %v err %v", ok, err)
	}
	if !a.Armed(now.Add(9*time.Minute)) || a.Armed(now.Add(10*time.Minute)) {
		t.Fatalf("arm window wrong: %+v", a)
	}
	if a.Cluster != testPin {
		t.Fatalf("cluster pin stored as %q, want it normalised", a.Cluster)
	}
	if err := Disarm(path); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := LoadArm(path); ok {
		t.Fatal("still armed after Disarm")
	}
}

func TestHeardPairAddressUsesTheArrivalInterface(t *testing.T) {
	h := Heard{Beacon: openBeacon(testPin), Src: netip.MustParseAddr("fe80::1"), Iface: "bridge0"}
	if got := h.PairAddress(); got != "[fe80::1%bridge0]:9345" {
		t.Fatalf("PairAddress = %q", got)
	}
}
