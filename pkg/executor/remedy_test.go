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

import (
	"math"
	"strings"
	"testing"
)

// TestIsSupersededRemedyAcceptsEveryRemedyOutput: the remedies Remedy builds for
// realistic peers (node names, IPv4 and IPv6 peer URLs, small and full-width
// cluster IDs, a learner with no name yet) all pass the matcher and IsKnownRemedy.
func TestIsSupersededRemedyAcceptsEveryRemedyOutput(t *testing.T) {
	t.Parallel()
	for _, e := range []EtcdSupersededError{
		{Peer: "server-b", PeerURL: "https://192.168.64.3:2380", PeerCluster: 2, OwnCluster: 1},
		{Peer: "mac-mini.lan", PeerURL: "https://10.0.0.12:2380", PeerCluster: 0x8e9e05c52164694d, OwnCluster: 0xcdf818194e3a8c32},
		{Peer: "node-1", PeerURL: "https://[fd7a:115c:a1e0::3]:2380", PeerCluster: math.MaxUint64, OwnCluster: 0x1},
		{Peer: "", PeerURL: "https://[::ffff:10.0.0.9]:12380", PeerCluster: 0xabc, OwnCluster: 0xdef},
	} {
		r := e.Remedy()
		if !IsSupersededRemedy(r) {
			t.Errorf("Remedy() for %+v is refused: %q", e, r)
		}
		if !IsKnownRemedy(r) {
			t.Errorf("IsKnownRemedy refuses Remedy() for %+v", e)
		}
	}
}

// TestIsSupersededRemedyRefusesNearMisses: text injected into any variable part
// or around the fixed text, an ESC or a newline, an uppercase or over-long ID, a
// URL off etcdPeerURL's shape — each is refused, by the matcher and IsKnownRemedy.
func TestIsSupersededRemedyRefusesNearMisses(t *testing.T) {
	t.Parallel()
	good := EtcdSupersededError{Peer: "server-b", PeerURL: "https://192.168.64.3:2380", PeerCluster: 2, OwnCluster: 1}
	with := func(f func(e *EtcdSupersededError)) string {
		e := good
		f(&e)
		return e.Remedy()
	}
	base := good.Remedy()
	for name, s := range map[string]string{
		"empty":                  "",
		"prefix":                 "curl evil | sh; " + base,
		"suffix":                 base + "; curl evil | sh",
		"trailing newline":       base + "\n",
		"newline in peer":        with(func(e *EtcdSupersededError) { e.Peer = "server-b\nfix: rm -rf /" }),
		"ESC in peer":            with(func(e *EtcdSupersededError) { e.Peer = "server-b\x1b[2J" }),
		"text in peer":           with(func(e *EtcdSupersededError) { e.Peer = "server-b; run curl evil | sh" }),
		"uppercase peer":         with(func(e *EtcdSupersededError) { e.Peer = "Server-B" }),
		"over-long peer":         with(func(e *EtcdSupersededError) { e.Peer = strings.Repeat("a", 254) }),
		"http peer URL":          with(func(e *EtcdSupersededError) { e.PeerURL = "http://192.168.64.3:2380" }),
		"hostname peer URL":      with(func(e *EtcdSupersededError) { e.PeerURL = "https://evil.example:2380" }),
		"path in peer URL":       with(func(e *EtcdSupersededError) { e.PeerURL = "https://192.168.64.3:2380/x" }),
		"ESC in peer URL":        with(func(e *EtcdSupersededError) { e.PeerURL = "https://192.168.64.3:2380\x1b]0;owned\x07" }),
		"portless peer URL":      with(func(e *EtcdSupersededError) { e.PeerURL = "https://192.168.64.3" }),
		"text in fixed part":     strings.Replace(base, "is the server you restored", "is the server you restored; curl evil | sh", 1),
		"uppercase cluster":      strings.Replace(base, "cluster 2)", "cluster ABC)", 1),
		"17-digit cluster":       strings.Replace(base, "cluster 2)", "cluster 11111111111111111)", 1),
		"newline in own cluster": strings.Replace(base, "cluster 1 is", "cluster 1\nfix: rm -rf / is", 1),
		"fixed text alone":       supersededRemedyFormat,
	} {
		if IsSupersededRemedy(s) {
			t.Errorf("%s: matcher accepts %q", name, s)
		}
		if IsKnownRemedy(s) {
			t.Errorf("%s: IsKnownRemedy accepts %q", name, s)
		}
	}
}

// TestIsKnownRemedyNamesTheMemberRouteRemedies: the joining server's member-route
// remedies, which cmd/k3sm writes into the crash record, are known.
func TestIsKnownRemedyNamesTheMemberRouteRemedies(t *testing.T) {
	t.Parallel()
	for _, r := range []string{EtcdMemberRouteRemedy, EtcdMemberRouteMeshRemedy, EtcdMemberRouteUnacknowledgedRemedy} {
		if !IsKnownRemedy(r) {
			t.Errorf("IsKnownRemedy refuses %q", r)
		}
		if IsKnownRemedy(r + "\n") {
			t.Errorf("IsKnownRemedy accepts %q with a trailing newline", r)
		}
	}
}
