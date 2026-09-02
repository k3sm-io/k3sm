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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// The two address ROLES this file pins: the control plane's mesh IP (the ONLY
// address its apiserver binds under `--mesh-ip`) and the underlay address the worker
// joined over. The defect was that the worker targeted the latter. The underlay
// literal is RFC 5737 TEST-NET-3 documentation space — the property under test is
// "not the mesh IP", which no real address is needed to express.
const (
	labServerMeshIP   = "100.64.0.1"
	labServerUnderlay = "203.0.113.50"
)

// TestWorkerAPIServerURLTargetsTheServerMesh pins the worker-side apiserver
// derivation. A mesh server binds its apiserver on the mesh IP alone, so a worker
// that builds the URL from its `--server` (an UNDERLAY address by construction —
// the join has to reach <host>:9345 before any mesh exists) dials a port nothing
// listens on: connection refused, no VK registration, a 5m timeout. That is the
// exact failure observed live, and the first subtest is red without the fix.
func TestWorkerAPIServerURLTargetsTheServerMesh(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		res        *bootstrap.JoinResult
		serverHost string
		apiPort    int
		want       string
	}{
		{
			// The live defect: the join advertises the mesh apiserver, so the
			// underlay --server must NOT appear in the URL.
			name:       "mesh cluster targets the advertised mesh apiserver",
			res:        &bootstrap.JoinResult{APIServers: []string{labServerMeshIP + ":6444"}, MeshIP: "100.64.1.1"},
			serverHost: labServerUnderlay,
			apiPort:    6444,
			want:       "https://" + labServerMeshIP + ":6444",
		},
		{
			// --api-port keeps its role as the port; the advertised endpoint
			// contributes only the host.
			name:       "the flag supplies the port, the advertisement the host",
			res:        &bootstrap.JoinResult{APIServers: []string{labServerMeshIP + ":6444"}},
			serverHost: labServerUnderlay,
			apiPort:    16444,
			want:       "https://" + labServerMeshIP + ":16444",
		},
		{
			name:       "no advertised endpoint falls back to --server",
			res:        &bootstrap.JoinResult{},
			serverHost: labServerUnderlay,
			apiPort:    6444,
			want:       "https://" + labServerUnderlay + ":6444",
		},
		{
			name:       "a nil join result falls back to --server",
			res:        nil,
			serverHost: "cp.lan",
			apiPort:    6444,
			want:       "https://cp.lan:6444",
		},
		{
			// A wildcard/hostless advertisement is not dialable; falling back to
			// an address that once answered beats emitting a dead URL.
			name:       "unspecified advertised hosts are skipped",
			res:        &bootstrap.JoinResult{APIServers: []string{":6444", "0.0.0.0:6444", "[::]:6444"}},
			serverHost: labServerUnderlay,
			apiPort:    6444,
			want:       "https://" + labServerUnderlay + ":6444",
		},
		{
			name:       "the first dialable advertisement wins",
			res:        &bootstrap.JoinResult{APIServers: []string{"0.0.0.0:6444", labServerMeshIP + ":6444", "100.64.2.1:6444"}},
			serverHost: labServerUnderlay,
			apiPort:    6444,
			want:       "https://" + labServerMeshIP + ":6444",
		},
		{
			name:       "an IPv6 advertised host is bracketed",
			res:        &bootstrap.JoinResult{APIServers: []string{"[fd00::1]:6444"}},
			serverHost: labServerUnderlay,
			apiPort:    6444,
			want:       "https://[fd00::1]:6444",
		},
		{
			name:       "a portless advertisement is still a host",
			res:        &bootstrap.JoinResult{APIServers: []string{labServerMeshIP}},
			serverHost: labServerUnderlay,
			apiPort:    6444,
			want:       "https://" + labServerMeshIP + ":6444",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := workerAPIServerURL(tc.res, tc.serverHost, tc.apiPort); got != tc.want {
				t.Errorf("workerAPIServerURL = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestWorkerNodeKubeconfigTargetsTheMeshAPIServer proves the derivation reaches
// the artifact that stranded the worker: the node kubeconfig every client on the
// joined node is built from. Asserting the underlay address is ABSENT is the
// point — the file is what the virtual-kubelet dialed.
func TestWorkerNodeKubeconfigTargetsTheMeshAPIServer(t *testing.T) {
	t.Parallel()

	res := &bootstrap.JoinResult{
		APIServers:        []string{labServerMeshIP + ":6444"},
		ClusterCAPEM:      []byte("ca"),
		NodeClientCertPEM: []byte("cert"),
		NodeClientKeyPEM:  []byte("key"),
	}
	path := filepath.Join(t.TempDir(), "node.kubeconfig")
	if err := writeNodeKubeconfig(path, workerAPIServerURL(res, labServerUnderlay, 6444), "worker-1", res); err != nil {
		t.Fatalf("writeNodeKubeconfig: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read kubeconfig: %v", err)
	}
	got := string(content)
	if want := `server: "https://` + labServerMeshIP + `:6444"`; !strings.Contains(got, want) {
		t.Errorf("node kubeconfig does not target the mesh apiserver (%s); got:\n%s", want, got)
	}
	if strings.Contains(got, labServerUnderlay) {
		t.Errorf("node kubeconfig still carries the underlay join address %s (refused by the mesh-bound apiserver); got:\n%s", labServerUnderlay, got)
	}
}
