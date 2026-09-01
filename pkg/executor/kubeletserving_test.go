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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
)

// TestApiserverKubeletCAFlagIffConfigured pins the DIVERGENCE B213 is most likely
// to perturb, in BOTH directions and in one place: --kubelet-certificate-authority
// is emitted exactly when Config.KubeletCAFile is set, and is absent otherwise.
//
// Both halves are load-bearing, and each is a different product posture. Set is the
// multi-node contract: it is what makes a node's serving cert VERIFIED, and B213 is
// the story of nodes that could not satisfy it. Absent is the single-node/dev
// contract (DESIGN §5c): the flag's absence is what makes certs.SelfSignedServing
// correct there — emit it single-node and every dev cluster's logs/exec breaks, the
// mirror image of the defect being fixed.
func TestApiserverKubeletCAFlagIffConfigured(t *testing.T) {
	t.Parallel()
	const flag = "--kubelet-certificate-authority"
	cases := []struct {
		name string
		cfg  Config
		want string // "" == the flag must be absent
	}{
		{
			name: "single-node dev: absent",
			cfg:  Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"},
		},
		{
			name: "mesh: names the cluster CA",
			cfg: Config{
				WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444,
				NodeIP: "100.64.0.1", BindAddress: "100.64.0.1",
				ClientCAFile:  certs.SigningCACertPath("/wd"),
				KubeletCAFile: certs.ClusterCACertPath("/wd"),
			},
			want: certs.ClusterCACertPath("/wd"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := apiServerArgs(tc.cfg)
			got := flagValue(args, flag)
			if tc.want == "" {
				if strings.Contains(strings.Join(args, " "), flag) {
					t.Fatalf("%s must be ABSENT in this posture (the node self-signs and nothing would verify it), args=%v", flag, args)
				}
				return
			}
			if got != tc.want {
				t.Errorf("%s = %q, want %q", flag, got, tc.want)
			}
		})
	}
}

// TestRotationReportsTheKubeletServingPair keeps the rotation report COMPLETE. The
// control-plane node's kubelet serving pair is re-minted from the cluster CA on
// every boot of a --mesh-ip server, so it belongs in Reissued: an artifact that is
// re-issued but absent from the report breaks the report's stated invariant just as
// badly as one that is listed but never re-issued.
//
// The pair is deliberately held in memory (no key file), so it is reported with a
// non-filesystem locator and its presence is read off the mesh posture's on-disk
// witness — which is why this test drives two real work dirs rather than asserting a
// constant.
func TestRotationReportsTheKubeletServingPair(t *testing.T) {
	t.Parallel()
	find := func(t *testing.T, wd string) RotationArtifact {
		t.Helper()
		for _, a := range reissuedArtifacts(wd) {
			if strings.Contains(a.Detail, "kubelet serving cert+key") {
				return a
			}
		}
		t.Fatalf("reissuedArtifacts does not report the node's kubelet serving pair, which every --mesh-ip boot re-mints")
		return RotationArtifact{}
	}

	t.Run("mesh work dir: reported present", func(t *testing.T) {
		wd := t.TempDir()
		if err := os.MkdirAll(filepath.Dir(certs.APIServerServingCertPath(wd)), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(certs.APIServerServingCertPath(wd), []byte("witness"), 0o644); err != nil {
			t.Fatalf("write witness: %v", err)
		}
		a := find(t, wd)
		if !a.Present {
			t.Error("a mesh work dir must report the kubelet serving pair as re-issued")
		}
		if strings.HasPrefix(a.Path, "/") {
			t.Errorf("Path = %q — the pair is held in memory and must not claim a file an operator could go read", a.Path)
		}
	})

	t.Run("single-node work dir: reported absent", func(t *testing.T) {
		a := find(t, t.TempDir())
		if a.Present {
			t.Error("a single-node work dir mints no cluster-CA kubelet serving pair, so reporting it present would overstate the rotation")
		}
	})
}
