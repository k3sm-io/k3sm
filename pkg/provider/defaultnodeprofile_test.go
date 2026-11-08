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

package provider

import (
	"bytes"
	"context"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/runtimed/pkg/sandbox"
)

// updateGolden regenerates the testdata goldens of this package. A changed
// default-node profile refuses every running pod's re-attach as drift on
// upgrade, so regenerating it belongs only in a reviewed commit that says why.
var updateGolden = flag.Bool("update", false, "rewrite the testdata goldens from the current code")

// defaultNodeProfileGolden is the full Seatbelt profile of one pod on a default
// k3sm server.
const defaultNodeProfileGolden = "testdata/default-node-profile.sb.golden"

// TestDefaultNodeProfileGolden pins, byte for byte, the sandbox profile a pod
// gets on a `k3sm server` with the default work dir in its default posture (the
// _k3sm service user, home /var/lib/k3sm), as an install starts it. A change to
// it refuses every running pod's re-attach as profile drift on upgrade, so the
// golden is the review artifact for any change that renders a new line on the
// most common node.
//
// The config is the one cmd/k3sm's runtimedConfig builds from the server's
// defaults. It goes through the provider's own path: statusRecordDirOf and
// dataRootOf validate the deny directories, runtimedConfigOf builds the
// runtime.Config, and buildBox translates the pod and stamps the node's denies
// and shim grants. runtimed's compileProfile is unexported, so the step from
// runtime.Config to sandbox.Posture is mirrored here field for field; it copies
// those fields verbatim.
//
// It also asserts the invariant the default node depends on: the data root
// and state dir denies add nothing to the profile of a node whose data root is
// its pod root and whose work dir has the default leaf.
func TestDefaultNodeProfileGolden(t *testing.T) {
	workDir := executor.DefaultWorkDir
	dataRoot := executor.RuntimeRoot(workDir)
	cfg := RuntimedConfig{
		NodeName:              "k3sm-golden",
		NodeIP:                "127.0.0.1",
		Root:                  dataRoot,
		StatusRecordDir:       status.Dir(workDir),
		DataRoot:              dataRoot,
		StateDir:              workDir,
		DyldShim:              filepath.Join(install.DefaultInstallDir, install.DNSShimName),
		PathShim:              filepath.Join(install.DefaultInstallDir, install.PathShimName),
		ShadowBinDir:          filepath.Join(install.DefaultInstallDir, "shadow"),
		ResolverVIP:           dns.DefaultDNSVIP,
		ClusterDomain:         dns.DefaultClusterDomain,
		PodLogsDir:            sandbox.DefaultPodLogsDir,
		APIServerVIP:          "10.43.0.1",
		DeniedUnixSocketPaths: []string{netd.DefaultSocketPath},
		DeniedLocalPorts:      []int{executor.DefaultKinePort},
	}

	// dataRootOf resolves the default work dir on disk when it exists, so a host
	// where it is a symlink renders a different, still valid, state dir deny. The
	// golden pins the host where it is absent or a plain directory.
	if resolved, err := filepath.EvalSymlinks(workDir); err == nil && resolved != workDir &&
		filepath.Join("/private", workDir) != resolved {
		t.Skipf("%s resolves to %s on this host; the golden pins an unlinked work dir", workDir, resolved)
	}

	statusDir, err := statusRecordDirOf(cfg)
	if err != nil {
		t.Fatalf("statusRecordDirOf: %v", err)
	}
	deniedRoot, stateDir, err := dataRootOf(cfg)
	if err != nil {
		t.Fatalf("dataRootOf: %v", err)
	}
	rc := runtimedConfigOf(cfg, slog.New(slog.DiscardHandler), statusDir, deniedRoot, stateDir)
	posture := sandbox.Posture{
		WorkDir: rc.Root,
		// runtimed's daemonHome: the _k3sm service user's home, which holds the
		// work dir.
		Home:            install.DefaultDataRoot,
		ResolverVIP:     rc.ResolverVIP,
		APIServerVIP:    rc.APIServerVIP,
		PodLogsDir:      rc.PodLogsDir,
		StatusRecordDir: rc.StatusRecordDir,
		DataRoot:        rc.DataRoot,
		StateDir:        rc.StateDir,
		ShadowBinDir:    rc.ShadowBinDir,
	}

	// buildBox creates the pod's log tree under PodLogsDir, so the box is
	// translated with a temp log root. The log root is not in the box's
	// SandboxProfile; the profile's log deny comes from the posture above.
	boxCfg := cfg
	boxCfg.PodLogsDir = t.TempDir()
	const podIP = "10.42.0.5"
	r := newRuntimedWith(newFakeRuntimeServer(), boxCfg, nil, nil)
	box, err := r.buildBox(context.Background(), runtimedPod("default", "web"), podIP)
	if err != nil {
		t.Fatalf("buildBox: %v", err)
	}
	render := func(posture sandbox.Posture) []byte {
		t.Helper()
		// compileProfile narrows the data volume to the pod's rootfs.
		sp := proto.Clone(box.GetSandboxProfile()).(*runtimev1.SandboxProfile)
		sp.DataVolumePath = filepath.Join(sp.GetDataVolumePath(), "rootfs")
		out, err := sandbox.Generate(sp, sandbox.GenerateOptions{
			Posture: posture,
			PodIP:   podIP,
			PodUID:  box.GetPodId(),
		})
		if err != nil {
			t.Fatalf("sandbox.Generate: %v", err)
		}
		return []byte(out)
	}
	got := render(posture)

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(defaultNodeProfileGolden), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(defaultNodeProfileGolden, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(defaultNodeProfileGolden)
	if err != nil {
		t.Fatalf("read golden (regenerate with -update only in a reviewed commit): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the default node's pod profile differs from %s; every running pod would be recreated on upgrade.\n--- got ---\n%s\n--- want ---\n%s", defaultNodeProfileGolden, got, want)
	}

	bare := posture
	bare.StatusRecordDir, bare.DataRoot, bare.StateDir = "", "", ""
	if without := render(bare); !bytes.Equal(got, without) {
		t.Errorf("the status, data root or state dir deny added a line on a default node:\n--- with ---\n%s\n--- without ---\n%s", got, without)
	}
}
