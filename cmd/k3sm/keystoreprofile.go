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
	"path/filepath"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/runtimed/pkg/sandbox"
)

// serverRuntimeDirs are the directories serverNodeOptions hands the
// server's node, as the flags give them: the pod root, the status record
// dir, the data root, the role's state dir and the container-log options.
// The node threads them through runtimedConfig into provider.NewRuntimed,
// which normalises them before runtimed renders a Pod profile from them.
func serverRuntimeDirs(opts serverOptions) nodeOptions {
	return nodeOptions{
		podRoot:   opts.podRoot,
		statusDir: status.Dir(opts.workDir),
		dataRoot:  executor.RuntimeRoot(opts.workDir),
		stateDir:  opts.workDir,
		logs:      opts.logs,
	}
}

// serverPodPosture is the node-level Seatbelt posture of the server's
// embedded runtime, the one runtimed renders every Pod profile from: the
// directories serverNodeOptions gives the node (serverRuntimeDirs), through
// runtimedConfig, normalised by the provider's own derivation
// (provider.RuntimePosture), so the keystore socket's start check
// (keystorePodProfile) and the runtime read one derivation. The error is the
// one the provider would refuse the node with. runtimed exports no way to
// ask a built runtime for its posture, so the fields runtimed fills from its
// own state (Home, WorkVolume, the VIPs, ShadowBinDir) are left out: none of
// them changes the keystore stanza, which runtimed writes from WorkDir,
// DataRoot and StateDir alone.
func serverPodPosture(opts serverOptions) (sandbox.Posture, error) {
	return provider.RuntimePosture(runtimedConfig(serverRuntimeDirs(opts), nil))
}

// keystoreProfileProbePod is the pod directory, under the posture's pods
// root, of the data volume keystorePodProfile renders for. No pod is made
// there: the generator only requires the volume to lie under the pods root.
const keystoreProfileProbePod = "profile-probe"

// keystorePodProfile renders, with runtimed's own generator
// (sandbox.Generate), the Pod profile a pod with no grants gets under
// posture. The keystore stanza is the profile's last rule whatever the
// pod's grants, so this is the profile the socket's start check reads.
func keystorePodProfile(posture sandbox.Posture) (string, error) {
	work := posture.WorkDir
	if work == "" {
		work = sandbox.DefaultWorkDir
	}
	sp := &runtimev1.SandboxProfile{DataVolumePath: filepath.Join(work, "pods", keystoreProfileProbePod, "rootfs")}
	return sandbox.Generate(sp, sandbox.GenerateOptions{Posture: posture})
}
