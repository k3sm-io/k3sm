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

import "k3sm.io/runtimed/pkg/sandbox"

// RuntimePosture returns the directories of the Seatbelt posture the runtime
// NewRuntimed builds from cfg renders every Pod profile from: the pod root
// (WorkDir, runtimed's default when cfg.Root is empty), the data root and the
// state dir as the denies are written from them (dataRootOf: the runtime
// root's spelling for a firmlink-spelled data root, a symlinked server or agent
// state dir resolved), the status record dir (statusRecordDirOf) and the
// container-log root (podLogsDirOf). The error is the one NewRuntimed would
// refuse the same cfg with. The fields runtimed fills from its own state are
// left empty. A caller that renders a Pod profile outside the runtime reads
// these, so it and the runtime read one derivation.
func RuntimePosture(cfg RuntimedConfig) (sandbox.Posture, error) {
	statusRecordDir, err := statusRecordDirOf(cfg)
	if err != nil {
		return sandbox.Posture{}, err
	}
	dataRoot, stateDir, err := dataRootOf(cfg)
	if err != nil {
		return sandbox.Posture{}, err
	}
	return sandbox.Posture{
		WorkDir:         runtimeRoot(cfg.Root),
		DataRoot:        dataRoot,
		StateDir:        stateDir,
		StatusRecordDir: statusRecordDir,
		PodLogsDir:      podLogsDirOf(cfg),
	}, nil
}
