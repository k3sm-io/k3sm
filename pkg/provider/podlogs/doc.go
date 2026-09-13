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

// Package podlogs is the node's half of the CRI container-log split: the READER,
// the ROTATOR, the sole DELETER, and the kubelet's /containerLogs HTTP surface.
//
// The split it implements is upstream's. A CRI runtime (here k3sm.io/runtimed)
// WRITES each container's stdout and stderr into
// <podLogsDir>/<ns>_<pod>_<uid>/<container>/<restartCount>.log in the CRI line
// format, and does nothing else with the file; the kubelet (here the k3sm
// provider, through this package) creates the directories, reads the file for
// `kubectl logs`, rotates it, prunes dead instances, and removes the pod's tree
// when the pod goes. runtimed never reads or deletes a log file; this package
// never writes one.
//
// Provenance. The behaviour below is PORTED from Kubernetes v1.36.2, which is
// also Apache-2.0, so that `kubectl logs` against a k3sm node answers exactly as
// it does against a kubelet — same options, same truncation rules, same status
// codes, same error strings. The origins, file by file:
//
//	reader.go       k8s.io/cri-client/pkg/logs/logs.go and tail.go (ReadLogs,
//	                findTailLineStartIndex, the CRI line parser, the follow loop)
//	paths.go        pkg/kubelet/kuberuntime/helpers.go (BuildPodLogsDirectory,
//	                BuildContainerLogsDirectory) and legacy.go (logSymlink)
//	logmanager.go   pkg/kubelet/logs/container_log_manager.go
//	gc.go           pkg/kubelet/kuberuntime/kuberuntime_gc.go
//	                (evictPodLogsDirectories and the dead-symlink sweep)
//	termination.go  pkg/kubelet/kuberuntime/kuberuntime_container.go
//	                (readLastStringFromContainerLogs)
//	handler.go      pkg/kubelet/server/server.go (getContainerLogs) and
//	                pkg/kubelet/kubelet_pods.go (GetKubeletContainerLogs,
//	                validateContainerLogStatus)
//
// Where upstream reaches the container runtime over CRI, this package takes a
// small consumer-side interface instead (Runtime, Backend, PodSource) so the
// provider can serve it in-process and tests can fake it.
package podlogs
