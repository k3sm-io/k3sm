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

package podlogs

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Ported from k8s.io/kubernetes@v1.36.2 pkg/kubelet/kuberuntime/helpers.go and
// legacy.go (Apache-2.0). The path shapes are a compatibility surface, not an
// implementation detail: every log shipper, runbook and support answer in the
// ecosystem names /var/log/pods/<ns>_<pod>_<uid>/<container>/<n>.log and the
// /var/log/containers symlink, so k3sm spells them identically.

const (
	// DefaultPodLogsDir is the kubelet's own default PodLogsDir
	// (pkg/kubelet/apis/config/v1beta1/defaults.go DefaultPodLogsDir). k3sm
	// ships the same default, so a Mac node's log tree is where a k8s operator
	// already looks.
	DefaultPodLogsDir = "/var/log/pods"

	// ContainerLogsDir is the flat directory of per-container symlinks into the
	// pod log tree (upstream's legacyContainerLogsDir). It exists for log
	// shippers, which glob one directory instead of walking the pod tree.
	ContainerLogsDir = "/var/log/containers"

	// logSuffix is the symlink's extension (upstream legacyLogSuffix).
	logSuffix = "log"

	// maxFileNameLen is upstream's ext4MaxFileNameLen. macOS APFS allows 255
	// UTF-8 bytes too, so the truncation point is the same 255 minus ".log"
	// (251 usable characters) and a symlink name generated here is byte-for-byte
	// what a kubelet would generate.
	maxFileNameLen = 255

	// logPathDelimiter joins namespace, pod name and uid in a pod log directory
	// name (upstream logPathDelimiter).
	logPathDelimiter = "_"
)

// BuildPodLogsDirectory returns the absolute log directory of one pod:
// <podLogsDir>/<namespace>_<name>_<uid>.
func BuildPodLogsDirectory(podLogsDir, podNamespace, podName, podUID string) string {
	return filepath.Join(podLogsDir, strings.Join([]string{podNamespace, podName, podUID}, logPathDelimiter))
}

// BuildContainerLogsDirectory returns the absolute log directory of one container
// inside a pod: <podLogsDir>/<namespace>_<name>_<uid>/<container>. The runtime
// writes <restartCount>.log inside it.
func BuildContainerLogsDirectory(podLogsDir, podNamespace, podName, podUID, containerName string) string {
	return filepath.Join(BuildPodLogsDirectory(podLogsDir, podNamespace, podName, podUID), containerName)
}

// BuildContainerLogsPath returns a container instance's log file path:
// <podLogsDir>/<namespace>_<name>_<uid>/<container>/<restartCount>.log.
func BuildContainerLogsPath(podLogsDir, podNamespace, podName, podUID, containerName string, restartCount int32) string {
	return filepath.Join(
		BuildContainerLogsDirectory(podLogsDir, podNamespace, podName, podUID, containerName),
		fmt.Sprintf("%d.log", restartCount),
	)
}

// LogSymlink returns the flat /var/log/containers symlink path for one container
// instance: <containerLogsDir>/<pod>_<ns>_<container>-<containerID>.log,
// truncated to maxFileNameLen bytes INCLUDING the suffix, exactly as upstream's
// logSymlink does.
//
// The truncation is applied to the name WITHOUT the suffix and then the suffix is
// appended, so an over-long name still ends in ".log" and a shipper globbing
// "*.log" still matches it — the property that makes the truncation safe.
func LogSymlink(containerLogsDir, podName, podNamespace, containerName, containerID string) string {
	suffix := "." + logSuffix
	logPath := fmt.Sprintf("%s_%s_%s-%s", podName, podNamespace, containerName, containerID)
	if len(logPath) > maxFileNameLen-len(suffix) {
		logPath = logPath[:maxFileNameLen-len(suffix)]
	}
	return filepath.Join(containerLogsDir, logPath+suffix)
}

// ParsePodUIDFromLogsDirectory returns the pod UID encoded in a pod log directory
// NAME (not a path): the last delimiter-separated field of
// "<namespace>_<name>_<uid>". Upstream keeps the same "last field wins" rule so a
// pod name containing the delimiter still yields the right uid.
func ParsePodUIDFromLogsDirectory(name string) string {
	parts := strings.Split(name, logPathDelimiter)
	return parts[len(parts)-1]
}

// ContainerIDFromLogSymlink returns the container ID encoded in a
// /var/log/containers symlink NAME, or an error when the name is not one this
// node would have written. It is upstream's getContainerIDFromLegacyLogSymlink,
// including its six-character floor: a shorter trailing field is a coincidence,
// not an ID, and deleting a file on that evidence would be deleting somebody
// else's.
func ContainerIDFromLogSymlink(symlink string) (string, error) {
	base := filepath.Base(symlink)
	parts := strings.Split(base, "-")
	if len(parts) < 2 {
		return "", fmt.Errorf("unable to find separator in %q", symlink)
	}
	withSuffix := parts[len(parts)-1]
	suffix := "." + logSuffix
	if !strings.HasSuffix(withSuffix, suffix) {
		return "", fmt.Errorf("%q doesn't end with %q", symlink, suffix)
	}
	id := strings.TrimSuffix(withSuffix, suffix)
	if len(id) < 6 {
		return "", fmt.Errorf("container Id %q is too short", id)
	}
	return id, nil
}
