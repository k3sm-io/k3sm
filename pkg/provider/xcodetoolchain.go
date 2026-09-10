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
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// lookupDeveloperDir returns this node's active developer directory — the path
// `xcode-select -p` prints (typically /Applications/Xcode.app/Contents/Developer,
// or the Command Line Tools directory when no full Xcode is selected). It is the
// package's one seam onto that command: production keeps this value, tests
// replace it, and no unit test ever runs the real command.
//
// A var, not a func, because the answer is a property of the HOST the provider
// happens to run on: a test asserting what the provider stamps must be able to
// state that host fact rather than inherit whichever toolchain the developer's
// Mac has installed.
//
// The output is trimmed — `xcode-select -p` terminates its path with a newline,
// and a path carrying one would be stamped into a Seatbelt profile as a literal
// that matches nothing.
var lookupDeveloperDir = func() (string, error) {
	out, err := exec.Command("/usr/bin/xcode-select", "-p").Output()
	if err != nil {
		return "", fmt.Errorf("xcode-select -p: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", fmt.Errorf("xcode-select -p: empty developer directory")
	}
	return dir, nil
}

// resolveDeveloperDir reads the node's developer directory ONCE, at provider
// construction, and returns "" when the node has none.
//
// Once, and at construction, for two reasons. It is a node fact, not a pod fact:
// re-running a subprocess per CreatePod would put an exec on the pod-admission
// path to re-learn something that cannot change while the daemon runs. And a
// node with no toolchain must say so at startup — an empty
// SandboxProfile.xcode_toolchain_dir grants nothing, so a pod carrying the
// annotation on such a node fails at build time with no explanation anywhere
// unless the daemon logged the absence when it looked.
//
// A failure is not an error the caller handles: a Mac without Xcode or the
// Command Line Tools is a perfectly good k3sm node for every workload that is
// not a build, and refusing to start there would be a far larger claim than the
// annotation makes. It degrades to the empty grant and one WARN line.
func resolveDeveloperDir(log *slog.Logger) string {
	dir, err := lookupDeveloperDir()
	if err != nil {
		log.Warn("node has no developer toolchain; the annotation grants nothing here",
			"annotation", runtimev1.AnnotationXcodeToolchain, "err", err)
		return ""
	}
	return dir
}
