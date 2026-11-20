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
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/shadowset"

	"k3sm.io/k3sm/pkg/shadow"
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

// warnXcodeToolchainUngranted reports, ON THE POD, that a pod which asked for
// the node's developer toolchain did not get it — because the node has no
// developer directory selected, or because the one it has is not a directory
// applyXcodeToolchain could stamp (sandbox.ValidateXcodeToolchainDir refused it,
// a Command Line Tools root being the ordinary case).
//
// Degrade, not fail: it returns nothing and the create proceeds. That is the
// deliberate half of this design — the annotation is a request, and refusing the
// pod would make a node without Xcode unable to run a workload that merely
// prefers it. The other half is that a degrade nobody can see is indistinguishable
// from a grant that worked: post-fix the pod runs, reports healthy, and builds
// against whatever toolchain it can reach, so the only question an operator
// actually asks — "why did my build not see Xcode?" — has no answer on the pod
// unless one is put there. The node log alone cannot answer it: developerDir is
// resolved at daemon construction, which may be days before this pod existed.
//
// It reads the BOX, not developerDir, for the granted/ungranted verdict, so the
// Event follows whatever applyXcodeToolchain actually decided rather than a
// second opinion about the same node fact — the same shape preflightImagePlatform
// uses when it reads the box's platform annotation back.
//
// CREATE-ONLY by placement (CreatePod calls it; UpdatePod does not), matching the
// admission advisory's create-only scope and for the same reason: buildBox also
// runs on an in-place label/annotation update, and warning there would re-fire on
// every unrelated update of a pod whose node has not changed.
func (r *runtimedRuntime) warnXcodeToolchainUngranted(ctx context.Context, pod *corev1.Pod, box *runtimev1.PodBox) {
	if !podRequestsXcodeToolchain(pod) || box.GetSandboxProfile().GetXcodeToolchainDir() != "" {
		return
	}
	r.log.WarnContext(ctx, "pod requested the developer toolchain; this node grants none",
		"namespace", pod.Namespace, "name", pod.Name,
		"annotation", runtimev1.AnnotationXcodeToolchain, "developer_dir", r.developerDir)
	r.recorder.Event(pod, corev1.EventTypeWarning, reasonXcodeToolchainUngranted,
		msgXcodeToolchainUngranted(r.developerDir))
}

// xcodebuildCopyTimeout bounds the one codesign run diagnoseXcodebuildCopy makes.
const xcodebuildCopyTimeout = 10 * time.Second

// xcodebuildCopyProblem returns "" when this node's re-signed xcodebuild copy
// can serve a pod granted developerDir, and otherwise one sentence saying why
// it cannot. It is the package's seam onto three host facts (the shadow
// directory's contents, its manifest, and the live Xcode's code directory
// hash): production keeps this value, tests replace it, exactly as
// lookupDeveloperDir is replaced, so no unit test reads the developer's own
// Xcode.
//
// A var for the same reason lookupDeveloperDir is one: the answer is a fact of
// the host the provider runs on, and a test must be able to state it.
var xcodebuildCopyProblem = func(ctx context.Context, shadowDir, developerDir string) string {
	ctx, cancel := context.WithTimeout(ctx, xcodebuildCopyTimeout)
	defer cancel()
	return diagnoseXcodebuildCopy(shadowDir, developerDir, xcodebuildCopyHost{
		readFile: os.ReadFile,
		exists: func(p string) bool {
			fi, err := os.Stat(p)
			return err == nil && fi.Mode().IsRegular()
		},
		cdhash: func(p string) (string, error) { return shadow.CDHash(ctx, p) },
	})
}

// xcodebuildCopyHost is what diagnoseXcodebuildCopy reads of the host.
type xcodebuildCopyHost struct {
	readFile func(string) ([]byte, error)
	exists   func(string) bool
	cdhash   func(string) (string, error)
}

// xcodeCopy is one shadow copy an Xcode build in a pod relies on.
type xcodeCopy struct{ name, source string }

// xcodeBuildCopies are the copies an xcodebuild build needs, in the order the
// Event names them: xcodebuild itself and xcrun (B1786), and the asset-catalog
// and Interface Builder compilers actool, ibtool and ibtoold, which are signed
// with library validation, so they refuse the path-rebase shim and fail their
// atomic writes without a re-signed copy. Each is the copy `sudo k3sm install`
// makes; a node installed before a copy existed is reported as missing it,
// which is the truth: that build step fails there.
func xcodeBuildCopies() []xcodeCopy {
	bin := filepath.Dir(shadowset.XcodebuildSource)
	return []xcodeCopy{
		{"xcodebuild", shadowset.XcodebuildSource},
		{"xcrun", "/usr/bin/xcrun"},
		{"actool", filepath.Join(bin, "actool")},
		{"ibtool", filepath.Join(bin, "ibtool")},
		{"ibtoold", filepath.Join(bin, "ibtoold")},
	}
}

// diagnoseXcodebuildCopy is xcodebuildCopyProblem over an injected host. It
// answers the question `k3sm status` answers for the whole shadow set, for the
// copies an xcodebuild build cannot run without: each copy is present, the
// manifest records it, and the binary it was made from is still the one on
// disk. Without them Apple's binaries run with their private entitlements or
// library validation, lose the path-rebase shim and the per-pod user dirs, and
// the build does not finish in a pod.
func diagnoseXcodebuildCopy(shadowDir, developerDir string, h xcodebuildCopyHost) string {
	if filepath.Join(developerDir, "usr", "bin", "xcodebuild") != shadowset.XcodebuildSource {
		return fmt.Sprintf("the node's developer directory is %s, and k3sm makes its Xcode tool copies only from %s",
			developerDir, filepath.Dir(filepath.Dir(filepath.Dir(shadowset.XcodebuildSource))))
	}
	if shadowDir == "" {
		return "the node has no shadow binary set, so there are no Xcode tool copies"
	}
	b, err := h.readFile(filepath.Join(shadowDir, shadow.ManifestName))
	if err != nil {
		return fmt.Sprintf("the shadow binary set's manifest could not be read: %v", err)
	}
	m, err := shadow.Decode(b)
	if err != nil {
		return err.Error()
	}
	var problems []string
	for _, c := range xcodeBuildCopies() {
		if p := diagnoseOneCopy(shadowDir, c, m, h); p != "" {
			problems = append(problems, p)
		}
	}
	return strings.Join(problems, "; ")
}

// diagnoseOneCopy is diagnoseXcodebuildCopy's verdict for one copy.
func diagnoseOneCopy(shadowDir string, c xcodeCopy, m shadow.Manifest, h xcodebuildCopyHost) string {
	for _, s := range m.Skipped {
		if s.Name == c.name {
			return fmt.Sprintf("the last install skipped the %s copy: %s", c.name, s.Reason)
		}
	}
	for _, s := range m.Sources {
		if s.Name != c.name {
			continue
		}
		if !h.exists(filepath.Join(shadowDir, c.name)) {
			return fmt.Sprintf("the shadow binary set %s has no %s copy", shadowDir, c.name)
		}
		live, err := h.cdhash(s.Path)
		if err != nil {
			return fmt.Sprintf("the live %s could not be read: %v", s.Path, err)
		}
		if live != s.CDHash {
			return fmt.Sprintf("%s changed since its copy was made (an Xcode or macOS update), so the copy is stale", s.Path)
		}
		return ""
	}
	return fmt.Sprintf("the shadow binary set has no %s copy", c.name)
}

// warnXcodebuildCopyUnavailable is the build preflight: a pod whose toolchain
// grant took effect, on a node whose Xcode tool copies (xcodeBuildCopies) are
// missing, stale or unusable, hears it ON THE POD, once, at create. Without it the first sign is
// an xcodebuild that never finishes. Degrade, not fail, and create-only, for
// the reasons warnXcodeToolchainUngranted gives: most builds a granted pod runs
// (clang, swiftc, swift build) never touch xcodebuild.
func (r *runtimedRuntime) warnXcodebuildCopyUnavailable(ctx context.Context, pod *corev1.Pod, box *runtimev1.PodBox) {
	dir := box.GetSandboxProfile().GetXcodeToolchainDir()
	if !podRequestsXcodeToolchain(pod) || dir == "" {
		return
	}
	problem := xcodebuildCopyProblem(ctx, r.shadowBinDir, dir)
	if problem == "" {
		return
	}
	r.log.WarnContext(ctx, "pod was granted the Xcode toolchain; the node's xcodebuild copy is unavailable",
		"namespace", pod.Namespace, "name", pod.Name, "problem", problem)
	r.recorder.Event(pod, corev1.EventTypeWarning, reasonXcodebuildCopyUnavailable,
		msgXcodebuildCopyUnavailable(problem))
}
