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
	"strings"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/dns"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// sipPlatformPrefixes are the SIP-protected system binary roots dyld treats as
// PLATFORM binaries. A process whose own executable resolves under one of these
// roots is signed with the platform-binary flag, and dyld strips every DYLD_*
// environment variable before it loads such a binary. The DNS getaddrinfo shim
// this provider injects via DYLD_INSERT_LIBRARIES is exactly the kind of
// variable dyld strips, so a pod whose entrypoint IS a platform binary — most
// commonly /bin/sh, since a shell script's own interpreter is what actually
// execs — silently loses the shim, and its cluster-name lookups NXDOMAIN with
// nothing on the pod pointing at why.
// This is the set of common roots, not a proof: the platform-binary property comes
// from the signature (the trust cache by cdhash), so a signed Apple binary elsewhere
// is still restricted and would be missed here; the check only ever warns.
var sipPlatformPrefixes = [...]string{
	"/bin/",
	"/sbin/",
	"/usr/bin/",
	"/usr/sbin/",
	"/usr/libexec/",
	"/System/Library/",
	"/System/Applications/",
	"/System/Cryptexes/",
	"/Library/Apple/",
}

// restrictedPlatformEntrypoint reports the host path a container's entrypoint
// will exec, and whether that path is a macOS SIP platform binary (see
// sipPlatformPrefixes).
//
// It fires ONLY for a container on the host-binary route —
// isHostBinaryContainer, isHostBinaryRoute's corev1 twin (runtimed_pull.go,
// translate.go), the discriminator mirroring runtimed's resolveBinary. A
// container that pulls an OCI image is executed from runtimed's ad-hoc-resigned
// copy of the image's own binary, which IS re-signed and so never loses the
// shim this way; a bare prefix test against every container would wrongly flag
// that arm, which is why the discriminator gates this predicate rather than a
// prefix check on c.Image or c.Command alone.
//
// The path resolved is the one resolveBinary will actually exec: Command[0] on
// the native-sentinel arm (c.Image == runtimed.NativeImage, where the image
// reference itself carries no path at all), and the image reference on the
// host-path-reference arm (an absolute-path image with no command/args —
// image.IsHostPathReference, checked inside isHostBinaryContainer).
func restrictedPlatformEntrypoint(c corev1.Container) (path string, ok bool) {
	if !isHostBinaryContainer(&c) {
		return "", false
	}
	if c.Image == runtimed.NativeImage {
		if len(c.Command) == 0 {
			// No argv[0] to inspect; resolveBinary has nothing to exec either.
			return "", false
		}
		path = c.Command[0]
	} else {
		path = c.Image
	}
	for _, prefix := range sipPlatformPrefixes {
		if strings.HasPrefix(path, prefix) {
			return path, true
		}
	}
	return "", false
}

// containerReceivedClusterDNSEnv reports whether c — a container off the
// RESOLVED PodBox, read after injectClusterDNSEnv has run — actually carries
// the cluster DNS shim env. It reads dns.EnvDNSServer, the one key
// injectClusterDNSEnv's own dns.ConfigToEnv encoding is keyed on, rather than a
// second hand-rolled literal that could drift from the encoder.
func containerReceivedClusterDNSEnv(c *runtimev1.Container) bool {
	for _, e := range c.GetEnv() {
		if e.GetName() == dns.EnvDNSServer {
			return true
		}
	}
	return false
}

// warnRestrictedShellEntrypoint reports, ON THE POD, that a container which
// received the cluster DNS shim env has an entrypoint dyld will treat as a
// macOS platform binary — see restrictedPlatformEntrypoint and
// sipPlatformPrefixes for why that silently drops the shim.
//
// Degrade, not refuse: most /bin/sh entrypoints exec a compiled binary that
// inherits the shim fine, so refusing at create would be a false positive for
// most of them. The Event exists because the ones that DO fail otherwise show
// only an in-pod "no such host", with nothing pointing at the cause.
//
// v1 (DNS only): this warns about the DNS getaddrinfo shim specifically. It
// does not cover the per-pod bind-discipline path-shim — the node does not
// hold a per-pod path-shim fact at the provider layer to check against here.
//
// Scope: the runtimedRuntime provider only. The legacy HostProcess provider
// injects no DYLD shim at all, so it has nothing this warning could report.
//
// CREATE-ONLY by placement (CreatePod calls it; UpdatePod does not) — matching
// warnXcodeToolchainUngranted's placement and for the same reason: an in-place
// label/annotation update would otherwise re-fire this on every unrelated
// update of a pod whose entrypoint has not changed.
func (r *runtimedRuntime) warnRestrictedShellEntrypoint(ctx context.Context, pod *corev1.Pod, box *runtimev1.PodBox) {
	warn := func(specCS []corev1.Container, boxCS []*runtimev1.Container) {
		for i := range specCS {
			if i >= len(boxCS) {
				continue
			}
			path, ok := restrictedPlatformEntrypoint(specCS[i])
			if !ok || !containerReceivedClusterDNSEnv(boxCS[i]) {
				continue
			}
			r.log.WarnContext(ctx, "container entrypoint is a macOS platform binary; the DNS shim will not load",
				"namespace", pod.Namespace, "name", pod.Name, "container", specCS[i].Name, "path", path)
			r.recorder.Event(pod, corev1.EventTypeWarning, reasonRestrictedShellEntrypoint,
				msgRestrictedShellEntrypoint(path))
		}
	}
	warn(pod.Spec.InitContainers, box.GetInitContainers())
	warn(pod.Spec.Containers, box.GetContainers())
}
