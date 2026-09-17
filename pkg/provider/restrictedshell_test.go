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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// restrictedShellPod builds a pod with the given containers and DNSPolicy
// ("" selects the upstream ClusterFirst default).
func restrictedShellPod(name string, policy corev1.DNSPolicy, containers ...corev1.Container) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			Containers: containers,
			DNSPolicy:  policy,
		},
	}
}

// TestRestrictedShellEntrypointWarns is the pod-visible-signal gate: a container
// on the host-binary route whose entrypoint is a macOS SIP platform binary, and
// which actually received the cluster DNS shim env, must say so ON THE POD —
// dyld silently strips the DYLD_INSERT_LIBRARIES shim before loading such a
// binary, and without the Event the only symptom is an in-pod "no such host"
// with nothing pointing at the cause.
//
// BOTH LEGS ARE LOAD-BEARING: a check exercised only on its warn leg degrades
// into "every /bin/sh pod gets flagged", which would be a false positive for
// the (common) case where the shell only execs a compiled binary that keeps the
// shim fine. So the table also covers the OCI-pull arm (never the host-binary
// route at all), a non-platform host-binary path, and a host-binary entrypoint
// that never received the DNS env in the first place.
func TestRestrictedShellEntrypointWarns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		containers []corev1.Container
		dnsPolicy  corev1.DNSPolicy
		wantPaths  []string // one entry per container index expected to warn; "" = no warn for that container
	}{
		{
			// The native sentinel arm: Command[0] is the path resolveBinary will
			// actually exec, and it is a SIP platform binary that received the
			// cluster DNS env — the exact failure this Event exists to surface.
			name: "native_sentinel_platform_path_with_dns_env_warns",
			containers: []corev1.Container{
				{Name: "c0", Image: runtimed.NativeImage, Command: []string{"/bin/sh"}},
			},
			wantPaths: []string{"/bin/sh"},
		},
		{
			// Same entrypoint string, but the OCI-pull arm: runtimed execs an
			// ad-hoc-resigned copy of the image's own binary, which IS re-signed
			// and never loses the shim this way. isHostBinaryContainer must gate
			// the predicate off this arm entirely.
			name: "oci_pull_arm_never_flagged",
			containers: []corev1.Container{
				{Name: "c0", Image: "some/image", Command: []string{"/bin/sh"}},
			},
		},
		{
			// Host-binary route, but the path is not under any SIP platform root —
			// an ordinary compiled binary at a non-system prefix.
			name: "host_binary_non_platform_path_no_warn",
			containers: []corev1.Container{
				{Name: "c0", Image: runtimed.NativeImage, Command: []string{"/usr/local/bin/tool"}},
			},
		},
		{
			// Host-binary route, platform path, but DNSPolicy: Default never injects
			// the shim env in the first place — nothing was lost, so nothing to warn.
			name: "host_binary_platform_path_no_dns_env_no_warn",
			containers: []corev1.Container{
				{Name: "c0", Image: runtimed.NativeImage, Command: []string{"/bin/sh"}},
			},
			dnsPolicy: corev1.DNSDefault,
		},
		{
			// The host-path-reference arm: an absolute-path image with no
			// command/args. The path resolved is the image reference itself.
			name: "host_path_reference_arm_warns",
			containers: []corev1.Container{
				{Name: "c0", Image: "/bin/bash"},
			},
			wantPaths: []string{"/bin/bash"},
		},
		{
			// Two offending containers on a pod that still gets created: one Event
			// per offender, not one for the pod, and CreatePod still succeeds.
			name: "two_containers_one_event_each_pod_still_created",
			containers: []corev1.Container{
				{Name: "c0", Image: runtimed.NativeImage, Command: []string{"/bin/sh"}},
				{Name: "c1", Image: "/usr/sbin/tool"},
			},
			wantPaths: []string{"/bin/sh", "/usr/sbin/tool"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := record.NewFakeRecorder(8)
			r := newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
				NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
				Recorder: rec, ResolverVIP: "10.43.0.10",
			}, nil, nil)

			pod := restrictedShellPod(tc.name, tc.dnsPolicy, tc.containers...)
			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}

			var wantCount int
			for _, p := range tc.wantPaths {
				if p != "" {
					wantCount++
				}
			}
			if wantCount == 0 {
				if ev := nextLifecycleEvent(rec.Events, 100*time.Millisecond); ev != "" {
					t.Fatalf("unexpected Event %q, want none", ev)
				}
				return
			}

			for i, wantPath := range tc.wantPaths {
				if wantPath == "" {
					continue
				}
				ev := nextLifecycleEvent(rec.Events, 3*time.Second)
				if ev == "" {
					t.Fatalf("container %d: no Event recorded, want a %s Event naming %q",
						i, reasonRestrictedShellEntrypoint, wantPath)
				}
				if !strings.HasPrefix(ev, corev1.EventTypeWarning+" "+reasonRestrictedShellEntrypoint+" ") {
					t.Errorf("Event = %q, want a Warning %s event", ev, reasonRestrictedShellEntrypoint)
				}
				if !strings.Contains(ev, wantPath) {
					t.Errorf("Event %q does not name the offending path %q", ev, wantPath)
				}
			}
			if ev := nextLifecycleEvent(rec.Events, 100*time.Millisecond); ev != "" {
				t.Fatalf("unexpected extra Event %q", ev)
			}
		})
	}
}
