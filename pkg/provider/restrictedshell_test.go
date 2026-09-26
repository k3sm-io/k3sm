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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	runtimev1 "k3sm.io/apis/runtime/v1"
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

// shimInactiveCondition is the condition runtimed publishes for a restricted
// main process (runtimed/pkg/runtime shiminactive.go), with a message in its
// shape: the container, the path, the flags, and both losses.
func shimInactiveCondition(reason, container, path string) *runtimev1.PodCondition {
	return &runtimev1.PodCondition{
		Type:   runtimed.ShimInactiveConditionType,
		Status: runtimev1.ConditionStatus_CONDITION_STATUS_TRUE,
		Reason: reason,
		Message: "container " + container + ": pod shim inactive for a restricted main process (" + path +
			", CS_PLATFORM_BINARY): per-namespace DNS precedence and bind/connect source discipline are " +
			"unavailable; FQDN and name.ns.svc resolve through the node resolver",
	}
}

// TestRestrictedShellEntrypointWarns is B309's pod-visible-signal gate,
// re-pointed by B243 (the name is kept so B309's gate reference stays live): a
// container whose main process lost the DNS shim must say so ON THE POD. The
// signal is no longer the argv heuristic B309 shipped (a SIP path prefix on
// Command[0]) but runtimed's kernel verdict, the k3sm.io/shim-inactive
// condition, because since B243 a /bin/sh entrypoint runs through the node's
// re-signed shell and KEEPS the shim, while a restricted binary under any
// other path still loses it. So the table pins both directions: the argv alone
// no longer warns, and the condition warns whatever the argv.
func TestRestrictedShellEntrypointWarns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		containers []corev1.Container
		dnsPolicy  corev1.DNSPolicy
		condition  *runtimev1.PodCondition // what runtimed reports; nil = shim loaded
		wantEvent  bool
	}{
		{
			name:       "platform_shell_reported_restricted_warns",
			containers: []corev1.Container{{Name: "c0", Image: runtimed.NativeImage, Command: []string{"/usr/bin/python3"}}},
			condition:  shimInactiveCondition(runtimed.ShimInactiveReason, "c0", "/usr/bin/python3"),
			wantEvent:  true,
		},
		{
			// /bin/sh on the host-binary route: B309 warned on the argv; the
			// shadow shell keeps the shim, runtimed reports nothing, no Event.
			name:       "bin_sh_through_the_shadow_shell_no_warn",
			containers: []corev1.Container{{Name: "c0", Image: runtimed.NativeImage, Command: []string{"/bin/sh"}}},
		},
		{
			// The OCI-pull arm, never flagged by the old heuristic: a hardened
			// binary in an image also loses the shim, and the kernel says so.
			name:       "oci_pull_arm_reported_hardened_warns",
			containers: []corev1.Container{{Name: "c0", Image: "some/image", Command: []string{"/app/server"}}},
			condition:  shimInactiveCondition(runtimed.ShimInactiveHardenedReason, "c0", "/app/server"),
			wantEvent:  true,
		},
		{
			name:       "dns_default_no_condition_no_warn",
			containers: []corev1.Container{{Name: "c0", Image: runtimed.NativeImage, Command: []string{"/bin/sh"}}},
			dnsPolicy:  corev1.DNSDefault,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := record.NewFakeRecorder(8)
			f := newFakeRuntimeServer()
			r := newRuntimedWith(f, RuntimedConfig{
				NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
				Recorder: rec, ResolverVIP: "10.43.0.10",
			}, nil, nil)

			pod := restrictedShellPod(tc.name, tc.dnsPolicy, tc.containers...)
			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if ev := nextLifecycleEvent(rec.Events, 100*time.Millisecond); ev != "" {
				t.Fatalf("Event %q at create, want none: the argv no longer decides", ev)
			}
			if tc.condition != nil {
				f.setConditions(string(pod.UID), tc.condition)
			}
			if _, err := r.GetPodStatus(context.Background(), pod.Namespace, pod.Name); err != nil {
				t.Fatalf("GetPodStatus: %v", err)
			}

			ev := nextLifecycleEvent(rec.Events, 100*time.Millisecond)
			if !tc.wantEvent {
				if ev != "" {
					t.Fatalf("unexpected Event %q, want none", ev)
				}
				return
			}
			want := corev1.EventTypeWarning + " " + reasonShimInactive + " " + tc.condition.GetMessage()
			if ev != want {
				t.Fatalf("Event = %q, want %q", ev, want)
			}
		})
	}
}
