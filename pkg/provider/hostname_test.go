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
	"log/slog"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	"k3sm.io/k3sm/pkg/runtimeclass"
)

// TestPodHostnameFromHostnameOverride is the gate for the pod hostname the
// provider puts on PodBox.hostname: the kubelet's derivation at v1.37.1
// (hostnameOverride, hostname, pod name, truncation, subdomain and
// setHostnameAsFQDN), and the per-backend handling of a value that cannot be
// derived (a vm pod is refused with a Warning Event; a native pod proceeds with
// no hostname and a Warn log, since no native process can observe it).
//
// Every row goes through CreatePod, so each one also proves what reached the
// runtime and whether a refusal Event was recorded.
func TestPodHostnameFromHostnameOverride(t *testing.T) {
	t.Parallel()

	const (
		native = "" // no runtimeClassName: a native rung
		vm     = runtimeclass.Name
	)
	// "p.s.n.svc." is 10 characters, so a 55-character cluster domain makes the
	// FQDN 65 characters, one over the kubelet's 64.
	longDomain := strings.Repeat("d", 49) + ".local"
	longFQDN := "p.s.n.svc." + longDomain
	if len(longFQDN) != 65 {
		t.Fatalf("fixture: FQDN is %d characters, want 65", len(longFQDN))
	}
	// 70 characters with '-' at position 63: the cut keeps 63 and trims the '-'.
	longOverride := strings.Repeat("a", 62) + "-" + strings.Repeat("b", 7)
	truncated := strings.Repeat("a", 62)

	tests := []struct {
		name          string
		podName       string
		hostname      string
		override      *string
		subdomain     string
		fqdn          bool
		hostNetwork   bool
		runtimeClass  string
		clusterDomain string

		want        string
		wantRefused bool   // CreatePod fails, no RPC, a Warning Event
		wantErr     string // substring of the error and the Event (the kubelet's text)
		wantLog     []string
	}{
		{name: "override wins", podName: "p", hostname: "h", override: ptr("my.host"), want: "my.host"},
		{name: "override ignores subdomain and FQDN", podName: "p", override: ptr("o"), subdomain: "s", fqdn: true, want: "o"},
		{name: "hostname", podName: "p", hostname: "h", want: "h"},
		{name: "pod name", podName: "p", want: "p"},
		{name: "FQDN", podName: "p", subdomain: "s", fqdn: true, clusterDomain: "cluster.local", want: "p.s.n.svc.cluster.local"},
		{name: "subdomain without FQDN flag", podName: "p", subdomain: "s", want: "p"},
		{
			name: "FQDN too long vm", podName: "p", subdomain: "s", fqdn: true, clusterDomain: longDomain, runtimeClass: vm,
			wantRefused: true,
			wantErr:     "failed to construct FQDN from pod hostname and cluster domain, FQDN " + longFQDN + " is too long (64 characters is the max, 65 characters requested)",
		},
		{
			name: "FQDN too long native", podName: "p", subdomain: "s", fqdn: true, clusterDomain: longDomain, runtimeClass: native,
			want: "", wantLog: []string{"level=WARN", "pod hostname cannot be derived", "name=p", "is too long"},
		},
		{
			name: "truncation", podName: "p", override: ptr(longOverride), runtimeClass: vm, want: truncated,
			wantLog: []string{"level=WARN msg=\"pod hostname too long, truncated it\"", "name=p", "hostname=" + truncated},
		},
		{
			// The same cut on a backend that ignores the field is only worth a Debug line.
			name: "truncation native", podName: "p", override: ptr(longOverride), runtimeClass: native, want: truncated,
			wantLog: []string{"level=DEBUG msg=\"pod hostname too long, truncated it\"", "name=p", "hostname=" + truncated},
		},
		{
			name: "invalid override vm", podName: "p", override: ptr("Bad_Host"), runtimeClass: vm,
			wantRefused: true, wantErr: `pod HostnameOverride "Bad_Host" is not a valid DNS subdomain: `,
		},
		{
			name: "invalid override native", podName: "p", override: ptr("Bad_Host"), runtimeClass: native,
			want: "", wantLog: []string{"level=WARN", "pod hostname cannot be derived", "name=p", "not a valid DNS subdomain"},
		},
		{name: "hostNetwork with override", podName: "p", override: ptr("o"), hostNetwork: true, want: ""},
		{name: "hostNetwork without override", podName: "p", hostNetwork: true, want: ""},
		{name: "native backend", podName: "p", override: ptr("o"), runtimeClass: native, want: "o"},
		// The producer-to-consumer leg on the vm path: an admitted vm pod's box
		// carries the derived name, so dropping it there fails these rows.
		{name: "vm override admitted", podName: "p", hostname: "h", override: ptr("my.host"), runtimeClass: vm, want: "my.host"},
		{
			name: "vm FQDN admitted", podName: "p", hostname: "h", subdomain: "s", fqdn: true, clusterDomain: "cluster.local",
			runtimeClass: vm, want: "h.s.n.svc.cluster.local",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &platformFake{
				fakeRuntimeServer: newFakeRuntimeServer(),
				info:              capabilityInfo(NodeCapabilities{VMBackend: true}),
			}
			rec := record.NewFakeRecorder(32)
			logs := &syncBuffer{}
			log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			r := newRuntimedWith(f, RuntimedConfig{
				NodeName: "node", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
				Recorder: rec, ClusterDomain: tc.clusterDomain,
			}, nil, log)

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "n", Name: tc.podName, UID: types.UID("uid-" + tc.podName)},
				Spec: corev1.PodSpec{
					Hostname:         tc.hostname,
					HostnameOverride: tc.override,
					Subdomain:        tc.subdomain,
					HostNetwork:      tc.hostNetwork,
					Containers:       []corev1.Container{{Name: "c0", Image: "registry/web:1", Command: []string{"/web"}}},
				},
			}
			if tc.fqdn {
				pod.Spec.SetHostnameAsFQDN = ptr(true)
			}
			if tc.runtimeClass != "" {
				rc := tc.runtimeClass
				pod.Spec.RuntimeClassName = &rc
			}

			err := r.CreatePod(context.Background(), pod)
			_, createCalls := f.counts()
			sandboxEvents := drainEventsWithReason(rec.Events, reasonFailedCreatePodSandBox)

			if tc.wantRefused {
				if err == nil {
					t.Fatal("CreatePod = nil, want the vm pod refused: its kernel hostname is observable")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("CreatePod error = %q, want it to carry the kubelet's text %q", err, tc.wantErr)
				}
				if createCalls != 0 {
					t.Errorf("CreatePod RPC calls = %d, want 0: the refusal lands before the RPC", createCalls)
				}
				if len(sandboxEvents) != 1 {
					t.Fatalf("%s events = %q, want exactly one", reasonFailedCreatePodSandBox, sandboxEvents)
				}
				ev := sandboxEvents[0]
				if !strings.HasPrefix(ev, corev1.EventTypeWarning+" "+reasonFailedCreatePodSandBox+" Failed to create pod sandbox: ") {
					t.Errorf("event = %q, want a Warning with the kubelet's prefix", ev)
				}
				if !strings.Contains(ev, tc.wantErr) {
					t.Errorf("event = %q, want the kubelet's text %q", ev, tc.wantErr)
				}
				if !strings.Contains(ev, "spec.") || !strings.Contains(ev, " characters)") {
					t.Errorf("event = %q, want it to name the field and the length", ev)
				}
				return
			}

			if err != nil {
				t.Fatalf("CreatePod = %v, want the pod admitted", err)
			}
			if createCalls != 1 {
				t.Errorf("CreatePod RPC calls = %d, want 1", createCalls)
			}
			if len(sandboxEvents) != 0 {
				t.Errorf("events %q recorded for an admitted pod, want none", sandboxEvents)
			}
			box := f.createdBox(string(pod.UID))
			if box == nil {
				t.Fatal("no PodBox reached the runtime")
			}
			if got := box.GetHostname(); got != tc.want {
				t.Errorf("PodBox.hostname = %q, want %q", got, tc.want)
			}
			out := logs.String()
			for _, w := range tc.wantLog {
				if !strings.Contains(out, w) {
					t.Errorf("log does not contain %q:\n%s", w, out)
				}
			}
		})
	}
}

// drainEventsWithReason reads every Event already recorded on ch and returns
// those carrying reason.
func drainEventsWithReason(ch <-chan string, reason string) []string {
	var out []string
	for {
		select {
		case ev := <-ch:
			if strings.Contains(ev, " "+reason+" ") {
				out = append(out, ev)
			}
		default:
			return out
		}
	}
}
