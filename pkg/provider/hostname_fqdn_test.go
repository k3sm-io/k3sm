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

	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// TestVMPodHostnameEnvAndFQDN is the gate for PodBox.pod_fqdn: the provider
// renders the kubelet's <hostname>.<subdomain>.<ns>.svc.<clusterDomain> once,
// in podHostname, for a vm pod with a subdomain, and sends it on the box. An
// override pod, a pod without a subdomain and a hostNetwork pod carry none
// (the kubelet gives each an empty domain), the domain is the configured
// cluster domain, a native box carries none, and the provider never adds
// HOSTNAME to any container env (the runtime sets it beneath the image env).
//
// Every row goes through CreatePod, so the box checked is the one that reached
// the runtime, after the provider's env flattening.
func TestVMPodHostnameEnvAndFQDN(t *testing.T) {
	t.Parallel()

	const (
		native = ""
		vm     = runtimeclass.Name
	)
	// Five 50-character labels: the composed FQDN is "p.s.n.svc." (10) plus
	// 254, over the 253-byte DNS-1123 subdomain limit, with every label valid.
	longDomain := strings.Join([]string{
		strings.Repeat("a", 50), strings.Repeat("b", 50), strings.Repeat("c", 50),
		strings.Repeat("d", 50), strings.Repeat("e", 50),
	}, ".")
	if n := len("p.s.n.svc." + longDomain); n != 264 {
		t.Fatalf("fixture: FQDN is %d characters, want 264", n)
	}

	tests := []struct {
		name          string
		hostname      string
		override      *string
		subdomain     string
		fqdn          bool
		hostNetwork   bool
		runtimeClass  string
		clusterDomain string

		wantHostname string
		wantFQDN     string
		wantLog      []string
	}{
		{name: "pod name and subdomain", subdomain: "s", runtimeClass: vm, clusterDomain: "cluster.local",
			wantHostname: "p", wantFQDN: "p.s.n.svc.cluster.local"},
		{name: "hostname and subdomain", hostname: "h", subdomain: "s", runtimeClass: vm, clusterDomain: "cluster.local",
			wantHostname: "h", wantFQDN: "h.s.n.svc.cluster.local"},
		{name: "configured cluster domain", subdomain: "s", runtimeClass: vm, clusterDomain: "corp.example",
			wantHostname: "p", wantFQDN: "p.s.n.svc.corp.example"},
		{name: "setHostnameAsFQDN", subdomain: "s", fqdn: true, runtimeClass: vm, clusterDomain: "cluster.local",
			wantHostname: "p.s.n.svc.cluster.local", wantFQDN: "p.s.n.svc.cluster.local"},
		{name: "setHostnameAsFQDN with hostname", hostname: "h", subdomain: "s", fqdn: true, runtimeClass: vm,
			clusterDomain: "corp.example", wantHostname: "h.s.n.svc.corp.example", wantFQDN: "h.s.n.svc.corp.example"},
		{
			// The kubelet writes this name without a length check, so the pod is
			// never refused for it; the guest just gets no alias.
			name: "FQDN over 253 bytes", subdomain: "s", runtimeClass: vm, clusterDomain: longDomain,
			wantHostname: "p",
			wantLog:      []string{"level=WARN", "pod gets no FQDN alias", "not a valid DNS subdomain", "name=p", "fqdnLen=264"},
		},
		{name: "FQDN over 253 bytes native", subdomain: "s", runtimeClass: native, clusterDomain: longDomain,
			wantHostname: "p"},
		{name: "override with subdomain", override: ptr("my.host"), subdomain: "s", runtimeClass: vm, clusterDomain: "cluster.local",
			wantHostname: "my.host"},
		{name: "no subdomain", hostname: "h", runtimeClass: vm, clusterDomain: "cluster.local", wantHostname: "h"},
		{name: "hostNetwork", subdomain: "s", hostNetwork: true, runtimeClass: vm, clusterDomain: "cluster.local"},
		{name: "native with subdomain", subdomain: "s", runtimeClass: native, clusterDomain: "cluster.local",
			wantHostname: "p"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &platformFake{
				fakeRuntimeServer: newFakeRuntimeServer(),
				info:              capabilityInfo(NodeCapabilities{VMBackend: true}),
			}
			logs := &syncBuffer{}
			log := slog.New(slog.NewTextHandler(logs, nil))
			r := newRuntimedWith(f, RuntimedConfig{
				NodeName: "node", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
				Recorder: record.NewFakeRecorder(32), ClusterDomain: tc.clusterDomain,
			}, nil, log)

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "n", Name: "p", UID: types.UID("uid-fqdn")},
				Spec: corev1.PodSpec{
					Hostname:         tc.hostname,
					HostnameOverride: tc.override,
					Subdomain:        tc.subdomain,
					HostNetwork:      tc.hostNetwork,
					InitContainers:   []corev1.Container{{Name: "i0", Image: "registry/init:1", Command: []string{"/init"}}},
					Containers: []corev1.Container{{Name: "c0", Image: "registry/web:1", Command: []string{"/web"},
						Env: []corev1.EnvVar{{Name: "APP", Value: "1"}}}},
				},
			}
			if tc.fqdn {
				pod.Spec.SetHostnameAsFQDN = ptr(true)
			}
			if tc.runtimeClass != "" {
				rc := tc.runtimeClass
				pod.Spec.RuntimeClassName = &rc
			}

			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod = %v, want the pod admitted", err)
			}
			box := f.createdBox(string(pod.UID))
			if box == nil {
				t.Fatal("no PodBox reached the runtime")
			}
			if got := box.GetHostname(); got != tc.wantHostname {
				t.Errorf("PodBox.hostname = %q, want %q", got, tc.wantHostname)
			}
			if got := box.GetPodFqdn(); got != tc.wantFQDN {
				t.Errorf("PodBox.pod_fqdn = %q, want %q", got, tc.wantFQDN)
			}
			if tc.fqdn && box.GetPodFqdn() != box.GetHostname() {
				t.Errorf("setHostnameAsFQDN: PodBox.pod_fqdn = %q, PodBox.hostname = %q, want the same string",
					box.GetPodFqdn(), box.GetHostname())
			}
			out := logs.String()
			for _, w := range tc.wantLog {
				if !strings.Contains(out, w) {
					t.Errorf("log does not contain %q:\n%s", w, out)
				}
			}
			if len(tc.wantLog) == 0 && strings.Contains(out, "FQDN alias") {
				t.Errorf("log carries an FQDN alias Warn for a pod that should get none:\n%s", out)
			}
			for _, cs := range [][]*runtimev1.Container{box.GetInitContainers(), box.GetContainers()} {
				for _, c := range cs {
					for _, e := range c.GetEnv() {
						if e.GetName() == "HOSTNAME" {
							t.Errorf("container %s env carries HOSTNAME=%q, want none from the provider", c.GetName(), e.GetValue())
						}
					}
				}
			}
		})
	}
}

// TestVMPodFQDNWithoutClusterDomain covers the one input CreatePod cannot
// produce (the runtime defaults an empty cluster domain): toPodBox with no
// cluster domain sends no FQDN, never a trailing-dot name, and says why.
func TestVMPodFQDNWithoutClusterDomain(t *testing.T) {
	t.Parallel()
	rc := runtimeclass.Name
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "n", Name: "p", UID: types.UID("uid-nodomain")},
		Spec: corev1.PodSpec{
			RuntimeClassName: &rc,
			Subdomain:        "s",
			Containers:       []corev1.Container{{Name: "c0", Image: "registry/web:1", Command: []string{"/web"}}},
		},
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	box, err := toPodBox(pod, "10.42.0.7", "192.168.1.10", t.TempDir(), "", netv1.DNSConfig{}, log)
	if err != nil {
		t.Fatalf("toPodBox: %v", err)
	}
	if got := box.GetPodFqdn(); got != "" {
		t.Errorf("PodBox.pod_fqdn = %q, want empty without a cluster domain", got)
	}
	if got := box.GetHostname(); got != "p" {
		t.Errorf("PodBox.hostname = %q, want %q", got, "p")
	}
	if out := logs.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "pod gets no FQDN alias: no cluster domain configured") {
		t.Errorf("log = %q, want a Warn naming the missing cluster domain", out)
	}
}
