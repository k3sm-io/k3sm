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
	"errors"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

func svc(ns, name string, typ corev1.ServiceType, clusterIP string, ports ...corev1.ServicePort) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.ServiceSpec{Type: typ, ClusterIP: clusterIP, Ports: ports},
	}
}

// TestResolvePodBoxEnvInjectsNamespaceServiceLinks is B363's gate: a pod's
// containers get the kubelet's service-links environment for every Service in
// the pod's namespace whose ClusterIP is set (type-independent), resolved once
// at the translate boundary, layered UNDER the master service, envFrom and the
// explicit env, and gated by spec.enableServiceLinks (nil means true).
func TestResolvePodBoxEnvInjectsNamespaceServiceLinks(t *testing.T) {
	objs := []runtime.Object{
		// Qualifying: plain ClusterIP with a named and an unnamed port.
		svc("prod", "web-api", corev1.ServiceTypeClusterIP, "10.43.0.20",
			corev1.ServicePort{Name: "http-alt", Port: 8080, Protocol: corev1.ProtocolTCP},
			corev1.ServicePort{Port: 9090, Protocol: corev1.ProtocolUDP}),
		// Qualifying: NodePort has a ClusterIP, so it links (IsServiceIPSet is
		// type-independent). Unnamed single port, protocol defaulted.
		svc("prod", "db", corev1.ServiceTypeNodePort, "10.43.0.30",
			corev1.ServicePort{Port: 5432, NodePort: 30432}),
		// Excluded: headless and ExternalName.
		svc("prod", "headless", corev1.ServiceTypeClusterIP, corev1.ClusterIPNone,
			corev1.ServicePort{Name: "x", Port: 80}),
		svc("prod", "ext", corev1.ServiceTypeExternalName, "",
			corev1.ServicePort{Port: 443}),
		// A same-name collision with the master service: must lose to it.
		svc("prod", "kubernetes", corev1.ServiceTypeClusterIP, "10.43.0.99",
			corev1.ServicePort{Name: "https", Port: 443}),
		// Another namespace: never linked.
		svc("other", "foreign", corev1.ServiceTypeClusterIP, "10.43.0.40",
			corev1.ServicePort{Port: 80}),
	}
	newR := func(t *testing.T) *runtimedRuntime {
		t.Helper()
		return newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
			NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
			APIServerVIP: "10.43.0.1",
			Client:       fake.NewSimpleClientset(objs...),
		}, nil, nil)
	}
	envOf := func(t *testing.T, box *runtimev1.PodBox) (map[string]string, []string) {
		t.Helper()
		m := map[string]string{}
		var names []string
		for _, e := range box.GetContainers()[0].GetEnv() {
			m[e.GetName()] = e.GetValue()
			names = append(names, e.GetName())
		}
		return m, names
	}
	build := func(t *testing.T, enable *bool, env ...corev1.EnvVar) (map[string]string, []string) {
		t.Helper()
		pod := runtimedPod("prod", "web")
		pod.Spec.EnableServiceLinks = enable
		pod.Spec.Containers[0].Env = env
		box, err := newR(t).buildBox(context.Background(), pod, "192.168.1.10")
		if err != nil {
			t.Fatalf("buildBox: %v", err)
		}
		return envOf(t, box)
	}
	yes, no := true, false

	wantLinks := map[string]string{
		"WEB_API_SERVICE_HOST":          "10.43.0.20",
		"WEB_API_SERVICE_PORT":          "8080",
		"WEB_API_SERVICE_PORT_HTTP_ALT": "8080",
		"WEB_API_PORT":                  "tcp://10.43.0.20:8080",
		"WEB_API_PORT_8080_TCP":         "tcp://10.43.0.20:8080",
		"WEB_API_PORT_8080_TCP_PROTO":   "tcp",
		"WEB_API_PORT_8080_TCP_PORT":    "8080",
		"WEB_API_PORT_8080_TCP_ADDR":    "10.43.0.20",
		"WEB_API_PORT_9090_UDP":         "udp://10.43.0.20:9090",
		"WEB_API_PORT_9090_UDP_PROTO":   "udp",
		"WEB_API_PORT_9090_UDP_PORT":    "9090",
		"WEB_API_PORT_9090_UDP_ADDR":    "10.43.0.20",
		"DB_SERVICE_HOST":               "10.43.0.30",
		"DB_SERVICE_PORT":               "5432",
		"DB_PORT":                       "tcp://10.43.0.30:5432",
		"DB_PORT_5432_TCP":              "tcp://10.43.0.30:5432",
		"DB_PORT_5432_TCP_PROTO":        "tcp",
		"DB_PORT_5432_TCP_PORT":         "5432",
		"DB_PORT_5432_TCP_ADDR":         "10.43.0.30",
		"KUBERNETES_SERVICE_HOST":       "10.43.0.1",
		"KUBERNETES_SERVICE_PORT_HTTPS": "443",
		"KUBERNETES_PORT":               "tcp://10.43.0.1:443",
		"KUBERNETES_PORT_443_TCP_ADDR":  "10.43.0.1",
	}

	for _, tc := range []struct {
		name   string
		enable *bool
	}{{"enableServiceLinks nil injects", nil}, {"enableServiceLinks true injects", &yes}} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := build(t, tc.enable)
			for k, v := range wantLinks {
				if env[k] != v {
					t.Errorf("env[%q] = %q, want %q", k, env[k], v)
				}
			}
			for k, v := range env {
				for _, bad := range []string{"HEADLESS_", "EXT_", "FOREIGN_"} {
					if strings.HasPrefix(k, bad) {
						t.Errorf("env carries %q: headless, ExternalName and other-namespace services must not link", k)
					}
				}
				// Only one WEB_API port is named, and DB's is not.
				if strings.HasPrefix(k, "DB_SERVICE_PORT_") ||
					(strings.HasPrefix(k, "WEB_API_SERVICE_PORT_") && k != "WEB_API_SERVICE_PORT_HTTP_ALT") {
					t.Errorf("env carries %q: an unnamed port gets no SERVICE_PORT_<NAME> variable", k)
				}
				// The namespace's own "kubernetes" Service loses every
				// collision to the master service.
				if strings.Contains(v, "10.43.0.99") {
					t.Errorf("env[%q] = %q: the namespace kubernetes Service beat the master service", k, v)
				}
			}
		})
	}

	t.Run("enableServiceLinks false injects none but keeps the master service", func(t *testing.T) {
		env, _ := build(t, &no)
		for k := range env {
			if !strings.HasPrefix(k, "KUBERNETES_") && !strings.HasPrefix(k, "K3SM_") {
				t.Errorf("env carries %q with service links disabled", k)
			}
		}
		if env["KUBERNETES_SERVICE_HOST"] != "10.43.0.1" {
			t.Errorf("KUBERNETES_SERVICE_HOST = %q, want the master service always injected", env["KUBERNETES_SERVICE_HOST"])
		}
	})

	t.Run("layering: explicit env beats a service link", func(t *testing.T) {
		env, _ := build(t, nil, corev1.EnvVar{Name: "DB_SERVICE_HOST", Value: "override"})
		if env["DB_SERVICE_HOST"] != "override" {
			t.Errorf("DB_SERVICE_HOST = %q, want the explicit env to win", env["DB_SERVICE_HOST"])
		}
	})

	t.Run("deterministic ordering", func(t *testing.T) {
		_, first := build(t, nil)
		for range 5 {
			if _, again := build(t, nil); !slices.Equal(first, again) {
				t.Fatalf("env order changed between builds:\n%v\n%v", first, again)
			}
		}
		// Namespace links (sorted by service name: db < kubernetes < web-api)
		// come first, then the master service's variables upsert over the
		// colliding names in place.
		iDB := slices.Index(first, "DB_SERVICE_HOST")
		iWeb := slices.Index(first, "WEB_API_SERVICE_HOST")
		if iDB < 0 || iWeb < 0 || iDB > iWeb {
			t.Errorf("want DB_* before WEB_API_* (sorted by service name), got order %v", first)
		}
	})

	t.Run("a List failure fails the translation", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("list", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver down")
		})
		r := newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
			NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Client: cs,
		}, nil, nil)
		if _, err := r.buildBox(context.Background(), runtimedPod("prod", "web"), "192.168.1.10"); err == nil {
			t.Fatal("buildBox succeeded with a failing Services List, want an error")
		}
	})
}

// TestServiceLinkEnvMangling pins the pure helper's mangling and emission
// order, with no client.
func TestServiceLinkEnvMangling(t *testing.T) {
	cases := []struct {
		name string
		in   []corev1.Service
		want []string
	}{
		{
			name: "dashes to underscores, uppercased, named port",
			in: []corev1.Service{*svc("ns", "my-svc", corev1.ServiceTypeLoadBalancer, "10.0.0.5",
				corev1.ServicePort{Name: "grpc-web", Port: 81, Protocol: corev1.ProtocolSCTP})},
			want: []string{
				"MY_SVC_SERVICE_HOST=10.0.0.5",
				"MY_SVC_SERVICE_PORT=81",
				"MY_SVC_SERVICE_PORT_GRPC_WEB=81",
				"MY_SVC_PORT=sctp://10.0.0.5:81",
				"MY_SVC_PORT_81_SCTP=sctp://10.0.0.5:81",
				"MY_SVC_PORT_81_SCTP_PROTO=sctp",
				"MY_SVC_PORT_81_SCTP_PORT=81",
				"MY_SVC_PORT_81_SCTP_ADDR=10.0.0.5",
			},
		},
		{
			name: "sorted by service name; headless, ExternalName and portless skipped",
			in: []corev1.Service{
				*svc("ns", "zeta", corev1.ServiceTypeClusterIP, "10.0.0.2", corev1.ServicePort{Port: 1}),
				*svc("ns", "hl", corev1.ServiceTypeClusterIP, "None", corev1.ServicePort{Port: 2}),
				*svc("ns", "en", corev1.ServiceTypeExternalName, "", corev1.ServicePort{Port: 3}),
				*svc("ns", "noports", corev1.ServiceTypeClusterIP, "10.0.0.4"),
				*svc("ns", "alpha", corev1.ServiceTypeNodePort, "10.0.0.1", corev1.ServicePort{Port: 5}),
			},
			want: []string{
				"ALPHA_SERVICE_HOST=10.0.0.1", "ALPHA_SERVICE_PORT=5", "ALPHA_PORT=tcp://10.0.0.1:5",
				"ALPHA_PORT_5_TCP=tcp://10.0.0.1:5", "ALPHA_PORT_5_TCP_PROTO=tcp", "ALPHA_PORT_5_TCP_PORT=5", "ALPHA_PORT_5_TCP_ADDR=10.0.0.1",
				"ZETA_SERVICE_HOST=10.0.0.2", "ZETA_SERVICE_PORT=1", "ZETA_PORT=tcp://10.0.0.2:1",
				"ZETA_PORT_1_TCP=tcp://10.0.0.2:1", "ZETA_PORT_1_TCP_PROTO=tcp", "ZETA_PORT_1_TCP_PORT=1", "ZETA_PORT_1_TCP_ADDR=10.0.0.2",
			},
		},
		{
			name: "IPv6 ClusterIP is bracketed in the link URL",
			in:   []corev1.Service{*svc("ns", "v6", corev1.ServiceTypeClusterIP, "fd00::10", corev1.ServicePort{Port: 80})},
			want: []string{
				"V6_SERVICE_HOST=fd00::10", "V6_SERVICE_PORT=80", "V6_PORT=tcp://[fd00::10]:80",
				"V6_PORT_80_TCP=tcp://[fd00::10]:80", "V6_PORT_80_TCP_PROTO=tcp", "V6_PORT_80_TCP_PORT=80", "V6_PORT_80_TCP_ADDR=fd00::10",
			},
		},
		{name: "no services", in: nil, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, e := range serviceLinkEnv(tc.in) {
				got = append(got, e.GetName()+"="+e.GetValue())
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("serviceLinkEnv:\n got %v\nwant %v", got, tc.want)
			}
		})
	}
}
