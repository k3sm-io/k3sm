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

package netserve

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/darwin-net/pkg/proxy"
)

// TestStaticPinBacksKubernetesVIPWithoutEndpointSlice proves the loopback
// single-server path end to end through the node proxy: with the static pin and
// NO EndpointSlice (the apiserver runs with --endpoint-reconciler-type=none, so
// none is published) default/kubernetes resolves to the loopback listener.
func TestStaticPinBacksKubernetesVIPWithoutEndpointSlice(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.43.0.1",
			Ports:     []corev1.ServicePort{{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP}},
		},
	}
	s := New(Config{
		Client:            fake.NewClientset(svc),
		WorkDir:           t.TempDir(),
		DNSVIP:            "10.43.0.10",
		ClusterDomain:     "cluster.local",
		APIServerEndpoint: "127.0.0.1:6444",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.watch.Run(ctx) }()

	key := proxy.PortKey{ClusterIP: "10.43.0.1", Port: 443, Protocol: "TCP"}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if bes := s.table.Backends(key); len(bes) == 1 {
			if got := bes[0].Addr().String(); got != "127.0.0.1:6444" {
				t.Fatalf("default/kubernetes backend = %s, want 127.0.0.1:6444", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("default/kubernetes has no backend with the static pin and no EndpointSlice")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
