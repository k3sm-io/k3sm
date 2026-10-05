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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/netip"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func netdTestPod(name, ip string, vm bool, ports ...int32) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, UID: types.UID("uid-" + name)},
		Spec:       corev1.PodSpec{NodeName: "worker", Containers: []corev1.Container{{Name: "c"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip},
	}
	if vm {
		h := "vm"
		p.Spec.RuntimeClassName = &h
	}
	for _, port := range ports {
		p.Spec.Containers[0].Ports = append(p.Spec.Containers[0].Ports, corev1.ContainerPort{ContainerPort: port})
	}
	return p
}

func netdTestSlice(name, ip string, owner types.UID, proto corev1.Protocol, ports ...int32) *discoveryv1.EndpointSlice {
	s := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Namespace: "ns", Name: name},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{ip}}},
	}
	if owner != "" {
		s.Endpoints[0].TargetRef = &corev1.ObjectReference{Kind: "Pod", UID: owner}
	}
	for _, port := range ports {
		p, pr := port, proto
		s.Ports = append(s.Ports, discoveryv1.EndpointPort{Port: &p, Protocol: &pr})
	}
	return s
}

// TestVMPodRelayPorts pins the source the published-vm-pod bind class reads:
// a live vm pod's declared TCP ports plus the TCP ports an EndpointSlice targets
// at its address, and nothing for any other pod or address.
func TestVMPodRelayPorts(t *testing.T) {
	t.Parallel()
	webhook := netdTestPod("webhook", "100.64.3.7", true, 443)
	native := netdTestPod("native", "100.64.3.8", false, 80)
	done := netdTestPod("done", "100.64.3.9", true, 80)
	done.Status.Phase = corev1.PodSucceeded
	hostNet := netdTestPod("hostnet", "100.64.3.10", true, 80)
	hostNet.Spec.HostNetwork = true
	twinA := netdTestPod("twin-a", "100.64.3.11", true, 80)
	twinB := netdTestPod("twin-b", "100.64.3.11", true, 81)

	pods := []*corev1.Pod{webhook, native, done, hostNet, twinA, twinB}
	eps := []*discoveryv1.EndpointSlice{
		netdTestSlice("svc-a", "100.64.3.7", webhook.UID, corev1.ProtocolTCP, 80),
		netdTestSlice("svc-udp", "100.64.3.7", webhook.UID, corev1.ProtocolUDP, 53),
		netdTestSlice("svc-stale", "100.64.3.7", "uid-previous-owner", corev1.ProtocolTCP, 22),
		netdTestSlice("svc-native", "100.64.3.8", native.UID, corev1.ProtocolTCP, 25),
	}

	cases := []struct {
		name string
		addr string
		want []uint16
	}{
		{name: "vm pod: declared plus Service-targeted TCP", addr: "100.64.3.7", want: []uint16{80, 443}},
		{name: "native pod", addr: "100.64.3.8"},
		{name: "terminal vm pod", addr: "100.64.3.9"},
		{name: "hostNetwork pod", addr: "100.64.3.10"},
		{name: "two live pods claim one address", addr: "100.64.3.11"},
		{name: "no pod", addr: "100.64.3.99"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := vmPodRelayPorts(pods, eps, netip.MustParseAddr(tc.addr))
			if !slices.Equal(got, tc.want) {
				t.Errorf("vmPodRelayPorts(%s) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// TestCredentialNodeName pins the node scoping of the pods informer: a node
// client certificate names its node, any other credential names none.
func TestCredentialNodeName(t *testing.T) {
	t.Parallel()
	certFor := func(cn string) []byte {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	cases := []struct {
		name string
		cfg  *rest.Config
		want string
	}{
		{name: "node certificate", cfg: &rest.Config{TLSClientConfig: rest.TLSClientConfig{CertData: certFor("system:node:worker-1")}}, want: "worker-1"},
		{name: "admin certificate", cfg: &rest.Config{TLSClientConfig: rest.TLSClientConfig{CertData: certFor("system:admin")}}},
		{name: "no certificate", cfg: &rest.Config{BearerToken: "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := credentialNodeName(tc.cfg)
			if err != nil || got != tc.want {
				t.Errorf("credentialNodeName = (%q, %v), want (%q, nil)", got, err, tc.want)
			}
		})
	}
}

// TestRunVMPodInformersFeedsThePredicate wires the informers to a fake
// apiserver and reads the predicate through the synced set, as netd does.
func TestRunVMPodInformersFeedsThePredicate(t *testing.T) {
	t.Parallel()
	pod := netdTestPod("webhook", "100.64.3.7", true, 443)
	cs := fake.NewClientset(pod, netdTestSlice("svc", "100.64.3.7", pod.UID, corev1.ProtocolTCP, 80))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pl, el, err := runVMPodInformers(ctx, cs, "worker", 5*time.Second)
	if err != nil {
		t.Fatalf("runVMPodInformers: %v", err)
	}
	set := &vmPodSet{}
	if got := set.ports(netip.MustParseAddr("100.64.3.7")); got != nil {
		t.Errorf("an unsynced set answered %v, want nil (deny)", got)
	}
	set.install(pl, el)
	if got, want := set.ports(netip.MustParseAddr("100.64.3.7")), []uint16{80, 443}; !slices.Equal(got, want) {
		t.Errorf("ports = %v, want %v", got, want)
	}
}
