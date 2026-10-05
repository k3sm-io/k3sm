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

	"k3sm.io/darwin-net/pkg/proxy"
)

func netdTestPod(name, ip string, vm bool, ports ...int32) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, UID: types.UID("uid-" + name)},
		Spec:       corev1.PodSpec{NodeName: "worker", Containers: []corev1.Container{{Name: "c", Image: "registry/app:1"}}},
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
// a live vm pod's declared TCP ports plus the TCP ports an EndpointSlice in its
// own namespace targets at it BY UID, and nothing for any other pod or address.
// The slice rows are the security-relevant ones: an endpoint may vouch for a pod
// address only through a Pod TargetRef carrying that pod's UID, so a
// selector-less Service's hand-written slice (no TargetRef), a non-Pod ref, an
// empty UID, another pod's UID or another namespace's slice adds no port.
func TestVMPodRelayPorts(t *testing.T) {
	t.Parallel()
	webhook := netdTestPod("webhook", "100.64.3.7", true, 443)
	terminating := netdTestPod("terminating", "100.64.3.12", true, 80)
	terminating.DeletionTimestamp = &metav1.Time{Time: time.Now()}
	wide := netdTestPod("wide", "100.64.3.13", true)
	for p := int32(1000); p < 1000+int32(proxy.MaxRelayPorts); p++ {
		wide.Spec.Containers[0].Ports = append(wide.Spec.Containers[0].Ports, corev1.ContainerPort{ContainerPort: p})
	}
	atCap := netdTestPod("atcap", "100.64.3.14", true)
	atCap.Spec.Containers[0].Ports = wide.Spec.Containers[0].Ports
	native := netdTestPod("native", "100.64.3.8", false, 80)
	done := netdTestPod("done", "100.64.3.9", true, 80)
	done.Status.Phase = corev1.PodSucceeded
	hostNet := netdTestPod("hostnet", "100.64.3.10", true, 80)
	hostNet.Spec.HostNetwork = true
	twinA := netdTestPod("twin-a", "100.64.3.11", true, 80)
	twinB := netdTestPod("twin-b", "100.64.3.11", true, 81)

	pods := []*corev1.Pod{webhook, native, done, hostNet, twinA, twinB, terminating, wide, atCap}
	selectorless := netdTestSlice("svc-handwritten", "100.64.3.7", "", corev1.ProtocolTCP, 22)
	nonPod := netdTestSlice("svc-nonpod", "100.64.3.7", webhook.UID, corev1.ProtocolTCP, 23)
	nonPod.Endpoints[0].TargetRef.Kind = "Node"
	emptyUID := netdTestSlice("svc-emptyuid", "100.64.3.7", webhook.UID, corev1.ProtocolTCP, 24)
	emptyUID.Endpoints[0].TargetRef.UID = ""
	crossNS := netdTestSlice("svc-otherns", "100.64.3.7", webhook.UID, corev1.ProtocolTCP, 25)
	crossNS.Namespace = "attacker"
	overCap := netdTestSlice("svc-overcap", "100.64.3.13", wide.UID, corev1.ProtocolTCP, 1)
	eps := []*discoveryv1.EndpointSlice{
		netdTestSlice("svc-a", "100.64.3.7", webhook.UID, corev1.ProtocolTCP, 80),
		netdTestSlice("svc-udp", "100.64.3.7", webhook.UID, corev1.ProtocolUDP, 53),
		netdTestSlice("svc-stale", "100.64.3.7", "uid-previous-owner", corev1.ProtocolTCP, 21),
		selectorless, nonPod, emptyUID, crossNS, overCap,
		netdTestSlice("svc-native", "100.64.3.8", native.UID, corev1.ProtocolTCP, 26),
	}

	cases := []struct {
		name string
		addr string
		want []uint16
	}{
		// Only svc-a vouches: the hand-written, non-Pod, empty-UID, stale-UID and
		// cross-namespace slices all name this /32 and add nothing (21-25 absent).
		{name: "vm pod: declared plus Service-targeted TCP, by UID and namespace only", addr: "100.64.3.7", want: []uint16{80, 443}},
		{name: "terminating vm pod", addr: "100.64.3.12"},
		{name: "port set over the relay ceiling", addr: "100.64.3.13"},
		{name: "native pod", addr: "100.64.3.8"},
		{name: "terminal vm pod", addr: "100.64.3.9"},
		{name: "hostNetwork pod", addr: "100.64.3.10"},
		{name: "two live pods claim one address", addr: "100.64.3.11"},
		{name: "no pod", addr: "100.64.3.99"},
	}
	if got := vmPodRelayPorts(pods, eps, netip.MustParseAddr("100.64.3.14")); len(got) != proxy.MaxRelayPorts {
		t.Errorf("a port set exactly at the ceiling = %d ports, want %d (the cap is inclusive)", len(got), proxy.MaxRelayPorts)
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
	// The cached pod is the trimmed one: the predicate's fields survive, the rest
	// does not.
	cached, err := pl.ByIndex(podIPIndex, "100.64.3.7")
	if err != nil || len(cached) != 1 {
		t.Fatalf("pods indexed under 100.64.3.7 = %v, %v; want exactly the webhook pod", cached, err)
	}
	if cp := cached[0].(*corev1.Pod); cp.UID != pod.UID || len(cp.Spec.Containers[0].Ports) != 1 || cp.Spec.Containers[0].Image != "" {
		t.Errorf("cached pod not trimmed to the predicate's fields: %+v", cp.Spec.Containers[0])
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
