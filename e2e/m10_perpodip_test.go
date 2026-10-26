//go:build e2e

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

package e2e

import (
	"context"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestM10_PerPodIP is the per-pod-IP criterion (Res.1): two pods on the same
// node each report a DISTINCT status.podIP (a real podnet /32, not podIP≈nodeIP), and
// a headless Service returns ALL backend pod IPs — proving the podnet adapter over
// supervisor.NodeNetwork on the converged runtimed path.
//
// Asserted, per pod: status.podIP is set, is not the node's InternalIP, lies
// inside the node's spec.podCIDR(s), is status.podIPs[0], and equals the
// K3SM_POD_IP the runtime handed the process (the /32 the bind shim pins); the
// two pods' IPs differ. For the headless Service (clusterIP None): its Ready
// EndpointSlice addresses are exactly the two pod IPs, and an in-pod A query of
// <svc>.<ns>.svc.<domain>, sent with /usr/bin/dig to the pod's own
// K3SM_DNS_SERVER, answers exactly those two IPs. The unit-level contracts are
// pkg/provider TestCreatePodAssignsDistinctPodIP and pkg/netserve
// TestHeadlessServiceReturnsAllPodIPs, which hack/acceptance/m10.sh runs beside
// this criterion.
func TestM10_PerPodIP(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	node := m10Node(t, c)
	nodeIP := m10NodeIP(t, c, node)
	ns := m10Namespace(t, c)

	n, err := c.Client.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node %s: %v", node, err)
	}
	cidrs := n.Spec.PodCIDRs
	if len(cidrs) == 0 && n.Spec.PodCIDR != "" {
		cidrs = []string{n.Spec.PodCIDR}
	}
	if len(cidrs) == 0 {
		t.Fatalf("node %s has no spec.podCIDR: per-pod IPs have no node range to be allocated from", node)
	}
	var nets []*net.IPNet
	for _, s := range cidrs {
		_, ipn, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("node %s podCIDR %q: %v", node, s, err)
		}
		nets = append(nets, ipn)
	}

	const app = "m10-ppip"
	const script = `echo "pod_ip=${K3SM_POD_IP:-}"; while :; do sleep 3600; done`
	names := []string{"ppip-a", "ppip-b"}
	for _, name := range names {
		pod := m10PinnedPod(ns, name, node, corev1.RestartPolicyAlways, script)
		pod.Labels["group"] = app
		m10Create(t, c, pod)
	}

	ips := map[string]string{}
	for _, name := range names {
		pod := c.WaitPodReady(t, ns, name, 2*time.Minute)
		ip := pod.Status.PodIP
		if ip == "" {
			t.Fatalf("pod %s/%s is Ready with no status.podIP", ns, name)
		}
		if len(pod.Status.PodIPs) == 0 || pod.Status.PodIPs[0].IP != ip {
			t.Errorf("pod %s: status.podIPs %v does not lead with status.podIP %s", name, pod.Status.PodIPs, ip)
		}
		if ip == nodeIP {
			t.Errorf("pod %s: status.podIP %s is the node InternalIP (podIP≈nodeIP, not a per-pod address)", name, ip)
		}
		parsed := net.ParseIP(ip)
		in := false
		for _, ipn := range nets {
			if parsed != nil && ipn.Contains(parsed) {
				in = true
			}
		}
		if !in {
			t.Errorf("pod %s: status.podIP %s is outside node %s podCIDR %v", name, ip, node, cidrs)
		}
		var inPod string
		pollUntil(30*time.Second, func() bool {
			inPod = m10Line(m10ContainerLogs(c, ns, name, "c"), "pod_ip")
			return inPod != ""
		})
		if inPod != ip {
			t.Errorf("pod %s: in-pod K3SM_POD_IP %q != status.podIP %s (the address the process binds is not the one the API reports)", name, inPod, ip)
		}
		ips[name] = ip
	}
	if ips[names[0]] == ips[names[1]] {
		t.Fatalf("two pods on node %s share status.podIP %s: not per-pod addresses", node, ips[names[0]])
	}
	want := []string{ips[names[0]], ips[names[1]]}
	sort.Strings(want)
	t.Logf("node %s (InternalIP %s, podCIDR %v): pod IPs %v", node, nodeIP, cidrs, want)

	const svc = "ppip-headless"
	if _, err := c.Client.CoreV1().Services(ns).Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: svc, Namespace: ns},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  map[string]string{"group": app},
			Ports:     []corev1.ServicePort{{Name: "web", Port: 18761}},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create headless service: %v", err)
	}

	var got []string
	if !pollUntil(time.Minute, func() bool {
		got = readyEndpointAddrs(t, c, ns, svc)
		sort.Strings(got)
		return strings.Join(got, ",") == strings.Join(want, ",")
	}) {
		t.Fatalf("headless service %s/%s Ready endpoints = %v, want exactly %v", ns, svc, got, want)
	}

	// In-pod A query of the headless name. It retries until the answer holds
	// both addresses (the resolver learns the endpoints asynchronously), and
	// prints every answer it got, so the test reads the final set from the log.
	probe := m10PinnedPod(ns, "ppip-dns", node, corev1.RestartPolicyNever, `
name="`+svc+`.`+ns+`.svc.${K3SM_DNS_DOMAIN:-cluster.local}"
echo "dns_server=${K3SM_DNS_SERVER:-} name=$name"
i=0
while [ $i -lt 30 ]; do
	ans=$(/usr/bin/dig +short +time=2 +tries=1 @"$K3SM_DNS_SERVER" "$name" A | sort | tr '\n' ',')
	echo "answer=$ans"
	case "$ans" in *.*,*.*,) exit 0 ;; esac
	i=$((i+1)); sleep 2
done
exit 1`)
	m10Create(t, c, probe)
	pod := c.WaitPodPhase(t, ns, probe.Name, corev1.PodSucceeded, 2*time.Minute)
	logs := m10ContainerLogs(c, ns, pod.Name, "c")
	answer := strings.TrimSuffix(m10Line(logs, "answer"), ",")
	if answer != strings.Join(want, ",") {
		t.Fatalf("in-pod A query of the headless service answered %q, want exactly %v\n%s", answer, want, logs)
	}
	t.Logf("in-pod headless A answer: %s", answer)
}
