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
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// namespaceServiceLinks returns the service-links environment the kubelet gives
// a pod's containers for the Services in the pod's own namespace, resolved ONCE
// per pod at the translate boundary. It returns nothing when the pod opted out
// (spec.enableServiceLinks false; nil means true, the upstream default) or when
// no apiserver client is configured.
//
// Trade: the kubelet reads Services from an informer; this does one Services
// List per pod translation. That is deliberate at this node's scale (tens of
// pods, not thousands), and it avoids a second cache of every Service on the
// node. Threading the node's existing netserve Service lister in is the named
// follow-up if the List ever shows up as load.
//
// A List failure fails the translation, as the kubelet's own service-env
// lookup does: a pod started without its links would read an absent variable
// as "no such service", which is worse than a retried create.
func namespaceServiceLinks(ctx context.Context, client kubernetes.Interface, pod *corev1.Pod) ([]*runtimev1.EnvVar, error) {
	if client == nil {
		return nil, nil
	}
	if pod.Spec.EnableServiceLinks != nil && !*pod.Spec.EnableServiceLinks {
		return nil, nil
	}
	list, err := client.CoreV1().Services(pod.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services in namespace %s for service links: %w", pod.Namespace, err)
	}
	return serviceLinkEnv(list.Items), nil
}

// serviceLinkEnv renders the kubelet's service environment for services, in a
// deterministic order: services sorted by name, and within a service the
// upstream emission order. It is pure, so the mangling is table-tested apart
// from any client.
//
// A service qualifies iff its ClusterIP is set and is not "None" — upstream's
// IsServiceIPSet, which is independent of spec.type: ClusterIP, NodePort and
// LoadBalancer services all qualify, headless and ExternalName services never
// do. A qualifying service with no ports is skipped (the apiserver rejects one,
// and the variables are defined off its first port).
//
// Per service <SVC> (name uppercased, dashes to underscores):
//
//	<SVC>_SERVICE_HOST             the ClusterIP
//	<SVC>_SERVICE_PORT             the first port
//	<SVC>_SERVICE_PORT_<NAME>      every NAMED port (an unnamed port gets none)
//	<SVC>_PORT                     proto://ip:port of the first port
//	<SVC>_PORT_<p>_<PROTO>         proto://ip:port, per port
//	<SVC>_PORT_<p>_<PROTO>_PROTO   the lowercase protocol, per port
//	<SVC>_PORT_<p>_<PROTO>_PORT    the port, per port
//	<SVC>_PORT_<p>_<PROTO>_ADDR    the ClusterIP, per port
//
// Blast radius: the environment grows with the namespace's Service count, a
// handful of variables per Service. That is upstream-faithful, and it is why
// spec.enableServiceLinks exists.
func serviceLinkEnv(services []corev1.Service) []*runtimev1.EnvVar {
	svcs := make([]*corev1.Service, 0, len(services))
	for i := range services {
		s := &services[i]
		ip := s.Spec.ClusterIP
		if ip == "" || ip == corev1.ClusterIPNone || len(s.Spec.Ports) == 0 {
			continue
		}
		svcs = append(svcs, s)
	}
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Name < svcs[j].Name })

	var out []*runtimev1.EnvVar
	add := func(name, value string) {
		out = append(out, &runtimev1.EnvVar{Name: name, Value: value})
	}
	for _, s := range svcs {
		prefix := envVarName(s.Name)
		ip := s.Spec.ClusterIP
		add(prefix+"_SERVICE_HOST", ip)
		add(prefix+"_SERVICE_PORT", strconv.Itoa(int(s.Spec.Ports[0].Port)))
		for _, p := range s.Spec.Ports {
			if p.Name != "" {
				add(prefix+"_SERVICE_PORT_"+envVarName(p.Name), strconv.Itoa(int(p.Port)))
			}
		}
		for i, p := range s.Spec.Ports {
			proto := string(corev1.ProtocolTCP)
			if p.Protocol != "" {
				proto = string(p.Protocol)
			}
			port := strconv.Itoa(int(p.Port))
			link := strings.ToLower(proto) + "://" + net.JoinHostPort(ip, port)
			if i == 0 {
				// Docker links special-case the first port.
				add(prefix+"_PORT", link)
			}
			portPrefix := prefix + "_PORT_" + port + "_" + strings.ToUpper(proto)
			add(portPrefix, link)
			add(portPrefix+"_PROTO", strings.ToLower(proto))
			add(portPrefix+"_PORT", port)
			add(portPrefix+"_ADDR", ip)
		}
	}
	return out
}

// envVarName mangles a Service or port name into an env-var name the way the
// kubelet does: uppercase, dashes to underscores.
func envVarName(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "-", "_"))
}
