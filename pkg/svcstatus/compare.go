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

package svcstatus

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/proxy"

	"k3sm.io/k3sm/pkg/status"
)

// Comparer is the services row's status.ServicesComparer over a cluster client.
type Comparer struct {
	Client kubernetes.Interface
	// Timeout bounds the two LISTs together; zero leaves ctx as it is.
	Timeout time.Duration
}

// CompareServices lists every Service and EndpointSlice once, uncached
// (ResourceVersion "" is a quorum read, the same read the proxy's own periodic
// check makes), and compares the Ready backends they give each Service port
// with the backends rec says the proxy routes.
func (c Comparer) CompareServices(ctx context.Context, rec status.ServicesRecord) (status.ServicesComparison, error) {
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	svcs, err := c.Client.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{ResourceVersion: ""})
	if err != nil {
		return status.ServicesComparison{}, fmt.Errorf("list services: %w", err)
	}
	eps, err := c.Client.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).List(ctx, metav1.ListOptions{ResourceVersion: ""})
	if err != nil {
		return status.ServicesComparison{}, fmt.Errorf("list endpointslices: %w", err)
	}
	return compare(rec, svcs.Items, eps.Items), nil
}

// compare is CompareServices over listed objects. Pure.
//
// The want side is proxy.APIBackendSets, the one derivation of a Service port's
// Ready backends (the Watcher installs the same sets), so this row and the proxy
// cannot disagree on what Ready means. A Service the server pins is derived by
// the same function from the pinned backends the record carries, never from the
// table itself, so a pinned port that lost its backend, or left the table, is a
// divergence naming the pinned backends. A ClusterIP the proxy leaves to another
// listener (rec.Unproxied) is not compared.
//
// A diverging port is settling, not diverging, when its Service is gone from the
// API or the Service or one of its EndpointSlices changed after the record was
// written: the record cannot have seen that change.
func compare(rec status.ServicesRecord, svcs []corev1.Service, eps []discoveryv1.EndpointSlice) status.ServicesComparison {
	svcPtrs := make([]*corev1.Service, len(svcs))
	owners := make(map[string]*corev1.Service, len(svcs))
	changed := make(map[string]time.Time, len(svcs))
	for i := range svcs {
		s := &svcs[i]
		svcPtrs[i] = s
		key := s.Namespace + "/" + s.Name
		changed[key] = lastChange(s.ObjectMeta, changed[key])
		if s.Spec.ClusterIP != "" {
			owners[s.Spec.ClusterIP] = s
		}
	}
	slicePtrs := make([]*discoveryv1.EndpointSlice, len(eps))
	for i := range eps {
		sl := &eps[i]
		slicePtrs[i] = sl
		if name := sl.Labels[discoveryv1.LabelServiceName]; name != "" {
			key := sl.Namespace + "/" + name
			changed[key] = lastChange(sl.ObjectMeta, changed[key])
		}
	}
	want := proxy.APIBackendSets(svcPtrs, slicePtrs, pinnedEndpoints(rec.Pinned))

	states := make([]proxy.VIPState, 0, len(rec.VIPs))
	recOwner := make(map[proxy.PortKey]status.VIPEntry, len(rec.VIPs))
	for _, e := range rec.VIPs {
		s := vipState(e)
		states = append(states, s)
		recOwner[s.Key()] = e
	}
	have := proxy.BackendSets(states)

	unproxied := make(map[string]bool, len(rec.Unproxied))
	for _, ip := range rec.Unproxied {
		unproxied[ip] = true
	}
	for k := range want {
		if unproxied[k.ClusterIP] {
			delete(want, k)
		}
	}

	var out status.ServicesComparison
	for _, d := range proxy.DiffBackendSets(want, have) {
		pd := status.ServicePortDivergence{Port: d.Key.String(), Missing: d.Missing, Extra: d.Extra}
		inAPI := false
		if s, ok := owners[d.Key.ClusterIP]; ok {
			pd.Namespace, pd.Name, inAPI = s.Namespace, s.Name, true
		} else if e, ok := recOwner[d.Key]; ok {
			pd.Namespace, pd.Name = e.Namespace, e.Name
		}
		if !inAPI || changed[pd.Namespace+"/"+pd.Name].After(rec.UpdatedAt) {
			out.Settling = append(out.Settling, pd)
			continue
		}
		out.Diverging = append(out.Diverging, pd)
	}
	return out
}

// pinnedEndpoints renders the record's pinned Services as the static override
// proxy.APIBackendSets takes, each backend Ready. A backend that does not parse
// is left out, which reads as that backend missing from the table's view.
func pinnedEndpoints(pinned []status.PinnedService) map[string][]netv1.Endpoint {
	if len(pinned) == 0 {
		return nil
	}
	out := make(map[string][]netv1.Endpoint, len(pinned))
	for _, p := range pinned {
		eps := []netv1.Endpoint{}
		for _, b := range p.Backends {
			ap, err := netip.ParseAddrPort(b)
			if err != nil {
				continue
			}
			eps = append(eps, netv1.Endpoint{IP: ap.Addr().String(), Port: int32(ap.Port()), Ready: true})
		}
		out[p.Namespace+"/"+p.Name] = eps
	}
	return out
}

// lastChange returns the latest of since and the object's creation, deletion
// and managed-field write times: when the apiserver last recorded a change to it.
func lastChange(m metav1.ObjectMeta, since time.Time) time.Time {
	latest := since
	bump := func(t time.Time) {
		if t.After(latest) {
			latest = t
		}
	}
	bump(m.CreationTimestamp.Time)
	if m.DeletionTimestamp != nil {
		bump(m.DeletionTimestamp.Time)
	}
	for _, f := range m.ManagedFields {
		if f.Time != nil {
			bump(f.Time.Time)
		}
	}
	return latest
}
