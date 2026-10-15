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
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k3sm.io/darwin-net/pkg/proxy"

	"k3sm.io/k3sm/pkg/status"
)

// settleAllowance is how long before a record's UpdatedAt an API change still
// counts as one the record may not have seen: the proxy applies a watch event
// within a second or so, and the allowance covers that plus clock skew between
// the API's managed-field timestamps and the server's clock.
const settleAllowance = 5 * time.Second

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
// cannot disagree on what Ready means. Two kinds of port are taken out of the
// comparison because the API cannot describe them: a ClusterIP the proxy leaves
// to another listener (rec.Unproxied), and a Service whose backends the server
// pins (VIPEntry.Static).
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
	// No static override is passed: the pinned endpoints live in the server, and
	// the record marks the pinned ports instead (handled below).
	want := proxy.APIBackendSets(svcPtrs, slicePtrs, nil)

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
	for k, e := range recOwner {
		if e.Static {
			want[k] = have[k]
		}
	}

	var out status.ServicesComparison
	cutoff := rec.UpdatedAt.Add(-settleAllowance)
	for _, d := range proxy.DiffBackendSets(want, have) {
		pd := status.ServicePortDivergence{Port: d.Key.String(), Missing: d.Missing, Extra: d.Extra}
		inAPI := false
		if s, ok := owners[d.Key.ClusterIP]; ok {
			pd.Namespace, pd.Name, inAPI = s.Namespace, s.Name, true
		} else if e, ok := recOwner[d.Key]; ok {
			pd.Namespace, pd.Name = e.Namespace, e.Name
		}
		// A port whose Service is gone, or whose Service or slices changed after
		// the record was taken, may simply be newer than the record.
		if !inAPI || !changed[pd.Namespace+"/"+pd.Name].Before(cutoff) {
			out.Settling = append(out.Settling, pd)
			continue
		}
		out.Diverging = append(out.Diverging, pd)
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
