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
	"reflect"
	"slices"
	"testing"
	"time"

	"k3sm.io/darwin-net/pkg/proxy"

	"k3sm.io/k3sm/pkg/status"
)

// TestRecordConvertsTheTable pins Record: every entry carries over, a nil
// backend list becomes empty, and the pinned Services land sorted with their
// backends.
func TestRecordConvertsTheTable(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.FixedZone("x", 3600))
	rec := Record([]proxy.VIPState{
		{ClusterIP: "10.43.0.1", Port: 443, Protocol: "TCP", Namespace: "default", Name: "kubernetes", Policy: "Cluster", Backends: []string{"127.0.0.1:6443"}, LocalBackends: 1, Generation: 3},
		{ClusterIP: "10.43.0.20", Port: 80, Protocol: "UDP", Namespace: "web", Name: "front", Policy: "Local"},
	}, map[string][]string{"web/pinned": {"127.0.0.1:2", "127.0.0.1:1"}, "default/kubernetes": {"127.0.0.1:6443"}}, []string{"10.43.0.10"}, now)
	if !rec.UpdatedAt.Equal(now) || rec.UpdatedAt.Location() != time.UTC {
		t.Errorf("UpdatedAt = %v, want %v in UTC", rec.UpdatedAt, now)
	}
	want := []status.VIPEntry{
		{ClusterIP: "10.43.0.1", Port: 443, Protocol: "TCP", Namespace: "default", Name: "kubernetes", Policy: "Cluster", Backends: []string{"127.0.0.1:6443"}, LocalBackends: 1, Generation: 3},
		{ClusterIP: "10.43.0.20", Port: 80, Protocol: "UDP", Namespace: "web", Name: "front", Policy: "Local", Backends: []string{}},
	}
	if !reflect.DeepEqual(rec.VIPs, want) {
		t.Errorf("VIPs = %+v, want %+v", rec.VIPs, want)
	}
	wantPinned := []status.PinnedService{
		{Namespace: "default", Name: "kubernetes", Backends: []string{"127.0.0.1:6443"}},
		{Namespace: "web", Name: "pinned", Backends: []string{"127.0.0.1:1", "127.0.0.1:2"}},
	}
	if !reflect.DeepEqual(rec.Pinned, wantPinned) {
		t.Errorf("Pinned = %+v, want %+v", rec.Pinned, wantPinned)
	}
	if !slices.Equal(rec.Unproxied, []string{"10.43.0.10"}) {
		t.Errorf("Unproxied = %v", rec.Unproxied)
	}
}

// TestVIPEntryMatchesVIPState pins field parity between the record's entry and
// the proxy's type: the two have the same exported fields with the same types
// and JSON tags, and a fully populated VIPState survives the round trip through
// the record. A field added to proxy.VIPState fails here until the record
// carries it.
func TestVIPEntryMatchesVIPState(t *testing.T) {
	pt, et := reflect.TypeFor[proxy.VIPState](), reflect.TypeFor[status.VIPEntry]()
	fields := func(t reflect.Type) map[string]reflect.StructField {
		out := map[string]reflect.StructField{}
		for f := range t.Fields() {
			if f.IsExported() {
				out[f.Name] = f
			}
		}
		return out
	}
	pf, ef := fields(pt), fields(et)
	for name, f := range pf {
		g, ok := ef[name]
		if !ok {
			t.Errorf("status.VIPEntry has no field %s (proxy.VIPState.%s %s)", name, name, f.Type)
			continue
		}
		if g.Type != f.Type || g.Tag.Get("json") != f.Tag.Get("json") {
			t.Errorf("field %s: VIPEntry %s %q, VIPState %s %q", name, g.Type, g.Tag.Get("json"), f.Type, f.Tag.Get("json"))
		}
	}
	for name := range ef {
		if _, ok := pf[name]; !ok {
			t.Errorf("status.VIPEntry.%s has no counterpart in proxy.VIPState", name)
		}
	}

	var in proxy.VIPState
	v := reflect.ValueOf(&in).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString(pt.Field(i).Name)
		case reflect.Int, reflect.Int32, reflect.Int64:
			f.SetInt(int64(i + 1))
		case reflect.Uint, reflect.Uint32, reflect.Uint64:
			f.SetUint(uint64(i + 1))
		case reflect.Slice:
			if f.Type().Elem().Kind() != reflect.String {
				t.Fatalf("field %s: no filler for %s", pt.Field(i).Name, f.Type())
			}
			f.Set(reflect.ValueOf([]string{"10.0.0.1:1", "10.0.0.2:2"}).Convert(f.Type()))
		default:
			t.Fatalf("field %s: no filler for kind %s; extend this test", pt.Field(i).Name, f.Kind())
		}
	}
	if out := vipState(vipEntry(in)); !reflect.DeepEqual(out, in) {
		t.Errorf("round trip = %+v, want %+v", out, in)
	}
}
