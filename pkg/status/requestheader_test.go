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

package status

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/certs"
)

// TestRequestHeaderRow pins the request-header status row: the HA role read from the
// installed arguments, this server's pin, and the cluster's trusted count, with a
// WARN for a second root, a foreign root, or an HA server holding none.
func TestRequestHeaderRow(t *testing.T) {
	const wd = "/var/lib/k3sm/server"
	caA, err := certs.NewCA("k3sm-request-header-ca")
	if err != nil {
		t.Fatal(err)
	}
	caB, err := certs.NewCA("k3sm-request-header-ca")
	if err != nil {
		t.Fatal(err)
	}
	cm := func(pems ...[]byte) []byte {
		var bundle []byte
		for _, p := range pems {
			bundle = append(bundle, p...)
		}
		b, err := json.Marshal(corev1.ConfigMap{Data: map[string]string{"requestheader-client-ca-file": string(bundle)}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	path := certs.RequestHeaderCACertPath(wd)
	join := []string{"--server-join", "--server", "192.0.2.10", "--etcd-peer-ip", "192.0.2.11"}
	initArgs := []string{"--cluster-init", "--etcd-peer-ip", "192.0.2.10"}
	for _, tc := range []struct {
		name       string
		args       []string
		local      []byte // nil: no CA file
		unreadable bool
		cmBody     []byte
		cmErr      error
		serving    bool
		wantOK     bool
		sev        Severity
		state      RowState
		detail     []string
		role       string
	}{
		{name: "single server without the CA: no row", args: nil},
		{name: "single server, one trusted, its own", local: caA.CertPEM, cmBody: cm(caA.CertPEM), serving: true,
			wantOK: true, sev: SeverityOK, state: StateOK, role: "mint-authority", detail: []string{"1 trusted", caA.PinHash()[:16]}},
		{name: "mint authority, count not read", args: initArgs, local: caA.CertPEM, serving: false,
			wantOK: true, sev: SeverityOK, state: StateOK, role: "mint-authority", detail: []string{"trusted count not read"}},
		{name: "joined, two trusted: a second root", args: join, local: caA.CertPEM, cmBody: cm(caA.CertPEM, caB.CertPEM), serving: true,
			wantOK: true, sev: SeverityWarn, state: StateOK, role: "joined", detail: []string{"2 request-header CAs trusted", "second impersonation root"}},
		{name: "joined, trusted is another server's", args: join, local: caA.CertPEM, cmBody: cm(caB.CertPEM), serving: true,
			wantOK: true, sev: SeverityWarn, state: StateOK, role: "joined", detail: []string{"not this server's"}},
		{name: "joined, no CA yet", args: join, serving: true,
			wantOK: true, sev: SeverityWarn, state: StateAbsent, role: "joined", detail: []string{"no request-header CA on this server"}},
		{name: "unreadable as this user", args: initArgs, local: caA.CertPEM, unreadable: true,
			wantOK: true, sev: SeverityUnknown, state: StateUnknown, role: "mint-authority", detail: []string{"unreadable"}},
		{name: "ConfigMap unreadable", args: initArgs, local: caA.CertPEM, cmErr: errors.New("forbidden"), serving: true,
			wantOK: true, sev: SeverityOK, state: StateOK, detail: []string{"trusted count not read"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fakeFS{present: map[string]bool{}, contents: map[string][]byte{}, unreadable: map[string]bool{}}
			if tc.local != nil {
				fsys.present[path] = true
				fsys.contents[path] = tc.local
			}
			if tc.unreadable {
				fsys.unreadable[path] = true
			}
			kube := fakeKube{raw: map[string][]byte{extensionAuthConfigMapPath: tc.cmBody}, rawErr: map[string]error{}}
			if tc.cmErr != nil {
				kube.rawErr[extensionAuthConfigMapPath] = tc.cmErr
			}
			c := Collector{FS: fsys, Kube: kube, Paths: Paths{WorkDir: wd}}
			row, ok := c.requestHeaderRow(context.Background(), tc.args, tc.serving)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (row %+v)", ok, tc.wantOK, row)
			}
			if !ok {
				return
			}
			if row.Name != RowRequestHeader || row.Severity != tc.sev || row.State != tc.state {
				t.Fatalf("row = %s %s %s %q, want %s %s", row.Name, row.State, row.Severity, row.Detail, tc.state, tc.sev)
			}
			for _, want := range tc.detail {
				if !strings.Contains(row.Detail, want) {
					t.Errorf("detail %q does not carry %q", row.Detail, want)
				}
			}
			if tc.role != "" && row.Wide["ha-role"] != tc.role {
				t.Errorf("ha-role = %q, want %q", row.Wide["ha-role"], tc.role)
			}
		})
	}
}
