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
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/dataroot"
)

// TestServingCertRow pins the apiserver serving-certificate status row: present,
// issued by this server's cluster CA, and in date is ok; an absent, foreign,
// corrupt or expired leaf FAILs with the recovery; an unreadable work dir is
// unknown; and a work dir with no cluster CA (no control plane booted) has no row.
func TestServingCertRow(t *testing.T) {
	const wd = "/var/lib/k3sm/server"
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	other, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	issue := func(t *testing.T, from *certs.CA) []byte {
		t.Helper()
		leaf, _, err := from.IssueServing("kube-apiserver", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return leaf
	}
	caPath, leafPath := certs.ClusterCACertPath(wd), certs.APIServerServingCertPath(wd)
	now := time.Now()
	for _, tc := range []struct {
		name       string
		ca, leaf   []byte
		unreadable bool
		now        time.Time
		wantOK     bool
		state      RowState
		sev        Severity
		detail     string
	}{
		{name: "no cluster CA: no row"},
		{name: "issued by the cluster CA, in date", ca: ca.CertPEM, leaf: issue(t, ca), now: now, wantOK: true, state: StateOK, sev: SeverityOK, detail: "issued by the cluster CA"},
		{name: "absent", ca: ca.CertPEM, now: now, wantOK: true, state: StateAbsent, sev: SeverityFail, detail: leafPath},
		{name: "another CA's leaf", ca: ca.CertPEM, leaf: issue(t, other), now: now, wantOK: true, state: StateCorrupt, sev: SeverityFail, detail: "not issued by this server's cluster CA"},
		{name: "corrupt", ca: ca.CertPEM, leaf: []byte("-----BEGIN CERT"), now: now, wantOK: true, state: StateCorrupt, sev: SeverityFail, detail: "does not parse"},
		{name: "expired", ca: ca.CertPEM, leaf: issue(t, ca), now: now.Add(2 * time.Hour), wantOK: true, state: StateExpired, sev: SeverityFail, detail: "expired"},
		{name: "unreadable as this user", ca: ca.CertPEM, unreadable: true, now: now, wantOK: true, state: StateUnknown, sev: SeverityUnknown, detail: "unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fakeFS{present: map[string]bool{}, contents: map[string][]byte{}, unreadable: map[string]bool{}}
			if tc.ca != nil {
				fsys.present[caPath], fsys.contents[caPath] = true, tc.ca
			}
			if tc.leaf != nil {
				fsys.present[leafPath], fsys.contents[leafPath] = true, tc.leaf
			}
			if tc.unreadable {
				fsys.unreadable[caPath] = true
			}
			c := Collector{FS: fsys, Paths: Paths{WorkDir: wd, ServerLabel: "io.k3sm.server"}}
			row, ok := c.servingCertRow(tc.now)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (row %+v)", ok, tc.wantOK, row)
			}
			if !ok {
				return
			}
			if row.Name != RowServingCert || row.State != tc.state || row.Severity != tc.sev {
				t.Fatalf("row = %s %s %s %q, want %s %s", row.Name, row.State, row.Severity, row.Detail, tc.state, tc.sev)
			}
			if !strings.Contains(row.Detail, tc.detail) {
				t.Errorf("detail %q does not carry %q", row.Detail, tc.detail)
			}
			if row.Severity == SeverityFail {
				if !strings.Contains(row.Remedy, "kickstart -k system/io.k3sm.server") {
					t.Errorf("remedy %q does not name the kickstart recovery", row.Remedy)
				}
			}
		})
	}
}

// TestAdminKubeconfigAnchorRow pins the root-only check of the admin kubeconfig
// install recorded: a match, a mismatch (the old self-signed pin, and skip-verify),
// a missing record, and a non-root run, which never reads the kubeconfig.
func TestAdminKubeconfigAnchorRow(t *testing.T) {
	const (
		wd     = "/var/lib/k3sm/server"
		record = "/Library/Preferences/io.k3sm.server-args.json"
		kube   = "/Users/alice/.kube/config"
	)
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	old, err := certs.NewCA("kube-apiserver-self-signed")
	if err != nil {
		t.Fatal(err)
	}
	kubeconfig := func(tls string) []byte {
		return []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: k3sm\n  cluster:\n    server: https://127.0.0.1:6444\n" + tls +
			"\ncontexts:\n- name: k3sm\n  context:\n    cluster: k3sm\n    user: k3sm\ncurrent-context: k3sm\nusers:\n- name: k3sm\n  user:\n    token: k3sm-tok\n")
	}
	pin := func(pemBytes []byte) string {
		return "    certificate-authority-data: " + base64.StdEncoding.EncodeToString(pemBytes)
	}
	rec := func(path string) []byte {
		raw, err := dataroot.EncodeServerArgsRecord(dataroot.ServerArgsRecord{Version: dataroot.ServerArgsRecordVersion, CreatedBy: "k3sm test", AdminKubeconfig: path})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, tc := range []struct {
		name   string
		euid   int
		record []byte
		kube   []byte
		state  RowState
		sev    Severity
		detail string
	}{
		{name: "match", record: rec(kube), kube: kubeconfig(pin(ca.CertPEM)), state: StateOK, sev: SeverityOK, detail: "admin kubeconfig anchor: cluster CA"},
		{name: "mismatch: the old self-signed pin", record: rec(kube), kube: kubeconfig(pin(old.CertPEM)), state: StateDrift, sev: SeverityWarn, detail: "MISMATCH: re-run sudo k3sm install"},
		{name: "mismatch: skip-verify", record: rec(kube), kube: kubeconfig("    insecure-skip-tls-verify: true"), state: StateDrift, sev: SeverityWarn, detail: "MISMATCH: re-run sudo k3sm install"},
		{name: "missing record", state: StateSkip, sev: SeveritySkip, detail: "not recorded"},
		{name: "record without the path", record: rec(""), state: StateSkip, sev: SeveritySkip, detail: "not recorded"},
		{name: "non-root", euid: 501, record: rec(kube), kube: kubeconfig(pin(ca.CertPEM)), state: StateNeedsAdmin, sev: SeveritySkip, detail: "needs sudo: only root checks the admin kubeconfig"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fakeFS{present: map[string]bool{}, contents: map[string][]byte{}, unreadable: map[string]bool{}}
			caPath := certs.ClusterCACertPath(wd)
			fsys.present[caPath], fsys.contents[caPath] = true, ca.CertPEM
			if tc.record != nil {
				fsys.present[record], fsys.contents[record] = true, tc.record
			}
			if tc.kube != nil {
				fsys.present[kube], fsys.contents[kube] = true, tc.kube
			}
			if tc.euid != 0 {
				// A non-root run must not read the kubeconfig at all.
				fsys.unreadable[kube] = true
			}
			c := Collector{FS: fsys, EUID: tc.euid, Paths: Paths{WorkDir: wd, ServerArgsRecord: record, ServerLabel: "io.k3sm.server", LaunchDaemonDir: "/nonexistent"}}
			row, ok := c.adminKubeconfigAnchorRow()
			if !ok {
				t.Fatal("no row on a server holding a cluster CA")
			}
			if row.Name != RowAdminKubeconfig || row.State != tc.state || row.Severity != tc.sev || !strings.HasPrefix(row.Detail, tc.detail) {
				t.Fatalf("row = %s %s %s %q, want %s %s %q", row.Name, row.State, row.Severity, row.Detail, tc.state, tc.sev, tc.detail)
			}
		})
	}

	t.Run("no cluster CA: no row", func(t *testing.T) {
		fsys := fakeFS{present: map[string]bool{}, contents: map[string][]byte{}}
		for _, euid := range []int{0, 501} {
			if _, ok := (Collector{FS: fsys, EUID: euid, Paths: Paths{WorkDir: wd}}).adminKubeconfigAnchorRow(); ok {
				t.Errorf("euid %d: a row without a cluster CA", euid)
			}
		}
	})
}
