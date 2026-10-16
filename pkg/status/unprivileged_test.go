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
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// TestUnprivilegedStatusReadsWhatTheUserCan is the gate for an ordinary
// account's report on a server, the posture the macOS app runs `k3sm status`
// in. It reads what kubectl can: the datastore through the apiserver's
// readiness check, the serving certificate from the TLS handshake, the
// mesh-claim and Service proxy records from the user-readable status directory.
// Only the runtime daemon's owner-only socket truly needs root, and that row
// says needs-admin, never unknown. The work-dir files are all unreadable, and
// the verdict is running.
func TestUnprivilegedStatusReadsWhatTheUserCan(t *testing.T) {
	now := time.Now()
	wd := unreadableWorkDir(t)
	p := testPaths(wd)
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	leaf := handshakeLeaf(t, ca, 24*time.Hour)
	encode := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	claims, services := MeshClaimsPath(wd), ServicesPath(wd)

	fsys := installedFS(p)
	fsys.present[certs.ClusterCACertPath(wd)] = true
	fsys.present[Dir(wd)] = true
	fsys.unreadable = map[string]bool{
		certs.ClusterCACertPath(wd):        true,
		certs.APIServerServingCertPath(wd): true,
		claims:                             true,
		services:                           true,
	}
	fsys.contents = map[string][]byte{
		UserReadablePath(wd, claims):   encode(MeshClaimsRecord{UpdatedAt: now.Add(-time.Minute)}),
		UserReadablePath(wd, services): encode(ServicesRecord{UpdatedAt: now.Add(-10 * time.Second), VIPs: []VIPEntry{{ClusterIP: "10.43.0.1", Port: 443, Protocol: "TCP"}}}),
	}
	kube := healthyKube()
	kube.raw["/readyz?verbose"] = []byte("[+]ping ok\n[+]etcd ok\nreadyz check passed")
	calls := 0
	c := Collector{
		Launchd: fakeLaunchd{out: map[string][]byte{
			p.NetdLabel:   fixture(t, "launchctl_netd_running.txt"),
			p.ServerLabel: fixture(t, "launchctl_netd_running.txt"),
		}},
		FS:         fsys,
		Kube:       kube,
		KubeSource: `~/.kube/config context "k3sm"`,
		Procs:      fakeProcs{live: LivenessRunning},
		Runtimed:   fatalRuntimed{t: t},
		DataRoot:   fakeDataRootFS{dir: p.DataRoot, mode: 0o755, uid: 0, mounted: true},
		Services:   fakeServicesComparer{calls: &calls},
		ServingChain: func(context.Context) (PresentedChain, error) {
			return PresentedChain{Server: kube.server, Host: "127.0.0.1", Chain: []*x509.Certificate{leaf}, CA: ca.CertPEM}, nil
		},
		Paths:      p,
		EUID:       501,
		ServiceUID: 250,
		Now:        func() time.Time { return now },
		Version:    goldenVersion,
		Hostname:   "my-mac",
	}
	rep := c.Collect(context.Background())

	for _, tc := range []struct {
		row    string
		state  RowState
		sev    Severity
		detail string
	}{
		{RowDatastore, StateOK, SeverityOK, DatastoreAnswersDetail},
		{RowServingCert, StateOK, SeverityOK, "issued by the cluster CA, valid until " + leaf.NotAfter.UTC().Format("2006-01-02") + " (read from the TLS handshake)"},
		{RowMeshClaims, StateOK, SeverityOK, "no abandoned pod-range claims"},
		{RowServices, StateOK, SeverityOK, "1 Service port(s) route to the API's Ready endpoints"},
		{RowRuntimed, StateNeedsAdmin, SeveritySkip, RuntimedNeedsAdminDetail},
		{RowAdminKubeconfig, StateNeedsAdmin, SeveritySkip, "needs sudo: only root checks the admin kubeconfig"},
	} {
		row, ok := rep.Row(tc.row)
		if !ok {
			t.Errorf("no %s row\n%s", tc.row, Render(rep, Style{}))
			continue
		}
		if row.State != tc.state || row.Severity != tc.sev || !strings.HasPrefix(row.Detail, tc.detail) {
			t.Errorf("%s = %s/%s %q, want %s/%s %q", tc.row, row.State, row.Severity, row.Detail, tc.state, tc.sev, tc.detail)
		}
		if row.State == StateUnknown {
			t.Errorf("%s is unknown although this account can read it another way", tc.row)
		}
	}
	if rt, _ := rep.Row(RowRuntimed); rt.Remedy != "sudo k3sm status" {
		t.Errorf("runtimed remedy = %q, want the sudo report", rt.Remedy)
	}
	if mc, _ := rep.Row(RowMeshClaims); mc.Wide["record"] != UserReadablePath(wd, claims) {
		t.Errorf("mesh-claims read %q, want the user-readable copy", mc.Wide["record"])
	}
	if calls != 1 {
		t.Errorf("the services comparer ran %d times, want once against the user-readable record", calls)
	}
	if rep.Verdict != VerdictRunning {
		t.Errorf("verdict = %v (%s), want running: a needs-admin row never degrades it\n%s", rep.Verdict, rep.Summary, Render(rep, Style{}))
	}
}
