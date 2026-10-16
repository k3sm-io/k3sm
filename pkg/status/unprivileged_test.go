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
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/nodecred"
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

// TestUnprivilegedAgentReadsThroughTheUserKubeconfig is the agent half of the
// gate: on a worker whose node credential this account cannot read, the report
// reads the cluster with the account's own kubeconfig, the way kubectl does,
// so the apiserver, node and workloads rows answer and the kubeconfig row
// names the context it used instead of reporting the credential missing.
func TestUnprivilegedAgentReadsThroughTheUserKubeconfig(t *testing.T) {
	p := agentPaths(t.TempDir())
	fsys := withCredential(t, agentInstalledFS(p), p.AgentCredentialDir, goldenTime.Add(90*24*time.Hour))
	fsys.denied = map[string]bool{filepath.Join(p.AgentCredentialDir, nodecred.KubeconfigFile): true}
	c := agentCollector(t, p, fsys)
	c.EUID = 501
	c.KubeErr = errors.New("node credential /var/lib/k3sm/agent/kubeconfig is not readable by this account (re-run with sudo)")
	source := `/Users/me/.kube/config context "k3sm"`
	builds := 0
	c.UserKube = func() (Kube, string, error) {
		builds++
		kube := healthyKube()
		kube.server = "https://100.64.0.1:6444"
		return kube, source, nil
	}
	rep := c.Collect(context.Background())

	if rep.Role != dataroot.RoleAgent {
		t.Fatalf("role = %s, want agent", rep.Role)
	}
	if builds != 1 {
		t.Errorf("the user's kubeconfig was read %d times, want once", builds)
	}
	for _, tc := range []struct {
		row    string
		state  RowState
		sev    Severity
		detail string
	}{
		{RowAPIServer, StateReady, SeverityOK, "https://100.64.0.1:6444 readyz ok"},
		{RowNode, StateReady, SeverityOK, "1/1 nodes ready · my-mac kubelet v1.36.2"},
		{RowWorkloads, StateOK, SeverityOK, "3 running"},
		{RowKubeconfig, StateOK, SeverityOK, source + " (" + UserKubeNote + ")"},
	} {
		row, ok := rep.Row(tc.row)
		if !ok {
			t.Errorf("no %s row", tc.row)
			continue
		}
		if row.State != tc.state || row.Severity != tc.sev || row.Detail != tc.detail {
			t.Errorf("%s = %s/%s %q, want %s/%s %q", tc.row, row.State, row.Severity, row.Detail, tc.state, tc.sev, tc.detail)
		}
	}
	if kc, _ := rep.Row(RowKubeconfig); kc.Wide["source"] != "user-kubeconfig" {
		t.Errorf("kubeconfig wide = %v, want the user kubeconfig named as the source", kc.Wide)
	}

	t.Run("a readable node credential is used, never the user's kubeconfig", func(t *testing.T) {
		c := agentCollector(t, p, withCredential(t, agentInstalledFS(p), p.AgentCredentialDir, goldenTime.Add(90*24*time.Hour)))
		c.Kube = healthyKube()
		c.UserKube = func() (Kube, string, error) {
			t.Fatal("the user's kubeconfig was read although the node credential answers")
			return nil, "", nil
		}
		c.Collect(context.Background())
	})
	t.Run("a kubeconfig with no usable context leaves the rows as they were", func(t *testing.T) {
		c := agentCollector(t, p, fsys)
		c.EUID = 501
		c.KubeErr = errors.New("node credential is not readable by this account")
		c.UserKube = func() (Kube, string, error) { return nil, "", errors.New("no k3sm context") }
		rep := c.Collect(context.Background())
		if api, _ := rep.Row(RowAPIServer); api.State != StateUnknown || !strings.Contains(api.Detail, "no k3sm context") {
			t.Errorf("apiserver = %s %q, want unknown naming both reasons", api.State, api.Detail)
		}
		if kc, _ := rep.Row(RowKubeconfig); kc.State != StateMissing {
			t.Errorf("kubeconfig = %s, want missing", kc.State)
		}
	})
}

// TestUserKubeContext pins which context of the invoking account's kubeconfig
// an agent's report reads: the installed admin context when there is one, else
// the current context only when it points at the host this Mac joined.
func TestUserKubeContext(t *testing.T) {
	cfg := func(current string, contexts map[string]string) *clientcmdapi.Config {
		c := clientcmdapi.NewConfig()
		c.CurrentContext = current
		for name, server := range contexts {
			c.Clusters[name] = &clientcmdapi.Cluster{Server: server}
			c.Contexts[name] = &clientcmdapi.Context{Cluster: name}
		}
		return c
	}
	for _, tc := range []struct {
		name string
		cfg  *clientcmdapi.Config
		join string
		want string
		ok   bool
	}{
		{"the k3sm context wins", cfg("other", map[string]string{"k3sm": "https://100.64.0.1:6444", "other": "https://192.168.0.50:6444"}), "192.168.0.50", "k3sm", true},
		{"the current context on the joined host", cfg("lab", map[string]string{"lab": "https://192.168.0.50:6444"}), "192.168.0.50:9345", "lab", true},
		{"a join server given as a URL", cfg("lab", map[string]string{"lab": "https://studio.example:6444"}), "https://Studio.example:9345", "lab", true},
		{"the current context on another cluster", cfg("work", map[string]string{"work": "https://10.0.0.9:6443"}), "192.168.0.50", "", false},
		{"no join server to compare with", cfg("lab", map[string]string{"lab": "https://192.168.0.50:6444"}), "", "", false},
		{"no kubeconfig", nil, "192.168.0.50", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := UserKubeContext(tc.cfg, "k3sm", tc.join)
			if got != tc.want || ok != tc.ok {
				t.Errorf("UserKubeContext = %q, %v, want %q, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
