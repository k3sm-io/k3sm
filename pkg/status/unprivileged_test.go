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
	"net/netip"
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
		ServerAnchor: ServerAnchor(6444, nil),
		Paths:        p,
		EUID:         501,
		ServiceUID:   250,
		Now:          func() time.Time { return now },
		Version:      goldenVersion,
		Hostname:     "my-mac",
	}
	rep := c.Collect(context.Background())

	for _, tc := range []struct {
		row    string
		state  RowState
		sev    Severity
		detail string
	}{
		{RowDatastore, StateOK, SeverityOK, DatastoreAnswersDetail},
		{RowServingCert, StateOK, SeverityOK, "issued by the CA your kubeconfig pins, valid until " + leaf.NotAfter.UTC().Format("2006-01-02") + " (read from the TLS handshake)"},
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
// a report reads: the installed admin context, else the current context, and
// either only when it points at the anchored endpoint. A context named k3sm
// is anchored like any other, never trusted by its name.
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
		{"the k3sm context on the joined host wins", cfg("other", map[string]string{"k3sm": "https://192.0.2.50:6444", "other": "https://192.0.2.50:6445"}), "192.0.2.50", "k3sm", true},
		{"a k3sm context pointing at another host yields no context", cfg("k3sm", map[string]string{"k3sm": "https://10.0.0.9:6444"}), "192.0.2.50", "", false},
		{"a k3sm context elsewhere falls to an anchored current context", cfg("lab", map[string]string{"k3sm": "https://10.0.0.9:6444", "lab": "https://192.0.2.50:6444"}), "192.0.2.50", "lab", true},
		{"the current context on the joined host", cfg("lab", map[string]string{"lab": "https://192.0.2.50:6444"}), "192.0.2.50:9345", "lab", true},
		{"a join server given as a URL", cfg("lab", map[string]string{"lab": "https://studio.example:6444"}), "https://Studio.example:9345", "lab", true},
		{"the current context on another cluster", cfg("work", map[string]string{"work": "https://10.0.0.9:6443"}), "192.0.2.50", "", false},
		{"no join server to compare with", cfg("lab", map[string]string{"lab": "https://192.0.2.50:6444"}), "", "", false},
		{"no kubeconfig", nil, "192.0.2.50", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := UserKubeContext(tc.cfg, "k3sm", JoinAnchor(tc.join))
			if got != tc.want || ok != tc.ok {
				t.Errorf("UserKubeContext = %q, %v, want %q, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestServerAnchor pins what proves an endpoint is this server's own control
// plane: a loopback host or one of this Mac's addresses, at the apiserver port.
func TestServerAnchor(t *testing.T) {
	anchor := ServerAnchor(6444, []netip.Addr{netip.MustParseAddr("100.64.0.1")})
	for server, want := range map[string]bool{
		"https://127.0.0.1:6444":  true,
		"https://localhost:6444":  true,
		"https://[::1]:6444":      true,
		"https://100.64.0.1:6444": true,
		"https://127.0.0.1:6443":  false,
		"https://100.64.0.1:443":  false,
		"https://100.64.0.1":      false,
		"https://100.64.0.9:6444": false,
		"https://studio.lan:6444": false,
		"https://192.0.2.50:6444": false,
		"":                        false,
	} {
		if got := anchor(server); got != want {
			t.Errorf("ServerAnchor(%q) = %v, want %v", server, got, want)
		}
	}
}

// TestEndpointsRecordAnchorsTheContext pins the published endpoints record as
// the anchor: a worker that joined over the LAN address while its kubeconfig
// points at the mesh address gets its context once the record names both; a
// host or port outside the record is refused; a missing record falls back to
// the anchor a node without one had.
func TestEndpointsRecordAnchorsTheContext(t *testing.T) {
	kubeconfig := func(server string) *clientcmdapi.Config {
		c := clientcmdapi.NewConfig()
		c.Clusters["k3sm"] = &clientcmdapi.Cluster{Server: server}
		c.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "k3sm"}
		c.CurrentContext = "k3sm"
		return c
	}
	join := JoinAnchor("192.0.2.50")
	rec := &EndpointsRecord{Port: 6444, Hosts: []string{"192.0.2.50", "100.64.0.1", "kubernetes.default.svc"}}

	if _, ok := UserKubeContext(kubeconfig("https://100.64.0.1:6444"), "k3sm", NodeAnchor(nil, join)); ok {
		t.Fatal("without the record the mesh address was accepted; this case proves nothing")
	}
	for _, tc := range []struct {
		name   string
		rec    *EndpointsRecord
		server string
		ok     bool
	}{
		{"the mesh address the record names", rec, "https://100.64.0.1:6444", true},
		{"the join address the record names", rec, "https://192.0.2.50:6444", true},
		{"a DNS SAN the record names", rec, "https://Kubernetes.Default.Svc:6444", true},
		{"a host outside the record", rec, "https://10.0.0.9:6444", false},
		{"a named host outside the record", rec, "https://other.example:6444", false},
		{"the right host on another port", rec, "https://100.64.0.1:6443", false},
		{"a non-default port the record carries", &EndpointsRecord{Port: 7444, Hosts: []string{"127.0.0.1"}}, "https://127.0.0.1:7444", true},
		{"a missing record falls back to the join host", nil, "https://192.0.2.50:6444", true},
		{"a missing record still refuses the mesh address", nil, "https://100.64.0.1:6444", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := UserKubeContext(kubeconfig(tc.server), "k3sm", NodeAnchor(tc.rec, join))
			if ok != tc.ok {
				t.Errorf("context for %s accepted = %v, want %v", tc.server, ok, tc.ok)
			}
		})
	}
	t.Run("a server's record covers its non-default port", func(t *testing.T) {
		anchor := NodeAnchor(&EndpointsRecord{Port: 7444, Hosts: []string{"127.0.0.1", "100.64.0.1"}}, ServerAnchor(6444, nil))
		if !anchor("https://100.64.0.1:7444") || anchor("https://127.0.0.1:6444") {
			t.Error("the server anchor did not follow the record's port")
		}
	})
	t.Run("the record is read from the status directory", func(t *testing.T) {
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		path := EndpointsPath("/var/lib/k3sm/status")
		read := func(p string) ([]byte, error) {
			if p == path {
				return raw, nil
			}
			return nil, errors.New("absent")
		}
		if got := ReadEndpointsRecord(read, path); got == nil || got.Port != 6444 || len(got.Hosts) != 3 {
			t.Errorf("read %+v, want the record", got)
		}
		for name, body := range map[string]string{"garbage": "{", "no port": `{"hosts":["a"]}`, "no hosts": `{"port":6444}`} {
			bad := func(string) ([]byte, error) { return []byte(body), nil }
			if ReadEndpointsRecord(bad, path) != nil {
				t.Errorf("a record with %s was trusted", name)
			}
		}
		if ReadEndpointsRecord(read, "/elsewhere") != nil {
			t.Error("an absent record was read as one")
		}
	})
}
