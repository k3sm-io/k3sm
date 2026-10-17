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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/registrysvc"
	"k3sm.io/k3sm/pkg/shadow"
)

// alertCase is one failure path of one row: build returns the row the real
// builder produces for it, through the same fakes the row's own tests use, and
// the context the alert is attached in.
type alertCase struct {
	name  string
	build func(t *testing.T) (Row, alertContext)
}

// server is the alert context of a control-plane Mac at the golden clock.
var serverCtx = alertContext{now: goldenTime, role: dataroot.RoleServer}

// fromScenario is the named row of a contract scenario's full report, which is
// how the daemon, credential and not-installed postures are driven: those
// collectors already describe them end to end.
func fromScenario(scenario, row string) func(t *testing.T) (Row, alertContext) {
	return func(t *testing.T) (Row, alertContext) {
		t.Helper()
		sc, ok := contractScenarios()[scenario]
		if !ok {
			t.Fatalf("no contract scenario %q", scenario)
		}
		rep := sc.collector(t).Collect(context.Background())
		r, ok := rep.Row(row)
		if !ok {
			t.Fatalf("scenario %s has no %s row", scenario, row)
		}
		return r, alertContext{now: rep.Timestamp, role: rep.Role, stopped: rep.StoppedBy}
	}
}

// built wraps a builder that needs no alert context beyond a server's.
func built(f func(t *testing.T) Row) func(t *testing.T) (Row, alertContext) {
	return func(t *testing.T) (Row, alertContext) { return f(t), serverCtx }
}

// launchdRow is the daemon row launchd's canned output describes.
func launchdRow(t *testing.T, name, fixtureName string, procs Liveness) Row {
	t.Helper()
	p := testPaths(t.TempDir())
	label := p.ServerLabel
	if name == RowNetd {
		label = p.NetdLabel
	}
	c := Collector{Launchd: fakeLaunchd{out: map[string][]byte{label: fixture(t, fixtureName)}},
		FS: installedFS(p), Procs: fakeProcs{live: procs}, Paths: p}
	r, _ := c.daemonRow(name, label, p.ServerLog, name == RowServer)
	return r
}

// parkedServer is a running server row folded with a crash record.
func parkedServer(t *testing.T, rec executor.CrashRecord) Row {
	t.Helper()
	r := launchdRow(t, RowServer, "launchctl_netd_running.txt", LivenessRunning)
	applyCrashLoop(&r, ClassifyCrashLoop(rec, nil, "/var/lib/k3sm/server/crashloop.json", goldenTime))
	return r
}

// crashes is n crashes of component inside the window, ending at the golden clock.
func crashes(n int, component, origin string) []executor.Crash {
	out := make([]executor.Crash, 0, n)
	for i := n; i > 0; i-- {
		out = append(out, executor.Crash{At: goldenTime.Add(-time.Duration(i) * time.Second), Component: component, Origin: origin})
	}
	return out
}

func tripped() *time.Time {
	at := goldenTime.Add(-time.Second)
	return &at
}

// alertCases is every warn, fail, unknown and needs-admin path of every row.
func alertCases() []alertCase {
	const wd = "/var/lib/k3sm/server"
	now := goldenTime
	ca, caErr := certs.NewCA("k3sm-cluster-ca")
	other, otherErr := certs.NewCA("k3sm-cluster-ca")
	issue := func(t *testing.T, from *certs.CA) []byte {
		t.Helper()
		if caErr != nil || otherErr != nil {
			t.Fatal(caErr, otherErr)
		}
		leaf, _, err := from.IssueServing("kube-apiserver", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return leaf
	}
	caPath, leafPath := certs.ClusterCACertPath(wd), certs.APIServerServingCertPath(wd)
	servingFile := func(leaf func(t *testing.T) []byte, caPEM func() []byte, unreadable bool, at time.Time) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			fsys := fakeFS{present: map[string]bool{caPath: true}, contents: map[string][]byte{caPath: caPEM()}, unreadable: map[string]bool{}}
			if leaf != nil {
				fsys.present[leafPath], fsys.contents[leafPath] = true, leaf(t)
			}
			if unreadable {
				fsys.unreadable[caPath] = true
			}
			r, _ := Collector{FS: fsys, Paths: Paths{WorkDir: wd, ServerLabel: "io.k3sm.server"}}.servingCertRow(context.Background(), at)
			return r
		}
	}
	handshake := func(host string, pinned func() []byte, leafFrom func() *certs.CA, at time.Time, fail bool) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			fsys := fakeFS{present: map[string]bool{caPath: true}, unreadable: map[string]bool{caPath: true, leafPath: true}}
			chain := func(context.Context) (PresentedChain, error) {
				if fail {
					return PresentedChain{}, errors.New("connection refused")
				}
				return PresentedChain{Server: "https://" + host + ":6444", Host: host, Chain: []*x509Cert{handshakeLeaf(t, leafFrom(), time.Hour)}, CA: pinned()}, nil
			}
			c := Collector{FS: fsys, ServingChain: chain, Paths: Paths{WorkDir: wd, ServerLabel: "io.k3sm.server"},
				ServerAnchor: ServerAnchor(6444, []netip.Addr{netip.MustParseAddr("100.64.0.9")})}
			r, _ := c.servingCertRow(context.Background(), at)
			return r
		}
	}
	caPEM := func() []byte { return ca.CertPEM }
	noCA := func() []byte { return nil }
	theCA := func() *certs.CA { return ca }
	otherCA := func() *certs.CA { return other }

	etcd := func(edit func(*executor.EtcdStatus)) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			st := healthyEtcd(now)
			edit(&st)
			p99 := 0.004
			return etcdRowFrom(st, &p99, now)
		}
	}
	etcdFile := func(fsys fakeFS) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			r, _ := Collector{FS: fsys, Paths: Paths{WorkDir: wd}}.etcdRow(context.Background(), []string{"--cluster-init"})
			return r
		}
	}
	update := func(rec UpdateRecord) func(t *testing.T) Row {
		return func(t *testing.T) Row { return UpdateRowFrom(rec, now) }
	}
	updateFile := func(fsys fakeFS) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			r, _ := Collector{FS: fsys, Paths: Paths{WorkDir: wd}, EUID: 501, ServiceUID: 250}.updateRow(now)
			return r
		}
	}
	services := func(fsys fakeFS, serving bool, cmp ServicesComparison, err error) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			calls := 0
			r, _ := Collector{FS: fsys, Paths: Paths{WorkDir: wd}, Services: fakeServicesComparer{cmp: cmp, err: err, calls: &calls}}.servicesRow(context.Background(), serving, now)
			return r
		}
	}
	servicesRec := func(t *testing.T, at time.Time) []byte {
		b, err := json.Marshal(ServicesRecord{UpdatedAt: at})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	diverging := ServicePortDivergence{Namespace: "web", Name: "front", Port: "10.43.0.20:80/TCP", Missing: []string{"100.64.0.9:8080"}}
	registry := func(st registrysvc.State, probe error) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			st.Port, st.Since = 5000, now.Add(-time.Hour)
			return ingestRegistryRowFrom(st, probe, "k3sm status logs server\nsudo launchctl kickstart -k system/io.k3sm.server")
		}
	}
	registryFile := func(fsys fakeFS) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			c := Collector{FS: fsys, Paths: Paths{WorkDir: wd, LaunchDaemonDir: "/nonexistent", ServerLabel: "io.k3sm.server"},
				ServerArgs: func([]byte) ([]string, error) { return []string{"--registry-port", "5000"}, nil }}
			fsys.contents[filepath.Join("/nonexistent", "io.k3sm.server.plist")] = []byte("x")
			r, _ := c.ingestRegistryRow(context.Background(), dataroot.RoleServer)
			return r
		}
	}
	meshFile := func(fsys fakeFS) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			r, _ := Collector{FS: fsys, Paths: Paths{WorkDir: wd}}.meshClaimsRow(now)
			return r
		}
	}
	reqHeader := func(local []byte, unreadable bool, trusted ...[]byte) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			path := certs.RequestHeaderCACertPath(wd)
			fsys := fakeFS{present: map[string]bool{}, contents: map[string][]byte{}, unreadable: map[string]bool{}}
			if local != nil {
				fsys.present[path], fsys.contents[path] = true, local
			}
			if unreadable {
				fsys.unreadable[path] = true
			}
			var bundle []byte
			for _, p := range trusted {
				bundle = append(bundle, p...)
			}
			cm, _ := json.Marshal(corev1.ConfigMap{Data: map[string]string{"requestheader-client-ca-file": string(bundle)}})
			c := Collector{FS: fsys, Kube: fakeKube{raw: map[string][]byte{extensionAuthConfigMapPath: cm}}, Paths: Paths{WorkDir: wd}}
			r, _ := c.requestHeaderRow(context.Background(), []string{"--server-join", "--server", "192.0.2.10", "--etcd-peer-ip", "192.0.2.11"}, true)
			return r
		}
	}
	rhA, rhAErr := certs.NewCA("k3sm-request-header-ca")
	rhB, rhBErr := certs.NewCA("k3sm-request-header-ca")
	rh := func(c *certs.CA) []byte {
		if rhAErr != nil || rhBErr != nil {
			return nil
		}
		return c.CertPEM
	}
	const manifest = "/Library/k3sm/shadow/sources.json"
	shadowRow := func(fsys fakeFS, live map[string]string) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			c := Collector{FS: fsys, CDHash: func(p string) (string, error) { return live[p], nil }, Paths: Paths{ShadowManifest: manifest}}
			r, _ := c.shadowShellsRow()
			return r
		}
	}
	shadowManifest := func(t *testing.T) []byte {
		b, err := shadow.Encode(shadow.Manifest{Version: shadow.ManifestVersion, Sources: []shadow.Source{{Name: "bash", Path: "/bin/bash", CDHash: "aa"}}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	resolver := func(present bool, err error, netd Row) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			c := Collector{FS: fakeFS{present: map[string]bool{"/var/lib/k3sm/run/netd.sock": true}}, Paths: Paths{NetdSocket: "/var/lib/k3sm/run/netd.sock"},
				NodeResolverPresent: func() (bool, error) { return present, err }}
			r, _ := c.nodeResolverRow(netd)
			return r
		}
	}
	netdUp := Row{Name: RowNetd, State: StateRunning, Severity: SeverityOK}
	dnsRow := func(q *fakeDNS, args func(dataroot.Role) ([]string, error)) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			r, _ := Collector{DNS: q, NodeArgs: args, Paths: testPaths(contractWorkDir)}.dnsRow(context.Background(), dataroot.RoleServer, true, Row{Name: RowServer, State: StateRunning})
			return r
		}
	}
	runtimedRow := func(info *runtimev1.GetRuntimeInfoResponse, err error) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			return Collector{Runtimed: fakeRuntimed{info: info, err: err}, EUID: 0, ServiceUID: 250, Paths: testPaths(wd)}.runtimedRow(context.Background(), dataroot.RoleServer)
		}
	}
	kubeDown := fakeKube{rawErr: map[string]error{"/readyz": errors.New("dial tcp 100.64.0.1:6444: connect: connection refused")}, server: "https://100.64.0.1:6444"}
	notReadyNode := func(name string) corev1.Node {
		n := readyNode(name)
		n.Status.Conditions[0].Status = corev1.ConditionFalse
		n.Status.Conditions[0].LastTransitionTime = metav1.NewTime(now.Add(-time.Hour))
		return n
	}
	terminating := func(node string) corev1.Pod {
		p := podIn(corev1.PodRunning)
		p.Namespace, p.Name, p.Spec.NodeName = "default", "web-0", node
		del := metav1.NewTime(now.Add(-time.Hour))
		p.DeletionTimestamp = &del
		return p
	}
	workloads := func(k fakeKube) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			return Collector{Kube: k}.workloadsRow(context.Background(), true, 0, k.nodes, nil, now)
		}
	}
	dataRoot := func(d DataRootFS, euid, serviceUID int) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			p := testPaths(wd)
			r, _ := Collector{DataRoot: d, Paths: p, EUID: euid, ServiceUID: serviceUID}.dataRootRow(context.Background(), dataroot.RoleServer)
			return r
		}
	}
	preVolume := func(euid int, readable bool) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			dir := "/var/lib/k3sm"
			pre := dir + ".pre-volume"
			d := fakeDataRootFS{dir: dir, mode: 0o755, mounted: true, files: map[string]fakeFileInfo{
				pre: {name: ".pre-volume", mode: fs.ModeDir | 0o750, mod: now.Add(-50 * time.Hour)},
			}}
			if readable {
				d.tree = map[string][]fakeFileInfo{pre: {{name: "state.db", size: 4096}}}
			}
			r, _ := Collector{DataRoot: d, Paths: Paths{DataRoot: dir}, EUID: euid, Now: func() time.Time { return now }}.preVolumeRow()
			return r
		}
	}
	apiReady := Row{Name: RowAPIServer, State: StateReady, Wide: map[string]string{"server": "https://10.0.0.9:6444"}}
	throughAPI := func(api Row, anchored bool) func(t *testing.T) Row {
		return func(t *testing.T) Row {
			r := Row{Name: RowDatastore, Wide: map[string]string{"path": executor.StateDBPath(wd)}}
			datastoreThroughAPIServer(&r, api, anchored)
			return r
		}
	}
	agentCtx := alertContext{now: now, role: dataroot.RoleAgent}

	return []alertCase{
		// install
		{"install absent", fromScenario("not-installed", RowInstall)},
		{"install partial", built(func(t *testing.T) Row {
			p := testPaths(wd)
			fsys := installedFS(p)
			fsys.links = nil
			r, _ := Collector{FS: fsys, Paths: p}.installRow(false, dataroot.RoleServer, false)
			return r
		})},
		// the daemons, as launchd describes them
		{"netd not loaded", fromScenario("not-installed", RowNetd)},
		{"server not loaded", fromScenario("not-installed", RowServer)},
		{"netd failed", fromScenario("stopped-clean", RowNetd)},
		{"server stopped", fromScenario("stopped-clean", RowServer)},
		{"server stopped by the user", fromScenario("stopped-by-user", RowServer)},
		{"server crash-looping in launchd", fromScenario("stopped-crashloop", RowServer)},
		{"server disabled", fromScenario("stopped-disabled", RowServer)},
		{"netd process gone", fromScenario("degraded", RowNetd)},
		{"server process gone", fromScenario("degraded", RowServer)},
		{"netd launchd unreadable", fromScenario("unknown", RowNetd)},
		{"server launchd unreadable", fromScenario("unknown", RowServer)},
		{"server not probed", built(func(t *testing.T) Row {
			r, _ := Collector{Paths: testPaths(wd)}.daemonRow(RowServer, "io.k3sm.server", "", true)
			return r
		})},
		{"netd disabled", built(func(t *testing.T) Row { return launchdRow(t, RowNetd, "launchctl_disabled.txt", LivenessRunning) })},
		// the crash-loop record and the staged control plane
		{"server parked on crashes", built(func(t *testing.T) Row {
			return parkedServer(t, executor.CrashRecord{Crashes: crashes(executor.CrashLoopThreshold, "kube-apiserver", ""), TrippedAt: tripped()})
		})},
		{"server parked, never came up", built(func(t *testing.T) Row {
			return parkedServer(t, executor.CrashRecord{Crashes: crashes(executor.CrashLoopThreshold, "kine", executor.CrashOriginBringUp), TrippedAt: tripped()})
		})},
		{"server parked on a permanent fault", built(func(t *testing.T) Row {
			c := crashes(1, "kine", executor.CrashOriginBringUp)
			c[0].Permanent, c[0].Remedy = true, "install the Go toolchain"
			return parkedServer(t, executor.CrashRecord{Crashes: c, TrippedAt: tripped()})
		})},
		{"server parked on leader-lease loss", built(func(t *testing.T) Row {
			return parkedServer(t, executor.CrashRecord{Crashes: crashes(executor.LeaderLostThreshold, "kube-scheduler", executor.CrashOriginLeaderLost), TrippedAt: tripped()})
		})},
		{"server restarting", built(func(t *testing.T) Row {
			return parkedServer(t, executor.CrashRecord{Crashes: crashes(2, "kube-apiserver", "")})
		})},
		{"server losing its lease", built(func(t *testing.T) Row {
			return parkedServer(t, executor.CrashRecord{Crashes: crashes(2, "kube-scheduler", executor.CrashOriginLeaderLost)})
		})},
		{"server control plane staged stale", built(func(t *testing.T) Row {
			r := launchdRow(t, RowServer, "launchctl_netd_running.txt", LivenessRunning)
			applyStagedControlPlane(&r, ClassifyStagedControlPlane([]byte("v1.30.0\n"), nil, executor.DefaultKubeVersion))
			return r
		})},
		{"server control plane staged newer", built(func(t *testing.T) Row {
			r := launchdRow(t, RowServer, "launchctl_netd_running.txt", LivenessRunning)
			applyStagedControlPlane(&r, ClassifyStagedControlPlane([]byte("v9.99.0\n"), nil, executor.DefaultKubeVersion))
			return r
		})},
		// the worker's credential
		{"agent waiting", fromScenario("agent-waiting", RowAgent)},
		{"agent expired", fromScenario("agent-expired", RowAgent)},
		{"agent corrupt", fromScenario("agent-corrupt", RowAgent)},
		{"agent address mismatch", fromScenario("agent-address-mismatch", RowAgent)},
		{"agent credential unreadable", func(t *testing.T) (Row, alertContext) {
			p := agentPaths(t.TempDir())
			fsys := agentInstalledFS(p)
			fsys.denied = map[string]bool{filepath.Join(p.AgentCredentialDir, "kubeconfig"): true}
			fsys.unreadable = map[string]bool{}
			for _, f := range []string{"kubeconfig", "client.crt", "client.key", "serving.crt", "serving.key", "ca.crt"} {
				fsys.unreadable[filepath.Join(p.AgentCredentialDir, f)] = true
			}
			c := agentCollector(t, p, fsys)
			c.EUID = 501
			r, _, _ := c.agentRow(now)
			return r, agentCtx
		}},
		// the data volume's mount job
		{"datavol not loaded", built(func(t *testing.T) Row { return datavolRow(t, "launchctl_not_loaded.txt") })},
		{"datavol disabled", built(func(t *testing.T) Row { return datavolRow(t, "launchctl_disabled.txt") })},
		{"datavol failed", built(func(t *testing.T) Row { return datavolRow(t, "launchctl_failed_once.txt") })},
		{"datavol unreadable", built(func(t *testing.T) Row { return datavolRow(t, "launchctl_garbage.txt") })},
		// the installed arguments and settings
		{"server-args needs admin", built(func(t *testing.T) Row {
			p := testPaths(wd)
			plist := filepath.Join(p.LaunchDaemonDir, p.ServerLabel+".plist")
			r, _ := Collector{FS: fakeFS{unreadable: map[string]bool{plist: true}}, ServerArgs: fakeServerArgs, Paths: p}.serverArgsRow()
			return r
		})},
		{"server-args unparsable", built(func(t *testing.T) Row {
			p := testPaths(wd)
			plist := filepath.Join(p.LaunchDaemonDir, p.ServerLabel+".plist")
			r, _ := Collector{FS: fakeFS{contents: map[string][]byte{plist: []byte("x")}},
				ServerArgs: func([]byte) ([]string, error) { return nil, errors.New("no ProgramArguments") }, Paths: p}.serverArgsRow()
			return r
		})},
		{"settings needs admin", fromScenario("unknown", RowSettings)},
		{"settings unreadable", built(func(t *testing.T) Row {
			r, _ := Collector{NodeArgs: nodeArgs(nil, errors.New("plist: bad header"))}.settingsRow(dataroot.RoleServer, true, Row{Name: RowDataRoot, State: StateOK}, nil, nil)
			return r
		})},
		// the apiserver
		{"apiserver no kubeconfig", fromScenario("not-installed", RowAPIServer)},
		{"apiserver down", fromScenario("stopped-clean", RowAPIServer)},
		{"apiserver not ready", built(func(t *testing.T) Row {
			return Collector{Kube: fakeKube{raw: map[string][]byte{"/readyz": []byte("[-]etcd failed")}, server: "https://127.0.0.1:6444"}}.apiserverRow(context.Background(), dataroot.RoleServer, CredentialUnknown)
		})},
		{"apiserver unreachable from a worker", func(t *testing.T) (Row, alertContext) {
			return Collector{Kube: kubeDown}.apiserverRow(context.Background(), dataroot.RoleAgent, CredentialValid), agentCtx
		}},
		{"apiserver: worker not joined", fromScenario("agent-waiting", RowAPIServer)},
		{"apiserver: worker credential expired", fromScenario("agent-expired", RowAPIServer)},
		{"apiserver: worker credential corrupt", fromScenario("agent-corrupt", RowAPIServer)},
		{"apiserver: worker credential unreadable", func(t *testing.T) (Row, alertContext) {
			return Collector{}.apiserverRow(context.Background(), dataroot.RoleAgent, CredentialUnknown), agentCtx
		}},
		// the node, its heartbeat and the workloads
		{"node: apiserver unreachable", fromScenario("stopped-clean", RowNode)},
		{"node: worker cannot reach the apiserver", fromScenario("agent-waiting", RowNode)},
		{"node list failed", built(func(t *testing.T) Row {
			return Collector{Kube: healthyKube()}.nodeRow(true, dataroot.RoleServer, nil, errors.New("forbidden"))
		})},
		{"no node ready", built(func(t *testing.T) Row {
			return Collector{Kube: healthyKube()}.nodeRow(true, dataroot.RoleServer, []corev1.Node{notReadyNode("my-mac")}, nil)
		})},
		{"some nodes not ready", built(func(t *testing.T) Row {
			return Collector{Kube: healthyKube()}.nodeRow(true, dataroot.RoleServer, []corev1.Node{readyNode("my-mac"), notReadyNode("other")}, nil)
		})},
		{"heartbeat stale", built(func(t *testing.T) Row {
			k := withHeartbeat(healthyKube(), now.Add(-10*time.Minute), now.Add(-5*time.Minute))
			r, _ := Collector{Kube: k, Hostname: "my-mac"}.heartbeatRow(context.Background(), true, dataroot.RoleServer, k.nodes, nil, now)
			return r
		})},
		{"workloads: apiserver unreachable", fromScenario("stopped-clean", RowWorkloads)},
		{"workloads pending", workloads(fakeKube{nodes: []corev1.Node{readyNode("my-mac")}, pods: []corev1.Pod{podIn(corev1.PodPending)}}).wrap()},
		{"workloads stuck terminating", workloads(fakeKube{nodes: []corev1.Node{notReadyNode("gone")}, pods: []corev1.Pod{terminating("gone")}}).wrap()},
		{"workloads on a deleted node", workloads(fakeKube{nodes: []corev1.Node{readyNode("my-mac")}, pods: []corev1.Pod{terminating("deleted")}}).wrap()},
		// the interconnect
		{"interconnect partial", fromScenario("running-interconnect", RowInterconnect)},
		{"interconnect down", built(func(t *testing.T) Row {
			ic := &netv1alpha1.Interconnect{Spec: netv1alpha1.InterconnectSpec{Enabled: true},
				Status: netv1alpha1.InterconnectStatus{Members: []netv1alpha1.InterconnectMember{{Node: "a", State: "Down"}}}}
			r, _ := InterconnectRow(ic, nil, nil)
			return r
		})},
		{"interconnect unreadable", built(func(t *testing.T) Row { return interconnectReadErrorRow(errors.New("timeout")) })},
		// the data root and its leftovers
		{"data root absent", fromScenario("not-installed", RowDataRoot)},
		{"data root shadowed, no record", built(dataRoot(fakeDataRootFS{dir: "/var/lib/k3sm", mode: 0o755,
			fstab: "UUID=" + recordUUID + " /var/lib/k3sm apfs rw\n", entries: []string{"run"}}, 501, 250))},
		{"data root shadowed, with a record", built(dataRoot(fakeDataRootFS{dir: "/var/lib/k3sm", mode: 0o755,
			record: `{"version":1,"uuid":"` + recordUUID + `","name":"k3sm","mountpoint":"/var/lib/k3sm"}`, entries: []string{"run"}}, 501, 250))},
		{"data root wrong owner", built(dataRoot(fakeDataRootFS{dir: "/var/lib/k3sm", mode: 0o755, uid: 250, mounted: true}, 501, 250))},
		{"data root nearly full", built(func(t *testing.T) Row {
			return dataRoot(volumeFS(t, "/var/lib/k3sm", "k3sm", 100<<30, 100<<30, 95<<30), 501, 250)(t)
		})},
		{"data root not probed", built(dataRoot(nil, 501, 250))},
		{"pre-volume copy", built(preVolume(0, true))},
		{"pre-volume copy, partly readable", built(preVolume(501, false))},
		// the datastore
		{"datastore: apiserver not ready", built(throughAPI(Row{Name: RowAPIServer, State: StateDown}, true))},
		{"datastore: kubeconfig points elsewhere", built(throughAPI(apiReady, false))},
		{"datastore not in WAL mode", built(func(t *testing.T) Row {
			work := t.TempDir()
			path := executor.StateDBPath(work)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFakeSQLiteHeader(t, path, 1, 1)
			return Collector{Paths: Paths{WorkDir: work}}.datastoreRow(dataroot.RoleServer, Row{})
		})},
		// the update check
		{"update: none recorded", fromScenario("running", RowUpdate)},
		{"update: a node behind", built(update(UpdateRecord{CheckedAt: now.Add(-time.Minute), Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.1.7", UpdateCurrent)}}))},
		{"update: stale", built(update(UpdateRecord{CheckedAt: now.Add(-25 * time.Hour), Latest: "v0.2.0"}))},
		{"update: check failed", built(update(UpdateRecord{CheckedAt: now.Add(-time.Minute), Error: "dial tcp: no such host"}))},
		{"update: no release", built(update(UpdateRecord{CheckedAt: now.Add(-time.Minute)}))},
		{"update: untagged node", built(update(UpdateRecord{CheckedAt: now.Add(-time.Minute), Latest: "v0.2.0", Nodes: []UpdateNode{{Name: "b", Version: "v1.37.1", State: UpdateCurrent}}}))},
		{"update: invalid record", built(update(UpdateRecord{CheckedAt: now.Add(-time.Minute), Latest: "v1;rm -rf"}))},
		{"update: record unreadable", built(updateFile(fakeFS{unreadable: map[string]bool{UpdatePath(wd): true}}))},
		{"update: record unparsable", built(updateFile(fakeFS{contents: map[string][]byte{UpdatePath(wd): []byte("{")}}))},
		{"update: worker cannot read", fromScenario("agent-waiting", RowUpdate)},
		{"update: no server published", func(t *testing.T) (Row, alertContext) {
			return Collector{Kube: healthyKube()}.agentUpdateRow(true, []corev1.Node{readyNode("my-mac")}, nil, now), agentCtx
		}},
		// the etcd member
		{"etcd NOSPACE", built(etcd(func(s *executor.EtcdStatus) { s.Alarms = []string{"NOSPACE"} }))},
		{"etcd nearing quota", built(etcd(func(s *executor.EtcdStatus) { s.DBSizeBytes = s.QuotaBytes * 9 / 10 }))},
		{"etcd no leader", built(etcd(func(s *executor.EtcdStatus) { s.LeaderPresent = false }))},
		{"etcd alarm", built(etcd(func(s *executor.EtcdStatus) { s.Alarms = []string{"CORRUPT"} }))},
		{"etcd foreign peer", built(etcd(func(s *executor.EtcdStatus) { s.ForeignPeer = "https://192.0.2.20:2380" }))},
		{"etcd peer URL drift", built(etcd(func(s *executor.EtcdStatus) {
			s.PeerURLDrift, s.RegisteredPeerURLs = true, []string{"https://192.0.2.99:2380"}
		}))},
		{"etcd superseded", built(etcd(func(s *executor.EtcdStatus) {
			s.Superseded, s.SupersededDetail, s.SupersededRemedy = true, "this member's cluster was replaced by a restore", "wipe <work-dir>/etcd and re-join"
		}))},
		{"etcd record stale", built(etcd(func(s *executor.EtcdStatus) { s.UpdatedAt = now.Add(-time.Hour) }))},
		{"etcd record unreadable", built(etcdFile(fakeFS{present: map[string]bool{executor.EtcdStatusPath(wd): true}, unreadable: map[string]bool{executor.EtcdStatusPath(wd): true}}))},
		{"etcd record unparsable", built(etcdFile(fakeFS{present: map[string]bool{executor.EtcdStatusPath(wd): true}, contents: map[string][]byte{executor.EtcdStatusPath(wd): []byte("{")}}))},
		{"etcd not probed", built(func(t *testing.T) Row {
			r, _ := Collector{Paths: Paths{WorkDir: wd}}.etcdRow(context.Background(), []string{"--cluster-init"})
			return r
		})},
		// the serving certificate and the anchors
		{"serving cert absent", built(servingFile(nil, caPEM, false, now))},
		{"serving cert corrupt", built(servingFile(func(*testing.T) []byte { return []byte("-----BEGIN CERT") }, caPEM, false, now))},
		{"serving cert from another CA", built(servingFile(func(t *testing.T) []byte { return issue(t, other) }, caPEM, false, now))},
		{"serving cert expired", built(servingFile(func(t *testing.T) []byte { return issue(t, ca) }, caPEM, false, now.Add(2*time.Hour)))},
		{"cluster CA corrupt", built(servingFile(func(t *testing.T) []byte { return issue(t, ca) }, func() []byte { return []byte("-----BEGIN CERT") }, false, now))},
		{"serving cert unreadable", built(servingFile(nil, caPEM, true, now))},
		{"handshake expired", built(handshake("127.0.0.1", caPEM, theCA, now.Add(2*time.Hour), false))},
		{"handshake from another CA", built(handshake("127.0.0.1", caPEM, otherCA, now, false))},
		{"handshake names another host", built(handshake("100.64.0.9", caPEM, theCA, now, false))},
		{"handshake from another server", built(handshake("10.0.0.9", caPEM, theCA, now, false))},
		{"handshake with no pinned CA", built(handshake("127.0.0.1", noCA, theCA, now, false))},
		{"no handshake", built(handshake("127.0.0.1", caPEM, theCA, now, true))},
		{"admin kubeconfig needs admin", built(func(t *testing.T) Row {
			fsys := fakeFS{present: map[string]bool{caPath: true}}
			r, _ := Collector{FS: fsys, EUID: 501, Paths: Paths{WorkDir: wd}}.adminKubeconfigAnchorRow()
			return r
		})},
		{"admin kubeconfig drift", built(func(t *testing.T) Row {
			const record, kube = "/Library/k3sm/server-args.json", "/Users/me/.kube/config"
			rec, _ := json.Marshal(dataroot.ServerArgsRecord{AdminKubeconfig: kube})
			fsys := fakeFS{present: map[string]bool{caPath: true, record: true}, contents: map[string][]byte{caPath: ca.CertPEM, record: rec}}
			r, _ := Collector{FS: fsys, EUID: 0, Paths: Paths{WorkDir: wd, ServerArgsRecord: record, ServerLabel: "io.k3sm.server", LaunchDaemonDir: "/nonexistent"}}.adminKubeconfigAnchorRow()
			return r
		})},
		{"request-header unreadable", built(reqHeader(rh(rhA), true))},
		{"request-header corrupt", built(reqHeader([]byte("-----BEGIN CERT"), false))},
		{"request-header absent", built(reqHeader(nil, false))},
		{"request-header second root", built(reqHeader(rh(rhA), false, rh(rhA), rh(rhB)))},
		{"request-header foreign root", built(reqHeader(rh(rhA), false, rh(rhB)))},
		// the mesh claims, the Service proxy and the registry
		{"mesh claims abandoned", built(func(t *testing.T) Row {
			return meshClaimsRowFrom(MeshClaimsRecord{UpdatedAt: now.Add(-time.Minute), Abandoned: []AbandonedMeshClaim{{Claim: "mesh-range-3", Holder: "server-c", PodCIDR: "10.42.3.0/24", Kind: "server"}}}, now)
		})},
		{"mesh claims stale", built(func(t *testing.T) Row {
			return meshClaimsRowFrom(MeshClaimsRecord{UpdatedAt: now.Add(-time.Hour)}, now)
		})},
		{"mesh claims needs admin", built(meshFile(fakeFS{unreadable: map[string]bool{MeshClaimsPath(wd): true}}))},
		{"mesh claims unparsable", built(meshFile(fakeFS{contents: map[string][]byte{MeshClaimsPath(wd): []byte("{")}}))},
		{"services diverging", built(func(t *testing.T) Row {
			return services(fakeFS{contents: map[string][]byte{ServicesPath(wd): servicesRec(t, now.Add(-10*time.Second))}}, true, ServicesComparison{Diverging: []ServicePortDivergence{diverging}}, nil)(t)
		})},
		{"services settling", built(func(t *testing.T) Row {
			return services(fakeFS{contents: map[string][]byte{ServicesPath(wd): servicesRec(t, now.Add(-10*time.Second))}}, true, ServicesComparison{Settling: []ServicePortDivergence{diverging}}, nil)(t)
		})},
		{"services needs admin", built(services(fakeFS{unreadable: map[string]bool{ServicesPath(wd): true}}, true, ServicesComparison{}, nil))},
		{"services not recorded", built(services(fakeFS{}, true, ServicesComparison{}, nil))},
		{"services unparsable", built(services(fakeFS{contents: map[string][]byte{ServicesPath(wd): []byte("{")}}, true, ServicesComparison{}, nil))},
		{"services stale", built(func(t *testing.T) Row {
			return services(fakeFS{contents: map[string][]byte{ServicesPath(wd): servicesRec(t, now.Add(-time.Hour))}}, true, ServicesComparison{}, nil)(t)
		})},
		{"services: apiserver not serving", built(func(t *testing.T) Row {
			return services(fakeFS{contents: map[string][]byte{ServicesPath(wd): servicesRec(t, now.Add(-10*time.Second))}}, false, ServicesComparison{}, nil)(t)
		})},
		{"services list failed", built(func(t *testing.T) Row {
			return services(fakeFS{contents: map[string][]byte{ServicesPath(wd): servicesRec(t, now.Add(-10*time.Second))}}, true, ServicesComparison{}, errors.New("forbidden"))(t)
		})},
		{"ingest registry down", built(registry(registrysvc.State{State: registrysvc.StateServing}, errors.New("connection refused")))},
		{"ingest registry disabled", built(registry(registrysvc.State{State: registrysvc.StateDisabled, Reason: "port 5000 is in use"}, nil))},
		{"ingest registry unknown state", built(registry(registrysvc.State{State: "frobbing"}, nil))},
		{"ingest registry needs admin", built(registryFile(fakeFS{contents: map[string][]byte{}, unreadable: map[string]bool{registrysvc.StatePath(wd): true}}))},
		{"ingest registry unparsable", built(registryFile(fakeFS{contents: map[string][]byte{registrysvc.StatePath(wd): []byte("{")}, unreadable: map[string]bool{}}))},
		// this account's kubeconfig and the runtime daemon
		{"kubeconfig missing", fromScenario("unknown", RowKubeconfig)},
		{"kubeconfig missing on a worker", fromScenario("agent-waiting", RowKubeconfig)},
		{"runtimed needs admin", fromScenario("running", RowRuntimed)},
		{"runtimed down", built(runtimedRow(nil, errors.New("connection refused")))},
		{"runtimed unhealthy", built(runtimedRow(&runtimev1.GetRuntimeInfoResponse{RuntimeName: "k3sm-runtimed", Healthy: false,
			Conditions: []*runtimev1.RuntimeCondition{{Type: "NetworkReady", Status: runtimev1.ConditionStatus_CONDITION_STATUS_FALSE, Reason: "netd down"}}}, nil))},
		// cluster DNS on the host
		{"dns silent", built(dnsRow(&fakeDNS{}, nil))},
		{"dns UDP silent, TCP answers", built(dnsRow(&fakeDNS{answers: map[string]netip.Addr{"tcp": netip.MustParseAddr("10.43.0.1")}}, nil))},
		{"dns no address", built(dnsRow(&fakeDNS{errs: map[string]error{"udp": ErrDNSNoAddress}}, nil))},
		{"dns VIP not an address", built(dnsRow(&fakeDNS{}, nodeArgs([]string{"--dns-vip", "nope"}, nil)))},
		{"node resolver missing", built(resolver(false, nil, netdUp))},
		{"node resolver orphaned", built(resolver(true, nil, Row{Name: RowNetd, State: StateStopped, Severity: SeverityFail}))},
		{"node resolver unreadable", built(resolver(false, errors.New("configd down"), netdUp))},
		{"shadow set missing", built(shadowRow(fakeFS{}, nil))},
		{"shadow set corrupt", built(shadowRow(fakeFS{contents: map[string][]byte{manifest: []byte("{")}}, nil))},
		{"shadow set drifted", built(func(t *testing.T) Row {
			return shadowRow(fakeFS{contents: map[string][]byte{manifest: shadowManifest(t)}}, map[string]string{"/bin/bash": "cc"})(t)
		})},
		{"shadow set unreadable", built(shadowRow(fakeFS{unreadable: map[string]bool{manifest: true}}, nil))},
	}
}

// wrap adapts a row builder to an alert case that runs on a server.
func (f rowBuilder) wrap() func(t *testing.T) (Row, alertContext) {
	return func(t *testing.T) (Row, alertContext) { return f(t), serverCtx }
}

type rowBuilder func(t *testing.T) Row

// datavolRow is the data-volume mount job's row from launchd's canned output.
func datavolRow(t *testing.T, fixtureName string) Row {
	t.Helper()
	const label = "io.k3sm.datavol"
	return Collector{Launchd: fakeLaunchd{out: map[string][]byte{label: fixture(t, fixtureName)}}, Paths: testPaths(t.TempDir())}.
		oneshotRow(RowDatavol, label, "/var/log/k3sm/datavol.log")
}

// fakeRuntimed answers the runtime daemon's Info.
type fakeRuntimed struct {
	info *runtimev1.GetRuntimeInfoResponse
	err  error
}

func (f fakeRuntimed) Info(context.Context) (*runtimev1.GetRuntimeInfoResponse, error) {
	return f.info, f.err
}

// TestEveryWarnRowCarriesAnAlert drives every warn, fail, unknown and
// needs-admin path of every row through the fakes the rows' own tests use, and
// asserts each comes back with an alert written for that failure mode: a cause,
// the row's detail as its first evidence, at least one fix step, a docs anchor,
// and not the generic floor. It also asserts that an ok row carries none, that
// every row name is driven at least once, and that the full reports of every
// contract posture hold the same rule.
func TestEveryWarnRowCarriesAnAlert(t *testing.T) {
	t.Parallel()
	covered := map[string]bool{}
	for _, tc := range alertCases() {
		t.Run(tc.name, func(t *testing.T) {
			row, ac := tc.build(t)
			if row.Name == "" {
				t.Fatalf("the builder produced no row")
			}
			covered[row.Name] = true
			if !NeedsAlert(row) {
				t.Fatalf("%s is %s/%s, not a failure path: %q", row.Name, row.State, row.Severity, row.Detail)
			}
			rows := []Row{row}
			attachAlerts(rows, ac)
			a := rows[0].Alert
			if a == nil {
				t.Fatalf("%s %s/%s carries no alert", row.Name, row.State, row.Severity)
			}
			if a.generic {
				t.Errorf("%s %s/%s %q reached the generic alert; its writer does not know this mode", row.Name, row.State, row.Severity, row.Detail)
			}
			if strings.TrimSpace(a.Cause) == "" || !strings.HasSuffix(a.Cause, ".") {
				t.Errorf("cause %q is not a sentence", a.Cause)
			}
			if len(a.Evidence) == 0 || a.Evidence[0] != row.Detail {
				t.Errorf("evidence %q does not lead with the detail %q", a.Evidence, row.Detail)
			}
			if len(a.Fix) == 0 {
				t.Fatalf("no fix step")
			}
			for i, s := range a.Fix {
				if strings.TrimSpace(s.Step) == "" {
					t.Errorf("fix[%d] has no step text: %+v", i, s)
				}
				if s.NeedsAdmin != strings.HasPrefix(s.Command, "sudo ") {
					t.Errorf("fix[%d] needsAdmin=%v for %q", i, s.NeedsAdmin, s.Command)
				}
			}
			if a.Docs == "" {
				t.Errorf("no docs anchor")
			}
			if a.Since != "" {
				if _, err := time.Parse(time.RFC3339, a.Since); err != nil {
					t.Errorf("since %q is not RFC 3339: %v", a.Since, err)
				}
			}
			if row.State == StateNeedsAdmin || strings.HasPrefix(row.Remedy, needsAdminRemedy) && row.Severity == SeverityUnknown {
				if !anyNeedsAdmin(a.Fix) {
					t.Errorf("a row only an administrator can answer has no administrator step: %+v", a.Fix)
				}
			}
		})
	}

	t.Run("every row is driven", func(t *testing.T) {
		for _, name := range []string{RowInstall, RowNetd, RowServer, RowAgent, RowServerArgs, RowSettings, RowAPIServer, RowNode,
			RowHeartbeat, RowWorkloads, RowInterconnect, RowDataRoot, RowPreVolume, RowDatavol, RowDatastore, RowUpdate, RowEtcd,
			RowServingCert, RowAdminKubeconfig, RowRequestHeader, RowMeshClaims, RowServices, RowIngestRegistry, RowKubeconfig,
			RowRuntimed, RowDNS, RowNodeResolver, RowShadowShells} {
			if !covered[name] {
				t.Errorf("no case drives a failure path of the %s row", name)
			}
		}
	})

	t.Run("an ok row carries none", func(t *testing.T) {
		rows := append(healthyRows(), Row{Name: RowDatastore, State: StateSkip, Severity: SeveritySkip, Detail: WorkerDatastoreDetail})
		attachAlerts(rows, serverCtx)
		for _, r := range rows {
			if r.Alert != nil {
				t.Errorf("%s %s/%s carries an alert: %+v", r.Name, r.State, r.Severity, r.Alert)
			}
		}
	})

	t.Run("every posture's full report holds the rule", func(t *testing.T) {
		for name, sc := range contractScenarios() {
			c := sc.collector(t)
			rep := c.Collect(context.Background())
			probe := c.CollectDaemons()
			for _, r := range append(rep.Rows, probe.Daemons...) {
				if (r.Alert != nil) != NeedsAlert(r) {
					t.Errorf("%s: %s %s/%s alert present=%v", name, r.Name, r.State, r.Severity, r.Alert != nil)
				}
				if r.Alert != nil && r.Alert.generic {
					t.Errorf("%s: %s %s/%s reached the generic alert", name, r.Name, r.State, r.Severity)
				}
			}
		}
	})
}

func anyNeedsAdmin(steps []FixStep) bool {
	for _, s := range steps {
		if s.NeedsAdmin {
			return true
		}
	}
	return false
}

// TestAlertDocsResolve pins every docs anchor an alert can name to a heading of
// the user documentation page it names, so a renamed section fails here rather
// than sending a reader to the top of a page.
func TestAlertDocsResolve(t *testing.T) {
	t.Parallel()
	anchors := map[string]bool{"troubleshooting.md#start-with-k3sm-status": true}
	for _, tc := range alertCases() {
		row, ac := tc.build(t)
		rows := []Row{row}
		attachAlerts(rows, ac)
		if rows[0].Alert != nil {
			anchors[rows[0].Alert.Docs] = true
		}
	}
	// The constants too, so a writer path no case reaches is still checked.
	src, err := os.ReadFile("alert.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`"([a-z-]+\.md#[a-z0-9-]+)"`).FindAllStringSubmatch(string(src), -1) {
		anchors[m[1]] = true
	}
	slugs := map[string]map[string]bool{}
	for anchor := range anchors {
		page, frag, _ := strings.Cut(anchor, "#")
		if slugs[page] == nil {
			slugs[page] = headingSlugs(t, filepath.Join("..", "..", "docs", "user", page))
		}
		if !slugs[page][frag] {
			t.Errorf("%s: no heading in docs/user/%s has the anchor #%s", anchor, page, frag)
		}
	}
}

// headingSlugs reads a markdown page's heading anchors the way GitHub and the
// site's renderer derive them: lowercased, punctuation dropped, spaces to
// hyphens. Fenced code blocks are skipped, since a "#" comment there is not a
// heading.
func headingSlugs(t *testing.T, path string) map[string]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	out := map[string]bool{}
	fenced := false
	drop := regexp.MustCompile(`[^a-z0-9 _-]`)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "```") {
			fenced = !fenced
			continue
		}
		if fenced || !strings.HasPrefix(line, "#") {
			continue
		}
		title := strings.TrimSpace(strings.TrimLeft(line, "#"))
		slug := strings.ReplaceAll(drop.ReplaceAllString(strings.ToLower(title), ""), " ", "-")
		out[slug] = true
	}
	return out
}
