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

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/version"
)

// ---- fakes ----------------------------------------------------------------

// recordingKube wraps the apiserver seam the PRODUCTION resolution built and
// records every URL it is asked to hit.
//
// It records rather than merely fails on purpose: the defect this gate pins is
// a worker probing the wrong apiserver, and a fake that only returned an error
// would be equally happy whether the loopback or the credential's server was
// dialled. The recorded host is Kube.Server() — the host the real client-go
// client would have connected to — so what is asserted is the production
// choice, not the fake's own state.
type recordingKube struct {
	inner status.Kube
	rec   *[]string
	// ready is whether the apiserver answers. False is the ordinary worker
	// posture in this test: a control plane on another Mac that is not
	// reachable from here.
	ready bool
	nodes []corev1.Node
}

func (k recordingKube) record(path string) { *k.rec = append(*k.rec, k.inner.Server()+path) }

func (k recordingKube) RawGet(_ context.Context, path string) ([]byte, error) {
	k.record(path)
	if !k.ready {
		return nil, fmt.Errorf("Get %q: dial tcp: connect: connection refused", k.inner.Server()+path)
	}
	if strings.HasPrefix(path, "/readyz") {
		return []byte("ok"), nil
	}
	return nil, fmt.Errorf("unexpected path %s", path)
}

func (k recordingKube) Nodes(context.Context) ([]corev1.Node, error) {
	k.record("/api/v1/nodes")
	if !k.ready {
		return nil, errors.New("dial tcp: connect: connection refused")
	}
	return k.nodes, nil
}

func (k recordingKube) Pods(context.Context) ([]corev1.Pod, error) {
	k.record("/api/v1/pods")
	if !k.ready {
		return nil, errors.New("dial tcp: connect: connection refused")
	}
	return nil, nil
}

func (k recordingKube) Server() string     { return k.inner.Server() }
func (k recordingKube) TLSPosture() string { return k.inner.TLSPosture() }

// runningLaunchd reports every label it was given as a running daemon, and
// anything else as not loaded.
type runningLaunchd struct{ running map[string]bool }

func (l runningLaunchd) Print(label string) ([]byte, error) {
	if !l.running[label] {
		return nil, fmt.Errorf("could not find service %q", label)
	}
	return []byte("system/" + label + " = {\n\tstate = running\n\tpid = 4242\n\truns = 1\n\tlast exit code = (never exited)\n}\n"), nil
}

func (runningLaunchd) PrintDisabled() ([]byte, error) { return []byte("{\n}\n"), nil }

// aliveProcs answers that every probed pid is there.
type aliveProcs struct{}

func (aliveProcs) Liveness(int) status.Liveness { return status.LivenessRunning }
func (aliveProcs) VMHosts(int) (int, error)     { return 0, nil }

// plainDataRoot is a data root that is an ordinary directory owned by the
// service user: the posture that keeps the data-root row out of this gate's
// way, since what is under test is the apiserver and kubeconfig rows.
type plainDataRoot struct{ dir string }

func (d plainDataRoot) Stat(path string) (fs.FileInfo, error) {
	if path != d.dir {
		return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
	}
	return os.Stat(path)
}

func (plainDataRoot) Statfs(_ string, st *unix.Statfs_t) error {
	copy(st.Mntonname[:], "/\x00")
	return nil
}

func (plainDataRoot) ReadFile(path string) ([]byte, error) {
	return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

func (plainDataRoot) ReadDir(path string) ([]fs.DirEntry, error) { return nil, nil }

// ---- fixture --------------------------------------------------------------

// nodeMac is a staged Mac: a real install tree on disk, with the role's plist,
// optionally a node credential store, and optionally the leftover
// control-plane work dir an earlier server-era install put there.
type nodeMac struct{ paths status.Paths }

// staleServerKubeconfigURL is what the leftover control-plane work dir's admin
// kubeconfig points at. It is the loopback, because that is what a server-era
// install left behind — and a worker that probes it is the defect.
const staleServerKubeconfigURL = "https://127.0.0.1:6444"

// stageNodeMac writes an install tree for one role under a temp dir.
func stageNodeMac(t *testing.T, role install.Role, joined, serverWorkDir bool) nodeMac {
	t.Helper()
	root := t.TempDir()
	mkdir := func(parts ...string) string {
		t.Helper()
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		return p
	}
	touch := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	installDir := mkdir("Library", "k3sm")
	linkDir := mkdir("usr", "local", "bin")
	ldDir := mkdir("Library", "LaunchDaemons")
	dataRoot := mkdir("var", "lib", "k3sm")
	runDir := mkdir("var", "lib", "k3sm", "run")
	logDir := mkdir("var", "log", "k3sm")

	binary := filepath.Join(installDir, "k3sm")
	touch(binary)
	link := filepath.Join(linkDir, "k3sm")
	if err := os.Symlink(binary, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	touch(filepath.Join(ldDir, install.NetdLabel+".plist"))
	nodeLabel := install.ServerLabel
	if role == install.RoleAgent {
		nodeLabel = install.AgentLabel
	}
	touch(filepath.Join(ldDir, nodeLabel+".plist"))
	socket := filepath.Join(runDir, "netd.sock")
	touch(socket)

	workDir := filepath.Join(dataRoot, "server")
	if serverWorkDir {
		kc := executor.KubeconfigPath(workDir)
		mkdirAll := filepath.Dir(kc)
		if err := os.MkdirAll(mkdirAll, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", mkdirAll, err)
		}
		writeAdminKubeconfig(t, kc, staleServerKubeconfigURL)
	}
	if joined {
		store := nodeCredentialStore{dir: filepath.Dir(install.AgentCredentialPath(dataRoot))}
		if err := os.MkdirAll(store.dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", store.dir, err)
		}
		res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		if err := store.Save(nodeCredTestAPI, nodeCredTestNode, res); err != nil {
			t.Fatalf("save the node credential: %v", err)
		}
	}

	return nodeMac{
		paths: status.Paths{
			Binary:             binary,
			Link:               link,
			LaunchDaemonDir:    ldDir,
			NetdLabel:          install.NetdLabel,
			ServerLabel:        install.ServerLabel,
			AgentLabel:         install.AgentLabel,
			AgentLog:           filepath.Join(logDir, "agent.log"),
			AgentCredentialDir: filepath.Dir(install.AgentCredentialPath(dataRoot)),
			DataRoot:           dataRoot,
			WorkDir:            workDir,
			NetdSocket:         socket,
			NetdLog:            filepath.Join(logDir, "netd.log"),
			ServerLog:          filepath.Join(logDir, "server.log"),
		},
	}
}

// writeAdminKubeconfig writes a control-plane admin kubeconfig targeting server.
func writeAdminKubeconfig(t *testing.T, path, server string) {
	t.Helper()
	body := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %s
    insecure-skip-tls-verify: true
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: admin
current-context: k3sm
users:
- name: admin
  user:
    token: notarealtoken
`, server)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// collectFrom runs a whole report for a staged Mac, resolving its credentials
// through the production path and recording every URL the report dials.
func collectFrom(t *testing.T, mac nodeMac, role install.Role, ready bool) (status.Report, []string, error) {
	t.Helper()
	t.Setenv("K3SM_WORK_DIR", "")
	t.Setenv("KUBECONFIG", "")

	var dialled []string
	kube, source, kubeErr := newStatusKube(statusKubeInputsFor(role, mac.paths))
	var seam status.Kube
	if kube != nil {
		node := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "k3sm-mac"}}
		node.Status.NodeInfo.KubeletVersion = "v1.36.2"
		node.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
		seam = recordingKube{inner: kube, rec: &dialled, ready: ready, nodes: []corev1.Node{node}}
	}

	uid := os.Geteuid()
	c := status.Collector{
		Launchd: runningLaunchd{running: map[string]bool{
			install.NetdLabel:   true,
			install.ServerLabel: role == install.RoleServer,
			install.AgentLabel:  role == install.RoleAgent,
		}},
		FS:         osStatusFS{},
		Kube:       seam,
		KubeErr:    kubeErr,
		KubeSource: source,
		Procs:      aliveProcs{},
		DataRoot:   plainDataRoot{dir: mac.paths.DataRoot},
		Paths:      mac.paths,
		EUID:       uid,
		ServiceUID: uid,
		Now:        func() time.Time { return time.Now() },
		Version:    version.Get(),
		Host:       "macOS 26.1",
		Hostname:   "k3sm-mac",
	}
	return c.Collect(context.Background()), dialled, kubeErr
}

// ---- the gate -------------------------------------------------------------

// TestStatusOnAWorkerNeverProbesTheLoopbackApiserver is the B324 gate.
//
// The defect: `k3sm status` chose its credentials from the EUID alone, so on a
// worker whose Mac still carried a stale <DataRoot>/server directory from an
// earlier server-era install, it probed the loopback apiserver that directory's
// admin kubeconfig names and reported that kubeconfig as this node's. The
// verdict then read degraded for a reason a worker cannot have — there is no
// control plane on this Mac to be down.
func TestStatusOnAWorkerNeverProbesTheLoopbackApiserver(t *testing.T) {
	t.Run("a worker with a stale server directory probes only its own credential's apiserver", func(t *testing.T) {
		mac := stageNodeMac(t, install.RoleAgent, true, true)
		rep, dialled, err := collectFrom(t, mac, install.RoleAgent, false)
		if err != nil {
			t.Fatalf("a joined worker could not resolve its own credentials: %v", err)
		}
		if len(dialled) == 0 {
			t.Fatal("the report dialled nothing at all; it must probe the credential's apiserver")
		}
		for _, url := range dialled {
			if !strings.HasPrefix(url, nodeCredTestAPI) {
				t.Errorf("the report dialled %q; a worker probes only %s", url, nodeCredTestAPI)
			}
			if strings.Contains(url, "127.0.0.1") || strings.Contains(url, "localhost") {
				t.Errorf("the report dialled the loopback apiserver (%q) from a worker", url)
			}
		}

		api, ok := rep.Row(status.RowAPIServer)
		if !ok {
			t.Fatalf("no apiserver row\n%s", status.Render(rep, status.Style{}))
		}
		if api.Wide["server"] != nodeCredTestAPI {
			t.Errorf("apiserver row targets %q, want the credential's server %q", api.Wide["server"], nodeCredTestAPI)
		}

		kc, ok := rep.Row(status.RowKubeconfig)
		if !ok {
			t.Fatal("no kubeconfig row")
		}
		if want := install.AgentCredentialPath(mac.paths.DataRoot); !strings.Contains(kc.Detail, want) {
			t.Errorf("kubeconfig row = %q, want the node credential %s", kc.Detail, want)
		}
		if strings.Contains(kc.Detail, mac.paths.WorkDir) {
			t.Errorf("kubeconfig row names the control-plane work dir on a worker: %q", kc.Detail)
		}

		inst, ok := rep.Row(status.RowInstall)
		if !ok {
			t.Fatal("no install row")
		}
		if !strings.Contains(inst.Detail, "control-plane data directory") || !strings.Contains(inst.Detail, mac.paths.WorkDir) {
			t.Errorf("install row does not name the stale control-plane directory: %q", inst.Detail)
		}

		if rep.Verdict != status.VerdictRunning {
			t.Errorf("verdict = %v (%s); an unreachable remote apiserver is not this worker's health\n%s",
				rep.Verdict, rep.Summary, status.Render(rep, status.Style{}))
		}
	})

	t.Run("a worker that has not joined names nothing to probe", func(t *testing.T) {
		mac := stageNodeMac(t, install.RoleAgent, false, true)
		rep, dialled, err := collectFrom(t, mac, install.RoleAgent, false)
		if err == nil {
			t.Fatal("an unjoined worker resolved credentials; it holds none")
		}
		if len(dialled) != 0 {
			t.Errorf("an unjoined worker dialled %v", dialled)
		}
		api, ok := rep.Row(status.RowAPIServer)
		if !ok {
			t.Fatal("no apiserver row")
		}
		if !strings.Contains(api.Detail, "has not joined") {
			t.Errorf("apiserver row = %q, want it to say this Mac has not joined", api.Detail)
		}
		if strings.Contains(api.Detail, "127.0.0.1") {
			t.Errorf("apiserver row names the loopback on an unjoined worker: %q", api.Detail)
		}
	})

	t.Run("a control plane is unchanged: the loopback apiserver and the work dir kubeconfig", func(t *testing.T) {
		mac := stageNodeMac(t, install.RoleServer, false, true)
		rep, dialled, err := collectFrom(t, mac, install.RoleServer, true)
		if err != nil {
			t.Fatalf("a control plane could not resolve its own kubeconfig: %v", err)
		}
		if len(dialled) == 0 {
			t.Fatal("a control plane dialled nothing")
		}
		for _, url := range dialled {
			if !strings.HasPrefix(url, staleServerKubeconfigURL) {
				t.Errorf("a control plane dialled %q, want %s", url, staleServerKubeconfigURL)
			}
		}
		kc, _ := rep.Row(status.RowKubeconfig)
		if want := executor.KubeconfigPath(mac.paths.WorkDir); !strings.Contains(kc.Detail, want) {
			t.Errorf("kubeconfig row = %q, want the work dir's admin kubeconfig %s", kc.Detail, want)
		}
		if _, ok := rep.Row(status.RowAgent); ok {
			t.Error("a control plane carries an agent row")
		}
		if rep.Verdict != status.VerdictRunning {
			t.Errorf("verdict = %v (%s)\n%s", rep.Verdict, rep.Summary, status.Render(rep, status.Style{}))
		}
		inst, _ := rep.Row(status.RowInstall)
		if strings.Contains(inst.Detail, "control-plane data directory") {
			t.Errorf("a control plane's install row warns about its own work dir: %q", inst.Detail)
		}
	})

	t.Run("a worker whose apiserver answers is running", func(t *testing.T) {
		mac := stageNodeMac(t, install.RoleAgent, true, false)
		rep, dialled, err := collectFrom(t, mac, install.RoleAgent, true)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if len(dialled) == 0 {
			t.Fatal("nothing was dialled")
		}
		api, _ := rep.Row(status.RowAPIServer)
		if api.State != status.StateReady || api.Severity != status.SeverityOK {
			t.Errorf("apiserver row = %s/%v (%s), want ready/ok", api.State, api.Severity, api.Detail)
		}
		if rep.Verdict != status.VerdictRunning {
			t.Errorf("verdict = %v (%s)\n%s", rep.Verdict, rep.Summary, status.Render(rep, status.Style{}))
		}
	})
}
