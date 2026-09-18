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
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/dataroot"
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

// deadRuntimed is a runtime daemon that does not answer. It is the arm of the
// runtimed row that carries a remedy, which is why the worker gate wires it:
// the remedy names a launchd job, and on a worker that job is the agent.
type deadRuntimed struct{}

func (deadRuntimed) Info(context.Context) (*runtimev1.GetRuntimeInfoResponse, error) {
	return nil, errors.New("dial unix: connect: no such file or directory")
}

// shadowedDataRoot is a data root DECLARED in /etc/fstab with nothing mounted
// there — the shadow, whose remedy ends in a kickstart of netd and this Mac's
// node daemon. No unprivileged test can create the posture for real, so the
// declaration is served through the seam.
type shadowedDataRoot struct{ plainDataRoot }

func (d shadowedDataRoot) ReadFile(path string) ([]byte, error) {
	if path == dataroot.FstabPath {
		return []byte("UUID=1234-ABCD " + d.dir + " apfs rw 0 0\n"), nil
	}
	return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

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

// macOpts describes the Mac to stage: which role's plist(s) are on disk, and
// which of the two state directories a previous life left behind.
type macOpts struct {
	role install.Role
	// joined stages a complete node credential store under the data root.
	joined bool
	// serverWorkDir stages a control-plane work dir with an admin kubeconfig —
	// on an agent Mac, the stale leftover this gate is about.
	serverWorkDir bool
	// bothRoles additionally lays down the OTHER role's plist, the posture
	// `k3sm install` refuses to create and RoleFromPlists resolves to server.
	bothRoles bool
	// credentialAddress issues the staged kubelet serving certificate for THIS
	// address instead of the one the assignment names. It is the on-disk shape
	// of a node that joined asserting a `--node-ip` the control plane did not
	// assign: the node registers the assigned address, and its certificate
	// names another one (B340).
	credentialAddress string
	// unreadableCredential makes the staged credential store unreadable by
	// this account: the ordinary posture of an unprivileged `k3sm status`
	// against a service-user-owned store.
	unreadableCredential bool
	// stateDB stages a kine state.db inside the control-plane work dir, with
	// this SQLite write-format byte in its header (2 = wal, 1 = rollback).
	// Zero stages none. On an agent Mac it is the dead database the stale
	// directory carries, which is what B333 is about.
	stateDB byte
	// unreadableStateDB makes that staged database unreadable by this account.
	// It changes nothing a report may print — which is the point: a row that
	// reads the file cannot help printing something different.
	unreadableStateDB bool
}

// stageNodeMac writes an install tree for one role under a temp dir.
func stageNodeMac(t *testing.T, opts macOpts) nodeMac {
	t.Helper()
	role := opts.role
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
	if opts.bothRoles {
		other := install.ServerLabel
		if nodeLabel == install.ServerLabel {
			other = install.AgentLabel
		}
		touch(filepath.Join(ldDir, other+".plist"))
	}
	socket := filepath.Join(runDir, "netd.sock")
	touch(socket)

	workDir := filepath.Join(dataRoot, "server")
	if opts.serverWorkDir {
		kc := executor.KubeconfigPath(workDir)
		mkdirAll := filepath.Dir(kc)
		if err := os.MkdirAll(mkdirAll, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", mkdirAll, err)
		}
		writeAdminKubeconfig(t, kc, staleServerKubeconfigURL)
	}
	if opts.stateDB != 0 {
		db := executor.StateDBPath(workDir)
		if err := os.MkdirAll(filepath.Dir(db), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(db), err)
		}
		writeSQLiteHeader(t, db, opts.stateDB, staleUserVersion)
		if opts.unreadableStateDB {
			if err := os.Chmod(db, 0o000); err != nil {
				t.Fatalf("chmod %s: %v", db, err)
			}
			t.Cleanup(func() { _ = os.Chmod(db, 0o600) })
		}
	}
	if opts.joined {
		store := nodeCredentialStore{dir: filepath.Dir(install.AgentCredentialPath(dataRoot))}
		if err := os.MkdirAll(store.dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", store.dir, err)
		}
		res, clusterCA, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		if opts.credentialAddress != "" {
			cert, key, err := clusterCA.IssueServing(nodeCredTestNode,
				[]string{nodeCredTestNode, "localhost"},
				[]net.IP{net.ParseIP(opts.credentialAddress)}, nodeCredClientTTL)
			if err != nil {
				t.Fatalf("issue a kubelet serving pair for %s: %v", opts.credentialAddress, err)
			}
			res.KubeletServingCertPEM, res.KubeletServingKeyPEM = cert, key
		}
		if err := store.Save(nodeCredTestAPI, nodeCredTestNode, res); err != nil {
			t.Fatalf("save the node credential: %v", err)
		}
		if opts.unreadableCredential {
			// 0000 on the DIRECTORY, so every path inside it answers EACCES —
			// which is what an ordinary account gets against the real store,
			// whose owner is the service user.
			if err := os.Chmod(store.dir, 0o000); err != nil {
				t.Fatalf("chmod %s: %v", store.dir, err)
			}
			t.Cleanup(func() { _ = os.Chmod(store.dir, 0o700) })
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

// staleUserVersion is the schema version the staged database's header carries.
// It is a value a report would have to have READ the file to know, so it is what
// the worker rows below assert never appears.
const staleUserVersion = 7

// writeSQLiteHeader writes a minimal 100-byte SQLite database header: the magic
// at offset 0, the write-format byte at 18 (2 = wal, 1 = rollback) and the
// user_version at 60. It is not a database — DatastorePosture reads the header
// and nothing else, which is how it stays a read-only probe.
func writeSQLiteHeader(t *testing.T, path string, writeVersion byte, userVersion uint32) {
	t.Helper()
	var hdr [100]byte
	copy(hdr[0:16], "SQLite format 3\x00")
	hdr[18], hdr[19] = writeVersion, writeVersion
	binary.BigEndian.PutUint32(hdr[60:64], userVersion)
	if err := os.WriteFile(path, hdr[:], 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
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
func collectFrom(t *testing.T, mac nodeMac, role install.Role, ready bool, tweak ...func(*status.Collector)) (status.Report, []string, error) {
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
	for _, f := range tweak {
		f(&c)
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
		mac := stageNodeMac(t, macOpts{role: install.RoleAgent, joined: true, serverWorkDir: true})
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
		mac := stageNodeMac(t, macOpts{role: install.RoleAgent, serverWorkDir: true})
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
		mac := stageNodeMac(t, macOpts{role: install.RoleServer, serverWorkDir: true})
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

	t.Run("a credential store this account may not read names sudo, never a rejoin", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads every directory regardless of mode")
		}
		mac := stageNodeMac(t, macOpts{role: install.RoleAgent, joined: true, unreadableCredential: true})
		rep, dialled, err := collectFrom(t, mac, install.RoleAgent, false)
		if err == nil {
			t.Fatal("an unreadable credential store resolved credentials")
		}
		if !strings.Contains(err.Error(), "not readable") || !strings.Contains(err.Error(), "sudo") {
			t.Errorf("resolution error = %q, want it to name the permission problem and sudo", err)
		}
		if len(dialled) != 0 {
			t.Errorf("a report that could not read the credential dialled %v", dialled)
		}
		api, ok := rep.Row(status.RowAPIServer)
		if !ok {
			t.Fatal("no apiserver row")
		}
		if api.Remedy != "sudo k3sm status" {
			t.Errorf("apiserver remedy = %q, want the sudo re-run", api.Remedy)
		}
		if strings.Contains(api.Remedy, "k3sm token create") {
			t.Errorf("an unreadable credential store was answered with a rejoin: %q", api.Remedy)
		}
	})

	t.Run("an absent credential store is answered with the join", func(t *testing.T) {
		mac := stageNodeMac(t, macOpts{role: install.RoleAgent})
		rep, _, err := collectFrom(t, mac, install.RoleAgent, false)
		if err == nil {
			t.Fatal("an unjoined worker resolved credentials")
		}
		api, ok := rep.Row(status.RowAPIServer)
		if !ok {
			t.Fatal("no apiserver row")
		}
		if !strings.Contains(api.Remedy, "k3sm token create") {
			t.Errorf("apiserver remedy = %q, want the join remedy", api.Remedy)
		}
	})

	t.Run("a Mac carrying both node daemons reports the server's credentials", func(t *testing.T) {
		// RoleFromPlists resolves both-plists to the server — the posture
		// `k3sm install` refuses to create — so the credential choice must
		// follow it and take the work dir's admin kubeconfig, even though a
		// node credential is sitting right there.
		role, installed := install.RoleFromPlists(true, true)
		if role != install.RoleServer || !installed {
			t.Fatalf("RoleFromPlists(true, true) = %q/%t, want the server role", role, installed)
		}
		mac := stageNodeMac(t, macOpts{role: install.RoleServer, joined: true, serverWorkDir: true, bothRoles: true})
		rep, dialled, err := collectFrom(t, mac, role, true)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		for _, url := range dialled {
			if !strings.HasPrefix(url, staleServerKubeconfigURL) {
				t.Errorf("dialled %q, want the server's own apiserver %s", url, staleServerKubeconfigURL)
			}
		}
		kc, _ := rep.Row(status.RowKubeconfig)
		if want := executor.KubeconfigPath(mac.paths.WorkDir); !strings.Contains(kc.Detail, want) {
			t.Errorf("kubeconfig row = %q, want the work dir's admin kubeconfig %s", kc.Detail, want)
		}
	})

	t.Run("a worker whose apiserver answers is running", func(t *testing.T) {
		mac := stageNodeMac(t, macOpts{role: install.RoleAgent, joined: true})
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

// TestStatusKubeconfigDistinguishesAbsentFromUnreadable pins the credential
// choice's three answers on the agent role. fileExists cannot tell a missing
// file from one this account may not stat, and the two have opposite remedies:
// one is a worker that never joined, the other is a perfectly joined worker
// being read by an unprivileged command.
func TestStatusKubeconfigDistinguishesAbsentFromUnreadable(t *testing.T) {
	t.Parallel()

	const nodeKubeconfig = "/var/lib/k3sm/agent/node.kubeconfig"
	tests := []struct {
		name     string
		stat     func(string) error
		wantPath string
		wantErr  []string
	}{
		{"a readable credential is the kubeconfig", func(string) error { return nil }, nodeKubeconfig, nil},
		{"an absent credential says so",
			func(p string) error { return &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist} },
			"", []string{"no node credential", nodeKubeconfig}},
		{"an unreadable credential names sudo",
			func(p string) error { return &fs.PathError{Op: "stat", Path: p, Err: fs.ErrPermission} },
			"", []string{"not readable", "sudo", nodeKubeconfig}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := statusKubeconfig(statusKubeInputs{
				role:           install.RoleAgent,
				nodeKubeconfig: nodeKubeconfig,
				workDir:        "/var/lib/k3sm/server",
				exists:         func(string) bool { return true },
				stat:           tc.stat,
			})
			if tc.wantPath != "" {
				if err != nil {
					t.Fatalf("resolve: %v", err)
				}
				if cfg.kubeconfig != tc.wantPath {
					t.Errorf("kubeconfig = %q, want %q", cfg.kubeconfig, tc.wantPath)
				}
				return
			}
			if err == nil {
				t.Fatalf("resolved %+v, want an error", cfg)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// TestStatusOnAWorkerRendersNoControlPlaneRows is the B333 gate.
//
// The defect, seen on the two-Mac rig after a worker rejoin and a residual of
// B324: a Mac installed as an agent still carried the <DataRoot>/server
// directory an earlier server-era install left behind, and `k3sm status` PROBED
// the dead kine database inside it. The report then read "datastore ok kine
// sqlite, wal, user_version 0" — a fact about a database no daemon on this Mac
// has opened since the install changed role — and the datastore row's own
// non-wal arm offered "k3sm status logs server", a log no daemon here writes.
//
// The row that carried that remedy is the DATASTORE row (pkg/status/rows.go,
// the `jm != "wal"` arm); the worker-advisory map only kept it from moving the
// verdict. A worker runs no control plane and therefore no kine, so the row now
// says so and reads nothing at all.
func TestStatusOnAWorkerRendersNoControlPlaneRows(t *testing.T) {
	// serverLog is the remedy string the stale directory used to produce here,
	// and serverLabel the daemon this Mac does not run. Neither may appear
	// anywhere in a worker's report.
	const serverLog = "k3sm status logs server"
	serverLabel := install.ServerLabel

	t.Run("a worker with a stale server database reports no datastore of its own", func(t *testing.T) {
		mac := stageNodeMac(t, macOpts{role: install.RoleAgent, joined: true, serverWorkDir: true, stateDB: 2})
		rep, _, err := collectFrom(t, mac, install.RoleAgent, false)
		if err != nil {
			t.Fatalf("a joined worker could not resolve its own credentials: %v", err)
		}

		ds, ok := rep.Row(status.RowDatastore)
		if !ok {
			// The row NAME stays on a worker: it is a stable `-o json` key, and
			// a key that comes and goes with the role is worse to consume than
			// one that says the subsystem is not this node's.
			t.Fatalf("the datastore row is gone from a worker's report; it must remain as a stable JSON key\n%s",
				status.Render(rep, status.Style{}))
		}
		if ds.State != status.StateSkip || ds.Severity != status.SeveritySkip {
			t.Errorf("datastore row = %s/%v (%q), want skip/skip", ds.State, ds.Severity, ds.Detail)
		}
		if ds.Detail != status.WorkerDatastoreDetail {
			t.Errorf("datastore detail = %q, want %q", ds.Detail, status.WorkerDatastoreDetail)
		}
		if ds.Remedy != "" {
			t.Errorf("datastore remedy = %q; there is nothing here to repair", ds.Remedy)
		}
		for k, v := range ds.Wide {
			if strings.Contains(v, mac.paths.WorkDir) {
				t.Errorf("datastore wide %q names the stale control-plane directory: %q", k, v)
			}
		}

		// Every remedy in the report, because the Next block is nothing but the
		// rows' remedies deduped in severity order: a worker whose rows name no
		// server daemon can never offer one as a next step, in any verdict.
		for _, row := range rep.Rows {
			if strings.Contains(row.Remedy, serverLog) || strings.Contains(row.Remedy, serverLabel) {
				t.Errorf("row %q offers a remedy naming the server daemon on a worker: %q", row.Name, row.Remedy)
			}
		}
		for _, step := range rep.Next {
			if strings.Contains(step, serverLog) || strings.Contains(step, serverLabel) {
				t.Errorf("the Next block names the server daemon on a worker: %q", step)
			}
		}

		// The rendered screens, overview and cluster: the cluster view prints
		// every row's fix lines, so it is where a stale remedy shows up
		// regardless of the verdict.
		for name, screen := range map[string]string{
			"overview": status.Render(rep, status.Style{}),
			"cluster":  status.RenderCluster(rep, status.Style{}),
		} {
			for _, unwanted := range []string{"kine sqlite", serverLog, serverLabel, fmt.Sprintf("user_version %d", staleUserVersion)} {
				if strings.Contains(screen, unwanted) {
					t.Errorf("the %s screen on a worker contains %q:\n%s", name, unwanted, screen)
				}
			}
			if !strings.Contains(screen, status.WorkerDatastoreDetail) {
				t.Errorf("the %s screen does not say the datastore is not this node's:\n%s", name, screen)
			}
		}
	})

	t.Run("the worker's datastore row does not depend on the file, so nothing opened it", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads every file regardless of mode")
		}
		// The probe is os.Stat + os.Open (DatastorePosture), not an FS seam, so
		// "was it opened" is asserted the only way that is honest here: the
		// same Mac with the database made UNREADABLE must produce a
		// byte-identical row. A row that read the file could not: it would fall
		// into the permission arm ("state.db not readable as this user") and
		// offer the sudo re-run.
		readable := workerDatastoreRow(t, false)
		unreadable := workerDatastoreRow(t, true)
		if !reflect.DeepEqual(readable, unreadable) {
			t.Errorf("the datastore row changed when the stale database became unreadable, so the row reads it:\n readable   = %+v\n unreadable = %+v",
				readable, unreadable)
		}
		if unreadable.Detail != status.WorkerDatastoreDetail || unreadable.Remedy != "" {
			t.Errorf("datastore row = %q / remedy %q, want the worker sentence and no remedy", unreadable.Detail, unreadable.Remedy)
		}
	})

	t.Run("a control plane is unchanged: it reports and repairs its own datastore", func(t *testing.T) {
		wal := stageNodeMac(t, macOpts{role: install.RoleServer, serverWorkDir: true, stateDB: 2})
		rep, _, err := collectFrom(t, wal, install.RoleServer, true)
		if err != nil {
			t.Fatalf("a control plane could not resolve its own kubeconfig: %v", err)
		}
		ds, ok := rep.Row(status.RowDatastore)
		if !ok {
			t.Fatal("no datastore row on a control plane")
		}
		want := status.Row{
			Name:     status.RowDatastore,
			State:    status.StateOK,
			Severity: status.SeverityOK,
			Detail:   fmt.Sprintf("kine sqlite, wal, user_version %d", staleUserVersion),
			Wide:     map[string]string{"path": executor.StateDBPath(wal.paths.WorkDir)},
		}
		if !reflect.DeepEqual(ds, want) {
			t.Errorf("server datastore row =\n %+v\nwant\n %+v", ds, want)
		}
		// The whole server overview, pinned: states and remedies, in order. A
		// healthy control plane repairs nothing, so every remedy is empty and
		// the single next step is the one a running cluster gets.
		wantRows := []struct{ name, state string }{
			{status.RowInstall, "ok"}, {status.RowNetd, "running"}, {status.RowServer, "running"},
			{status.RowAPIServer, "ready"}, {status.RowNode, "ready"}, {status.RowWorkloads, "ok"},
			{status.RowDataRoot, "ok"}, {status.RowDatastore, "ok"}, {status.RowKubeconfig, "ok"},
		}
		for _, w := range wantRows {
			row, ok := rep.Row(w.name)
			if !ok {
				t.Errorf("server row %q missing", w.name)
				continue
			}
			if string(row.State) != w.state {
				t.Errorf("server row %q state = %q, want %q (%s)", w.name, row.State, w.state, row.Detail)
			}
			if row.Remedy != "" {
				t.Errorf("server row %q carries a remedy on a healthy control plane: %q", w.name, row.Remedy)
			}
		}
		if got := rep.Next; len(got) != 1 || got[0] != "k3sm kubectl get pods -A" {
			t.Errorf("server Next = %q, want the running step", got)
		}

		// And the non-wal arm, which is where "k3sm status logs server" comes
		// from: on a control plane it is exactly right, and it is unchanged.
		rollback := stageNodeMac(t, macOpts{role: install.RoleServer, serverWorkDir: true, stateDB: 1})
		rep, _, err = collectFrom(t, rollback, install.RoleServer, true)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		ds, _ = rep.Row(status.RowDatastore)
		want = status.Row{
			Name:     status.RowDatastore,
			State:    status.StateNotReady,
			Severity: status.SeverityWarn,
			Detail:   fmt.Sprintf("kine sqlite, rollback, user_version %d (expected wal)", staleUserVersion),
			Remedy:   serverLog,
			Wide:     map[string]string{"path": executor.StateDBPath(rollback.paths.WorkDir)},
		}
		if !reflect.DeepEqual(ds, want) {
			t.Errorf("server datastore row (non-wal) =\n %+v\nwant\n %+v", ds, want)
		}
	})

	t.Run("a worker's repairs name its own daemon, never the server's", func(t *testing.T) {
		// The two rows whose remedies restart a node daemon: the runtime daemon
		// that did not answer, and the shadowed data root that has to be
		// re-opened once it is mounted. Both used to name io.k3sm.server, a
		// launchd job a worker's Mac does not have — `k3sm install --role agent`
		// never writes that plist, so the operator's kickstart fails with
		// "could not find service".
		mac := stageNodeMac(t, macOpts{role: install.RoleAgent, joined: true, serverWorkDir: true, stateDB: 2})
		rep, _, err := collectFrom(t, mac, install.RoleAgent, false, func(c *status.Collector) {
			c.Runtimed = deadRuntimed{}
			c.DataRoot = shadowedDataRoot{plainDataRoot{dir: mac.paths.DataRoot}}
		})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		rt, ok := rep.Row(status.RowRuntimed)
		if !ok || rt.Remedy == "" {
			t.Fatalf("the runtimed row carries no remedy, so this case proves nothing: %+v", rt)
		}
		dr, ok := rep.Row(status.RowDataRoot)
		if !ok || dr.Remedy == "" {
			t.Fatalf("the data-root row carries no remedy, so this case proves nothing: %+v", dr)
		}
		if want := "sudo launchctl kickstart -k system/" + install.AgentLabel; rt.Remedy != want {
			t.Errorf("runtimed remedy on a worker = %q, want %q", rt.Remedy, want)
		}
		if !strings.Contains(dr.Remedy, "sudo launchctl kickstart -k system/"+install.AgentLabel) {
			t.Errorf("data-root remedy on a worker = %q, want it to kickstart %s", dr.Remedy, install.AgentLabel)
		}
		for _, row := range rep.Rows {
			if strings.Contains(row.Remedy, serverLabel) || strings.Contains(row.Remedy, serverLog) {
				t.Errorf("row %q names the server daemon on a worker: %q", row.Name, row.Remedy)
			}
		}
		for _, step := range rep.Next {
			if strings.Contains(step, serverLabel) || strings.Contains(step, serverLog) {
				t.Errorf("the Next block names the server daemon on a worker: %q", step)
			}
		}
		if screen := status.RenderCluster(rep, status.Style{}); strings.Contains(screen, serverLabel) {
			t.Errorf("the cluster screen on a worker names the server daemon:\n%s", screen)
		}
	})

	t.Run("a control plane's repairs are byte-identical", func(t *testing.T) {
		// The same two arms on a server, pinned as exact strings: this is the
		// output the role-aware helper must not have changed.
		mac := stageNodeMac(t, macOpts{role: install.RoleServer, serverWorkDir: true, stateDB: 2})
		rep, _, err := collectFrom(t, mac, install.RoleServer, true, func(c *status.Collector) {
			c.Runtimed = deadRuntimed{}
			c.DataRoot = shadowedDataRoot{plainDataRoot{dir: mac.paths.DataRoot}}
		})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		rt, _ := rep.Row(status.RowRuntimed)
		if want := "sudo launchctl kickstart -k system/" + install.ServerLabel; rt.Remedy != want {
			t.Errorf("runtimed remedy on a control plane = %q, want %q", rt.Remedy, want)
		}
		dr, _ := rep.Row(status.RowDataRoot)
		want := fmt.Sprintf("sudo rm -r %s/run && sudo diskutil mount -mountPoint %s <volume>   # the shadow holds only the netd socket\nsudo launchctl kickstart -k system/%s && sudo launchctl kickstart -k system/%s",
			mac.paths.DataRoot, mac.paths.DataRoot, install.NetdLabel, install.ServerLabel)
		if dr.Remedy != want {
			t.Errorf("data-root shadow remedy on a control plane =\n %q\nwant\n %q", dr.Remedy, want)
		}
	})

	t.Run("k3sm doctor says the same sentence about a worker's stale database", func(t *testing.T) {
		present := func() (bool, int, string, error) { return true, staleUserVersion, "wal", nil }

		worker := agentEnv()
		worker.datastorePosture = present
		got := checkDatastore(worker)
		if got.status != statusSkip {
			t.Errorf("doctor datastore on a worker = %v (%q), want skip", got.status, got.detail)
		}
		if got.detail != status.WorkerDatastoreDetail {
			t.Errorf("doctor datastore detail = %q, want %q", got.detail, status.WorkerDatastoreDetail)
		}
		if got.remedy != "" {
			t.Errorf("doctor datastore remedy = %q on a worker; there is nothing here to repair", got.remedy)
		}

		server := healthyDoctorEnv()
		server.datastorePosture = present
		if got := checkDatastore(server); got.status != statusPass || !strings.Contains(got.detail, "kine") {
			t.Errorf("doctor datastore on a control plane = %v (%q), want the unchanged pass", got.status, got.detail)
		}
	})
}

// workerDatastoreRow collects a whole report for a worker whose stale
// control-plane directory holds a WAL database, readable or not, and returns
// its datastore row.
func workerDatastoreRow(t *testing.T, unreadable bool) status.Row {
	t.Helper()
	mac := stageNodeMac(t, macOpts{
		role: install.RoleAgent, joined: true, serverWorkDir: true,
		stateDB: 2, unreadableStateDB: unreadable,
	})
	rep, _, err := collectFrom(t, mac, install.RoleAgent, false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	row, ok := rep.Row(status.RowDatastore)
	if !ok {
		t.Fatal("no datastore row")
	}
	return row
}
