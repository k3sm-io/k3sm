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

package dev

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/hostnet"
)

// Cluster CIDRs whose lo0 /32 aliases the datapath teardown + pre-flight sweep
// (Lo0Flush) and the --datapath singleton assert key off. They MIRROR the
// hard-coded control-plane values: the apiserver's --service-cluster-ip-range
// (pkg/executor/supervised.go) and the cluster pod CIDR (darwin-net podnet
// ClusterPodCIDR). Kept here as named constants so the flush targets are
// single-sourced for the SIT bash helper too (hack/lib/clusterup.sh lo0_flush).
const (
	// ServiceCIDR is the cluster Service VIP range (matches
	// --service-cluster-ip-range 10.43.0.0/16).
	ServiceCIDR = "10.43.0.0/16"
	// PodCIDR is the cluster pod CIDR (matches darwin-net podnet ClusterPodCIDR
	// 100.64.0.0/10 — the /32 aliases the datapath binds fall inside it).
	PodCIDR = "100.64.0.0/10"
)

// terminateGrace is how long Down waits for a detached server to exit after
// SIGTERM before escalating to SIGKILL.
const terminateGrace = 10 * time.Second

// tierRootless / tierRoot are the privilege tiers recorded in the manifest and
// the fidelity axis.
const (
	tierRootless = "rootless"
	tierRoot     = "root"
)

// ErrDatapathRequiresRoot is returned by Up when --datapath is requested but the
// process is not root. It carries the exact sudo line the operator must run.
var ErrDatapathRequiresRoot = errors.New("dev: --datapath needs root (euid 0)")

// ErrDatapathSingleton is returned when a second --datapath instance is started
// while a live datapath (a 10.43.*/100.64.* lo0 alias) is present — its
// pre-flight lo0 flush would tear the live one down.
var ErrDatapathSingleton = errors.New("dev: a datapath instance is already live (lo0 alias present); k3sm dev supports one --datapath instance at a time")

// UpOptions configures `k3sm dev up`.
type UpOptions struct {
	// Name is the instance name (default "dev").
	Name string
	// Datapath requests the root datapath tier (network=direct); the default is
	// the rootless tier (network=none). --datapath requires euid 0.
	Datapath bool
}

// DownOptions configures `k3sm dev down`.
type DownOptions struct {
	// Name is the instance to tear down (default "dev"); ignored when All is set.
	Name string
	// All tears down EVERY registered instance + sweeps residual lo0 aliases and
	// stale kubeconfig contexts (the reboot-orphan reclaim path).
	All bool
}

// Manager is the `k3sm dev` lifecycle. It owns the durable registry and the
// System seam; the server binary path + euid are injected so tests and the CLI
// share one construction. Out is where banners/notices are written (os.Stdout for
// the CLI).
type Manager struct {
	reg    *Registry
	sys    System
	self   string // absolute path to THIS k3sm binary (re-exec'd as `k3sm server`)
	euid   int
	out    io.Writer
	kubeMg *kubeMerger
}

// ManagerConfig constructs a Manager.
type ManagerConfig struct {
	// Registry is the durable instance store (required).
	Registry *Registry
	// System is the syscall seam (required).
	System System
	// Self is the absolute path to the running k3sm binary, re-exec'd as
	// `k3sm server` for the detached control plane (required).
	Self string
	// EUID is the effective uid of the current process (os.Geteuid()).
	EUID int
	// Out is where user-facing output (banners, notices) is written; defaults to
	// os.Stdout when nil.
	Out io.Writer
}

// NewManager builds a Manager from cfg.
func NewManager(cfg ManagerConfig) *Manager {
	out := cfg.Out
	if out == nil {
		out = os.Stdout
	}
	name, uid, gid, underSudo := invokingUser()
	km := &kubeMerger{}
	if underSudo {
		km.chownUser, km.chownUID, km.chownGID = name, uid, gid
	} else {
		km.chownUID, km.chownGID = -1, -1
	}
	return &Manager{
		reg:    cfg.Registry,
		sys:    cfg.System,
		self:   cfg.Self,
		euid:   cfg.EUID,
		out:    out,
		kubeMg: km,
	}
}

// Up boots (or re-attaches to) a disposable dev instance: it allocates
// per-instance (name × euid) ports + workdir, pre-flight-reclaims any crashed
// prior run, spawns a detached `k3sm server` (runtimed + network=none rootless,
// or network=direct under --datapath), merges the kubeconfig into ~/.kube/config
// as context k3sm-dev-<name>, writes the durable manifest, and prints the tier's
// fidelity banner. It fails fast (never a silent degrade) on a --datapath posture
// miss, a live-datapath singleton violation, or a workdir/port collision.
func (m *Manager) Up(ctx context.Context, opts UpOptions) (Instance, error) {
	name := opts.Name
	if name == "" {
		name = "dev"
	}

	tier := tierRootless
	network := hostnet.NetworkNone
	datapath := DatapathNone
	if opts.Datapath {
		if m.euid != 0 {
			return Instance{}, fmt.Errorf("%w: re-run: sudo %s dev up --datapath --name %s", ErrDatapathRequiresRoot, m.self, name)
		}
		tier = tierRoot
		network = hostnet.NetworkDirect
		datapath = DatapathDirect
	}

	// --datapath singleton: a second datapath `up` must fail fast BEFORE its
	// pre-flight flush runs, else that flush tears the live datapath instance's
	// aliases down. The lock guards concurrent racers; the alias assert guards a
	// still-live prior instance whose lock was released but whose kernel aliases
	// persist.
	if opts.Datapath {
		unlock, err := m.sys.LockFile(m.datapathLockPath())
		if err != nil {
			return Instance{}, fmt.Errorf("%w: %v", ErrDatapathSingleton, err)
		}
		defer func() { _ = unlock() }()
		present, err := hasAliasInCIDRs(m.sys, ServiceCIDR, PodCIDR)
		if err != nil {
			return Instance{}, fmt.Errorf("datapath singleton pre-check: %w", err)
		}
		if present {
			return Instance{}, ErrDatapathSingleton
		}
	}

	workDir := m.workDir(name)

	// Pre-flight reclaim: self-heal a crashed prior run under this name — reap a
	// stale pid, flush its lo0 aliases, and re-assert ports. Reads the OLD
	// manifest if present; a missing one is a clean first boot.
	if err := m.preflightReclaim(name); err != nil {
		return Instance{}, err
	}

	apiPort, kinePort, err := allocatePorts(m.sys, name, m.euid)
	if err != nil {
		return Instance{}, err
	}

	// Boot the config-superset via a detached `k3sm server`: --psa-enforce-baseline
	// (so the M10 PSA cutover criterion works) + K3SM_WORK_DIR exported (so the
	// audit/PSA e2e read the SAME workdir). runtimed is the ONLY runtime (never
	// hostprocess — it has no Seatbelt). The rootless tier is network=none
	// (runtimePreflight returns nil — no root); --datapath is network=direct.
	pid, err := m.spawnServer(ctx, name, workDir, apiPort, network)
	if err != nil {
		return Instance{}, err
	}

	inst := Instance{
		Version:     registryVersion,
		Name:        name,
		WorkDir:     workDir,
		APIPort:     apiPort,
		KinePort:    kinePort,
		PID:         pid,
		Tier:        tier,
		Datapath:    datapath,
		ServiceCIDR: ServiceCIDR,
		PodCIDR:     PodCIDR,
		EUID:        m.euid,
		KubeContext: kubeContextName(name),
		CreatedAt:   time.Now().UTC(),
	}

	// Wait for the server to write its kubeconfig, then merge it. On any failure
	// after the spawn we tear the detached server down so a half-up instance never
	// leaks.
	kc := executor.KubeconfigPath(workDir)
	if err := m.awaitKubeconfig(ctx, kc); err != nil {
		_ = m.sys.TerminateProcess(pid, terminateGrace)
		return Instance{}, err
	}
	if err := m.kubeMg.merge(kc, inst.KubeContext); err != nil {
		_ = m.sys.TerminateProcess(pid, terminateGrace)
		return Instance{}, fmt.Errorf("merge kubeconfig: %w", err)
	}

	// Under sudo, hand the workdir back to the invoking human so the next rootless
	// run doesn't EACCES on a root-owned tree.
	if m.kubeMg.chownUID >= 0 {
		if err := chownTree(workDir, m.kubeMg.chownUID, m.kubeMg.chownGID); err != nil {
			fmt.Fprintf(m.out, "warning: could not chown workdir to %s: %v\n", m.kubeMg.chownUser, err)
		}
	}

	if err := m.reg.Save(inst); err != nil {
		_ = m.sys.TerminateProcess(pid, terminateGrace)
		return Instance{}, err
	}
	if m.kubeMg.chownUID >= 0 {
		_ = chownTree(m.reg.dir(name), m.kubeMg.chownUID, m.kubeMg.chownGID)
	}

	fmt.Fprint(m.out, FidelityBanner(datapath))
	fmt.Fprintf(m.out, "\ninstance %q up — apiserver 127.0.0.1:%d · context %s · kubeconfig %s\n", name, apiPort, inst.KubeContext, kc)
	return inst, nil
}

// Down tears an instance (or, with --all, every instance) down: SIGTERM the
// detached server's process group, flush the instance's Service+pod lo0 aliases
// (cluster_down does NOT reap kernel-global aliases), remove the kubeconfig
// context, and delete the registry entry.
func (m *Manager) Down(ctx context.Context, opts DownOptions) error {
	if opts.All {
		return m.downAll(ctx)
	}
	name := opts.Name
	if name == "" {
		name = "dev"
	}
	inst, err := m.reg.Load(name)
	if err != nil {
		return err
	}
	return m.teardown(inst)
}

// downAll sweeps EVERY registered instance, then a belt-and-braces global lo0
// flush + no-instances state, so a reboot's orphans self-heal even if a manifest
// was lost. It reports the first teardown error but attempts every instance.
func (m *Manager) downAll(ctx context.Context) error {
	insts, err := m.reg.List()
	if err != nil {
		return err
	}
	var firstErr error
	for _, inst := range insts {
		if terr := m.teardown(inst); terr != nil && firstErr == nil {
			firstErr = terr
		}
	}
	// Belt-and-braces: flush any residual cluster lo0 aliases even if no manifest
	// referenced them (a lost-manifest orphan). Root-only; a rootless caller has
	// none to flush.
	if m.euid == 0 {
		if removed, ferr := lo0FlushCIDRs(m.sys, ServiceCIDR, PodCIDR); ferr != nil && firstErr == nil {
			firstErr = ferr
		} else if len(removed) > 0 {
			fmt.Fprintf(m.out, "flushed %d residual lo0 alias(es): %v\n", len(removed), removed)
		}
	}
	fmt.Fprintf(m.out, "down --all: %d instance(s) reclaimed\n", len(insts))
	return firstErr
}

// teardown stops one instance's server, flushes its lo0 aliases, removes its
// kubeconfig context, and deletes its registry entry. Best-effort per step: a
// step failure is reported but never blocks the rest (a wedged instance must
// still be reclaimable).
func (m *Manager) teardown(inst Instance) error {
	if inst.PID > 0 && m.sys.ProcessAlive(inst.PID) {
		if err := m.sys.TerminateProcess(inst.PID, terminateGrace); err != nil {
			fmt.Fprintf(m.out, "warning: terminate %q pid %d: %v\n", inst.Name, inst.PID, err)
		}
	}
	// Flush the instance's Service+pod lo0 aliases (datapath tier only allocates
	// them; the rootless tier's flush is a no-op over an empty set). Root-only.
	if inst.Datapath == DatapathDirect && m.euid == 0 {
		if removed, err := lo0FlushCIDRs(m.sys, inst.ServiceCIDR, inst.PodCIDR); err != nil {
			fmt.Fprintf(m.out, "warning: lo0 flush for %q: %v\n", inst.Name, err)
		} else if len(removed) > 0 {
			fmt.Fprintf(m.out, "flushed lo0 alias(es) for %q: %v\n", inst.Name, removed)
		}
	}
	if err := m.kubeMg.remove(inst.KubeContext); err != nil {
		fmt.Fprintf(m.out, "warning: remove kubeconfig context %q: %v\n", inst.KubeContext, err)
	}
	if err := m.reg.Remove(inst.Name); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("remove registry entry %q: %w", inst.Name, err)
	}
	fmt.Fprintf(m.out, "instance %q down\n", inst.Name)
	return nil
}

// List returns the durable registry, each entry annotated (via the ALIVE field
// the caller renders) with current process liveness cross-checked against the
// System seam — so a stale pid from a crashed run reads not-alive without the
// manifest being lost.
func (m *Manager) List() ([]InstanceStatus, error) {
	insts, err := m.reg.List()
	if err != nil {
		return nil, err
	}
	out := make([]InstanceStatus, 0, len(insts))
	for _, inst := range insts {
		out = append(out, InstanceStatus{Instance: inst, Alive: inst.PID > 0 && m.sys.ProcessAlive(inst.PID)})
	}
	return out, nil
}

// InstanceStatus is a registry entry plus its current process liveness.
type InstanceStatus struct {
	Instance
	// Alive reports whether the recorded PID is a live process right now (the
	// durable manifest survives sleep/reboot; Alive tells `list` if the server is
	// still running or needs a re-`up`).
	Alive bool
}

// Load stages a native-arm64 binary for the dev cluster and returns the
// `image: <abs>` line (the no-command host-binary convention runtimed's
// resolveBinary supports) STAMPED non-portable. It does not copy the binary
// anywhere — the staged path IS the absolute path the operator passes as a pod's
// image — but it validates the path exists and is absolute so a bad reference is
// caught here, not at pod admission. The honest `kind load` analog: k3sm has no
// Docker images, so the stamp warns the ref won't work on real k8s or k3sm's
// OCI/vm paths.
func (m *Manager) Load(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stage binary %s: %w", abs, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("stage binary %s: is a directory, want a native-arm64 executable", abs)
	}
	line := LoadImageLine(abs)
	fmt.Fprintln(m.out, line)
	return line, nil
}

// preflightReclaim self-heals a crashed prior run under name: if an old manifest
// exists it reaps its (possibly stale) pid, flushes its lo0 aliases, and removes
// its kubeconfig context, so the fresh boot starts clean. A missing manifest is a
// clean first boot (nil). Idempotent and best-effort — a reclaim step failure is
// reported, not fatal.
func (m *Manager) preflightReclaim(name string) error {
	inst, err := m.reg.Load(name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if inst.PID > 0 && m.sys.ProcessAlive(inst.PID) {
		fmt.Fprintf(m.out, "reclaiming prior instance %q (pid %d)\n", name, inst.PID)
		_ = m.sys.TerminateProcess(inst.PID, terminateGrace)
	}
	if inst.Datapath == DatapathDirect && m.euid == 0 {
		if _, ferr := lo0FlushCIDRs(m.sys, inst.ServiceCIDR, inst.PodCIDR); ferr != nil {
			fmt.Fprintf(m.out, "warning: pre-flight lo0 flush for %q: %v\n", name, ferr)
		}
	}
	_ = m.kubeMg.remove(inst.KubeContext)
	return nil
}

// spawnServer starts a detached `k3sm server` (this binary re-exec'd) in its own
// process group with the config-superset argv, redirecting its output to
// <workDir>/server.log, and returns its pid. It does NOT wait — the server runs
// until `down` SIGTERMs it. K3SM_WORK_DIR is exported so the M10 audit/PSA e2e
// read the same workdir.
func (m *Manager) spawnServer(ctx context.Context, name, workDir string, apiPort int, network string) (int, error) {
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return 0, fmt.Errorf("create workdir %s: %w", workDir, err)
	}
	logPath := filepath.Join(workDir, "server.log")
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create server log: %w", err)
	}
	defer lf.Close()

	args := []string{
		"server",
		"--work-dir", workDir,
		"--node-name", "k3sm-dev-" + name,
		"--node-ip", "127.0.0.1",
		"--runtime", "runtimed",
		"--network", network,
		"--api-port", strconv.Itoa(apiPort),
		"--psa-enforce-baseline",
		// Disable the ingress listeners: the dev cluster does not front an ingress,
		// and the production :80/:443 bind needs privileges the rootless tier lacks.
		"--ingress-http-port", "0",
		"--ingress-https-port", "0",
	}
	cmd := exec.CommandContext(ctx, m.self, args...)
	cmd.Stdout, cmd.Stderr = lf, lf
	// Own process group so `down` can SIGTERM the whole supervised tree via -pid,
	// and detached from ctx cancellation (WaitDelay 0 + no Cancel) so the server
	// outlives the `k3sm dev up` CLI invocation.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return nil } // ctx cancel must NOT kill the detached server
	cmd.Env = append(os.Environ(), "K3SM_WORK_DIR="+workDir)
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start k3sm server: %w", err)
	}
	pid := cmd.Process.Pid
	// Release the child: a reaper goroutine Waits so the process is not left a
	// zombie if this CLI lingers, but the server keeps running independently.
	go func() { _ = cmd.Wait() }()
	return pid, nil
}

// awaitKubeconfig blocks until the detached server has written its admin
// kubeconfig (its readiness signal for the merge), bounded so a wedged bring-up
// fails with an actionable error instead of hanging.
func (m *Manager) awaitKubeconfig(ctx context.Context, kc string) error {
	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, err := os.Stat(kc); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("k3sm server did not write %s within 90s (see the server.log beside it)", kc)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// workDir is the per-instance control-plane state root: <root>/<name>/server,
// under the durable registry root so the (name × euid) identity is encoded in the
// path and a rootless vs datapath run never share a tree.
func (m *Manager) workDir(name string) string {
	return filepath.Join(m.reg.dir(name), "server")
}

// datapathLockPath is the flock file guarding the --datapath singleton (under the
// registry root, shared across instances of the current user).
func (m *Manager) datapathLockPath() string {
	return filepath.Join(m.reg.root, "datapath.lock")
}

// kubeContextName is the ~/.kube/config context an instance merges as.
func kubeContextName(name string) string { return "k3sm-dev-" + name }
