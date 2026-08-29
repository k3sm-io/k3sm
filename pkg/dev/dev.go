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
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

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

// PodRootBasePrefix is the fixed parent of every dev instance's runtimed root —
// the tree holding the per-pod dirs, the image blob cache and, decisively, the
// PVC storage root (<runtime-root>/storage/<namespace>/<claim>).
//
// It sits OUTSIDE the registry root (<home>/.k3sm/dev/<name>) on purpose, and the
// reason is a hard runtimed constraint rather than taste: /Users is one of the
// FIXED system-protected prefixes runtimed's SBPL generator refuses to grant a
// confined pod (runtimed pkg/sandbox systemProtectedPrefixes — "a hostPath-style
// mount can never widen the allow-list into /Users"). runtimed derives each PVC's
// dir from ITS work-dir and hands it to that generator as the pod's read/write
// scope, so with the runtime root under the invoking user's home EVERY
// PVC-backed pod is rejected at sandbox setup — `runtimed create pod … rejected:
// generate sbpl …: extra path is under a protected deny-set` — and sits Pending
// until it is deleted. The installed posture (/var/lib/k3sm) and the acceptance
// harness (hack/lib/clusterup.sh's /tmp/k3sm-cluster) both already keep the
// runtime root clear of /Users; this gives `k3sm dev` the same property.
//
// The euid is part of the directory NAME, not a subdirectory, so a root
// (--datapath) and a rootless instance never need write access to one another's
// 0700 tree — the same (name × euid) identity the registry work-dir encodes. The
// /private spelling is the resolved one: Seatbelt evaluates resolved paths, and
// /var is a symlink to /private/var.
const PodRootBasePrefix = "/private/var/tmp/k3sm-dev"

// terminateGrace is how long Down waits for a detached server to exit after
// SIGTERM before escalating to SIGKILL.
const terminateGrace = 10 * time.Second

// tierRootless / tierRoot are the privilege tiers recorded in the manifest and
// the fidelity axis.
const (
	tierRootless = "rootless"
	tierRoot     = "root"
)

// runtimeRuntimed / runtimeHostProcess are the effective pod runtimes recorded in
// the manifest. They MIRROR cmd/k3sm's --runtime values. runtimed (Seatbelt-
// confined) is the DEFAULT whenever the k3sm-execshim helper is provisionable;
// hostprocess (UNCONFINED — no Seatbelt) is the honest fallback used only when the
// helper cannot be built, so the dev loop stays up instead of dying at runtimed
// init sandbox-backend setup.
const (
	runtimeRuntimed    = "runtimed"
	runtimeHostProcess = "hostprocess"
)

// ErrDatapathRequiresRoot is returned by Up when --datapath is requested but the
// process is not root. It carries the exact sudo line the operator must run.
var ErrDatapathRequiresRoot = errors.New("dev: --datapath needs root (euid 0)")

// ErrServerExited is returned by Up when the detached `k3sm server` it spawned is
// no longer running. It is the EXIT-shaped verdict, and it beats a readiness
// verdict: every probe `up` runs is a statement about a socket or an API object,
// and none of them is falsified by the process serving them having died.
var ErrServerExited = errors.New("dev: the k3sm server exited during bring-up")

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
	// Kubeconfig, when non-empty, is the file the dev context is merged into and
	// selected in. Empty falls back to $KUBECONFIG (first entry) then ~/.kube/config
	// (kind-parity). Set it to keep an existing ~/.kube/config untouched.
	Kubeconfig string
}

// DownOptions configures `k3sm dev down`.
type DownOptions struct {
	// Name is the instance to tear down (default "dev"); ignored when All is set.
	Name string
	// All tears down EVERY registered instance + sweeps residual lo0 aliases and
	// stale kubeconfig contexts (the reboot-orphan reclaim path).
	All bool
	// Kubeconfig mirrors UpOptions.Kubeconfig — the file the dev context is removed
	// from (must match the path used at `up`). Empty resolves the same way.
	Kubeconfig string
}

// Manager is the `k3sm dev` lifecycle. It owns the durable registry and the
// System seam; the server binary path + euid are injected so tests and the CLI
// share one construction. Out is where banners/notices are written (os.Stdout for
// the CLI).
type Manager struct {
	reg         *Registry
	sys         System
	builder     ExecShimBuilder
	shimBuilder PodShimBuilder
	// shimDir is the pod-readable directory the two pod-support DYLD shims are
	// staged into; empty means DefaultPodShimDir. It is a field so a test stages
	// into a temp dir instead of /Library.
	shimDir string
	// podRootBase is the parent of the per-instance runtimed roots; empty means
	// PodRootBasePrefix-<euid>. It is a field, like shimDir, so a test drives the
	// derivation and the teardown removal against a temp dir instead of /private.
	podRootBase string
	self        string // absolute path to THIS k3sm binary (re-exec'd as `k3sm server`)
	euid        int
	out         io.Writer
	kubeMg      *kubeMerger
	// awaitNamespaceBootstrap blocks until the default namespace carries the two
	// objects every pod with a projected service-account token needs. It is a
	// field, not a plain method, so the wait is testable without a live cluster.
	// nil means the production implementation (awaitDefaultNamespaceBootstrap).
	awaitNamespaceBootstrap func(ctx context.Context, kubeconfig string) error
	// awaitNodeRegistration blocks until a node has registered with the fresh
	// control plane AND reports Ready — without it every pod created right after
	// `up` is Unschedulable. Same seam shape as awaitNamespaceBootstrap: a field,
	// not a plain method, so the wait is testable without a live cluster. nil
	// means the production implementation (awaitNodeRegistered).
	awaitNodeRegistration func(ctx context.Context, kubeconfig string) error
}

// ManagerConfig constructs a Manager.
type ManagerConfig struct {
	// Registry is the durable instance store (required).
	Registry *Registry
	// System is the syscall seam (required).
	System System
	// Builder provisions the k3sm-execshim Seatbelt helper (build+sign) the
	// detached runtimed server needs on its PATH. Optional — nil defaults to the
	// production NewExecShimBuilder (go build + codesign); tests inject a fake so
	// no real toolchain runs.
	Builder ExecShimBuilder
	// ShimBuilder provisions the two pod-support DYLD shim dylibs (build+sign) the
	// detached runtimed server injects into pods. Optional — nil defaults to the
	// production NewPodShimBuilder (the owning modules' build scripts + codesign);
	// tests inject a fake so no real clang runs.
	ShimBuilder PodShimBuilder
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
	builder := cfg.Builder
	if builder == nil {
		builder = NewExecShimBuilder()
	}
	shimBuilder := cfg.ShimBuilder
	if shimBuilder == nil {
		shimBuilder = NewPodShimBuilder()
	}
	return &Manager{
		reg:         cfg.Registry,
		sys:         cfg.System,
		builder:     builder,
		shimBuilder: shimBuilder,
		self:        cfg.Self,
		euid:        cfg.EUID,
		out:         out,
		kubeMg:      km,
	}
}

// Up boots (or re-attaches to) a disposable dev instance: it allocates
// per-instance (name × euid) ports + workdir, pre-flight-reclaims any crashed
// prior run, spawns a detached `k3sm server` (runtimed + network=none rootless,
// or network=direct under --datapath), merges the kubeconfig into ~/.kube/config
// as context k3sm-dev-<name>, writes the durable manifest, and prints the tier's
// fidelity banner. It returns only once the cluster is USABLE — the default
// namespace bootstrapped and a node registered Ready — so a caller that creates a
// pod immediately does not race the bring-up. It fails fast (never a silent
// degrade) on a --datapath posture miss, a live-datapath singleton violation, or a
// workdir/port collision.
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
	podRoot := m.podRoot(name)

	// Pre-flight reclaim: self-heal a crashed prior run under this name — reap a
	// stale pid, flush its lo0 aliases, and re-assert ports. Reads the OLD
	// manifest if present; a missing one is a clean first boot.
	if err := m.preflightReclaim(name); err != nil {
		return Instance{}, err
	}

	apiPort, kinePort, kubeletPort, err := allocatePorts(m.sys, name, m.euid)
	if err != nil {
		return Instance{}, err
	}

	// Provision the k3sm-execshim Seatbelt helper into the shared dev-bin cache and
	// prepend it to the detached server's PATH — without it runtimed's FindExecShim
	// fails and the server dies at `init sandbox backend`. If the helper cannot be
	// built (an installed k3sm with no workspace source) we fall back to
	// hostprocess (UNCONFINED, dev-only) with a loud notice rather than crashing —
	// runtimed stays the default whenever the helper IS provisionable.
	runtimeName := runtimeRuntimed
	binDir, provisioned, err := m.provisionExecShim(ctx)
	if err != nil {
		return Instance{}, err
	}
	if !provisioned {
		runtimeName = runtimeHostProcess
		binDir = ""
		fmt.Fprint(m.out, "NOTE: Seatbelt confinement unavailable (no buildable k3sm-execshim helper) — pods run UNCONFINED (dev-only). Run k3sm dev from the workspace, or install, for real isolation.\n")
	}

	// Provision the two pod-support DYLD shims and hand them to the server as
	// --path-shim / --dns-shim. cmd/k3sm resolves BOTH as siblings of the running
	// executable, and `k3sm dev` re-execs THIS binary out of a `go build` output
	// dir, so it found neither — one miss with two symptoms: every ABSOLUTE volume
	// mount path (ConfigMap/Secret/emptyDir/the projected SA token) ENOENTs in-pod
	// without the path-rebase shim, and every cluster Service name NXDOMAINs
	// without the getaddrinfo shim. Each is provisioned only in a posture that can
	// stage AND use it (wantsPathShim / wantsDNSShim); an unbuildable shim is a
	// loud degrade, not a failure.
	pathShim, dnsShim := "", ""
	if wantsPathShim(m.euid, runtimeName) {
		pathShim, err = m.provisionPodShim(ctx, pathShimName)
		if err != nil {
			return Instance{}, err
		}
		if pathShim == "" {
			fmt.Fprint(m.out, "NOTE: absolute volume-mount paths unavailable in-pod (no stageable path-rebase shim) — ConfigMap/Secret/emptyDir/service-account mounts will ENOENT. Run k3sm dev from the workspace for volume mounts.\n")
		}
	}
	if wantsDNSShim(m.euid, opts.Datapath, runtimeName) {
		dnsShim, err = m.provisionPodShim(ctx, dnsShimName)
		if err != nil {
			return Instance{}, err
		}
		if dnsShim == "" {
			fmt.Fprint(m.out, "NOTE: in-pod cluster DNS unavailable (no stageable getaddrinfo shim) — pods stay on the system resolver and cluster Service names NXDOMAIN. Run k3sm dev from the workspace for cluster DNS.\n")
		}
	}

	// Boot a detached `k3sm server` on the SHIPPED admission defaults (PSA
	// enforce=privileged, warn=baseline). dev used to pass --psa-enforce-baseline
	// "so the M10 PSA cutover criterion works", but that criterion's own skip-spec
	// demands a SEPARATE flagged boot (K3SM_PSA_ENFORCE=1) — while the flag here
	// made the default-posture criteria (TestM10_PSADefaultWarn/AuditLogLevel)
	// structurally unpassable under the SIT: they assert the shipped default and
	// the harness booted the cutover. K3SM_WORK_DIR is exported so the audit/PSA
	// e2e read the SAME workdir. runtimed (Seatbelt-confined) is the
	// default; hostprocess is only the honest execshim-unavailable fallback. The
	// rootless tier is network=none (runtimePreflight returns nil — no root);
	// --datapath is network=direct.
	proc, err := m.spawnServer(ctx, name, workDir, podRoot, apiPort, kinePort, kubeletPort, network, runtimeName, binDir, pathShim, dnsShim)
	if err != nil {
		return Instance{}, err
	}

	// Resolve where the dev context is merged (--kubeconfig / $KUBECONFIG /
	// ~/.kube/config) and record it so `down` removes from the same file.
	m.kubeMg.path = opts.Kubeconfig
	kubePath, err := m.kubeMg.dest()
	if err != nil {
		_ = m.sys.TerminateProcess(proc.pid, terminateGrace)
		return Instance{}, err
	}

	inst := Instance{
		Version:     registryVersion,
		Name:        name,
		WorkDir:     workDir,
		PodRoot:     podRoot,
		APIPort:     apiPort,
		KinePort:    kinePort,
		KubeletPort: kubeletPort,
		PID:         proc.pid,
		Tier:        tier,
		Runtime:     runtimeName,
		Datapath:    datapath,
		ServiceCIDR: ServiceCIDR,
		PodCIDR:     PodCIDR,
		EUID:        m.euid,
		KubeContext: kubeContextName(name),
		Kubeconfig:  kubePath,
		CreatedAt:   time.Now().UTC(),
	}

	// Wait for the server to write its kubeconfig, then merge it. On any failure
	// after the spawn we tear the detached server down so a half-up instance never
	// leaks.
	kc := executor.KubeconfigPath(workDir)
	if err := m.awaitOrExit(ctx, proc, m.awaitKubeconfig(ctx, kc, serverLogPath(workDir))); err != nil {
		_ = m.sys.TerminateProcess(proc.pid, terminateGrace)
		return Instance{}, err
	}
	if err := m.kubeMg.merge(kc, inst.KubeContext); err != nil {
		_ = m.sys.TerminateProcess(proc.pid, terminateGrace)
		return Instance{}, fmt.Errorf("merge kubeconfig: %w", err)
	}

	// A healthy apiserver is NOT a usable cluster. `Up` used to return here, while
	// the service-account controller and the root-ca-cert-publisher had not yet
	// reconciled the default namespace — so a caller that creates a pod immediately
	// (every acceptance/e2e suite does) raced them and failed spuriously, either at
	// admission ("serviceaccount \"default\" not found") or at volume materialisation
	// ("configMap default/kube-root-ca.crt: file does not exist",
	// FAILURE_REASON_ROOTFS_SETUP). Observed on lab hardware 2026-08-27: both objects
	// existed at AGE=1s, and the same criteria passed against a warm cluster — a
	// race, not a missing controller. Block until the namespace is actually usable,
	// the readiness gate kubeadm and kind both apply.
	wait := m.awaitNamespaceBootstrap
	if wait == nil {
		wait = m.awaitDefaultNamespaceBootstrap
	}
	if err := m.awaitOrExit(ctx, proc, wait(ctx, kc)); err != nil {
		_ = m.sys.TerminateProcess(proc.pid, terminateGrace)
		return Instance{}, err
	}

	// A bootstrapped namespace is still not a schedulable cluster: the node
	// registers on its own clock, well after the apiserver is serving. Measured on
	// lab hardware 2026-08-27: the server logged `starting k3sm node` at 12:34:36
	// and `node ... ready` at 12:36:06 — ~90s later — while `dev up` had already
	// returned at 12:34. Every caller that listed nodes right after `up` saw NONE,
	// and every pod it created sat Unschedulable ("no nodes available to schedule
	// pods"). Block until a Ready node exists, so `up` returning means the cluster
	// can actually run something.
	nodeWait := m.nodeRegistrationWait()
	if err := m.awaitOrExit(ctx, proc, nodeWait(ctx, kc)); err != nil {
		_ = m.sys.TerminateProcess(proc.pid, terminateGrace)
		return Instance{}, err
	}

	// Under sudo, hand the workdir back to the invoking human so the next rootless
	// run doesn't EACCES on a root-owned tree.
	if m.kubeMg.chownUID >= 0 {
		if err := chownTree(workDir, m.kubeMg.chownUID, m.kubeMg.chownGID); err != nil {
			fmt.Fprintf(m.out, "warning: could not chown workdir to %s: %v\n", m.kubeMg.chownUser, err)
		}
	}

	// The report is bound to the SERVER, not to the probes that ran against it.
	// This is the last thing checked before the manifest is written and `up` says
	// so: `instance "b" up` was once printed over a server that had already died,
	// because a bring-up whose every gate is a readiness signal reports the health
	// of signals rather than of a process. A dead server gets no manifest and no
	// success line.
	if err := m.awaitOrExit(ctx, proc, nil); err != nil {
		_ = m.sys.TerminateProcess(proc.pid, terminateGrace)
		return Instance{}, err
	}
	if err := m.reg.Save(inst); err != nil {
		_ = m.sys.TerminateProcess(proc.pid, terminateGrace)
		return Instance{}, err
	}
	if m.kubeMg.chownUID >= 0 {
		_ = chownTree(m.reg.dir(name), m.kubeMg.chownUID, m.kubeMg.chownGID)
	}

	fmt.Fprint(m.out, FidelityBanner(datapath, runtimeName))
	fmt.Fprintf(m.out, "\ninstance %q up — apiserver 127.0.0.1:%d · context %s · kubeconfig %s\n", name, apiPort, inst.KubeContext, kubePath)
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
	if opts.Kubeconfig != "" { // explicit override of the recorded merge target
		inst.Kubeconfig = opts.Kubeconfig
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
	m.kubeMg.path = inst.Kubeconfig // remove from the file this instance merged into
	if err := m.kubeMg.remove(inst.KubeContext); err != nil {
		fmt.Fprintf(m.out, "warning: remove kubeconfig context %q: %v\n", inst.KubeContext, err)
	}
	// The runtime root lives outside the registry root, so Remove below cannot
	// reclaim it: delete it here or every torn-down instance leaks its pod dirs,
	// blob cache and PVC storage. `down` is destructive by contract — the
	// pre-split layout put all three inside the instance dir Remove wipes.
	if dir := removablePodRoot(inst, m.podRootBaseDir()); dir != "" {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(m.out, "warning: remove pod-root %q: %v\n", dir, err)
		}
	}
	if err := m.reg.Remove(inst.Name); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("remove registry entry %q: %w", inst.Name, err)
	}
	fmt.Fprintf(m.out, "instance %q down\n", inst.Name)
	return nil
}

// removablePodRoot returns the instance's runtime root when it is safe to delete
// recursively, and "" otherwise. Safe means: recorded (an older manifest has
// none — that layout kept the root inside the instance dir Remove already
// reclaims), absolute and clean, and a PROPER descendant of base. The bound is
// what keeps a hand-edited or corrupted manifest from turning teardown into an
// arbitrary rm -rf running, in the datapath tier, as root.
func removablePodRoot(inst Instance, base string) string {
	dir := inst.PodRoot
	if dir == "" || base == "" {
		return ""
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return ""
	}
	base = filepath.Clean(base)
	if base == "/" || !strings.HasPrefix(dir, base+"/") {
		return ""
	}
	return dir
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

// serverArgs builds the detached `k3sm server` argv. It is pure (no I/O) so the
// argv wiring — notably --path-shim and --dns-shim, which carry the provisioned
// dylibs into the node's provider.RuntimedConfig.PathShim / .DyldShim — is
// unit-tested without spawning a process. An empty shim path emits NO flag at
// all: the server must fall back to its own sibling-dylib resolution rather than
// be pointed at a path that is not there.
func serverArgs(name, workDir, podRoot string, apiPort, kinePort, kubeletPort int, network, runtimeName, pathShim, dnsShim string) []string {
	args := []string{
		"server",
		"--work-dir", workDir,
		// Keep the runtime root (pod dirs, blob cache, PVC storage) out of the
		// registry root under /Users — see PodRootBasePrefix. Without this the
		// server derives it from the work-dir parent and no PVC-backed pod can
		// ever start.
		"--pod-root", podRoot,
		"--node-name", "k3sm-dev-" + name,
		"--node-ip", "127.0.0.1",
		"--runtime", runtimeName,
		"--network", network,
		"--api-port", strconv.Itoa(apiPort),
		// The allocated datastore port, NOT the server default: without it every
		// instance's kine would target the one fixed port, and the second instance up
		// would be refused by the executor (or, before that refusal existed, come up
		// healthy against the first instance's datastore).
		"--kine-port", strconv.Itoa(kinePort),
		// The allocated kubelet-API port, same reason one port further down the
		// bring-up: the node's logs/exec/stats listener is a per-NODE singleton, so
		// on the fixed default the second instance's node dies at "bind: address
		// already in use" after the control plane is already healthy.
		//
		// A PORT is all dev hands the server. The listener's bind address (the
		// wildcard) and its auth posture are the server's own, unchanged by this
		// flag and not dev's to move: `k3sm dev` must never be the reason that
		// surface is reachable from somewhere it was not already.
		"--kubelet-port", strconv.Itoa(kubeletPort),
		// Disable the ingress listeners: the dev cluster does not front an ingress,
		// and the production :80/:443 bind needs privileges the rootless tier lacks.
		"--ingress-http-port", "0",
		"--ingress-https-port", "0",
	}
	if pathShim != "" {
		args = append(args, "--path-shim", pathShim)
	}
	if dnsShim != "" {
		args = append(args, "--dns-shim", dnsShim)
	}
	return args
}

// spawnServer starts a detached `k3sm server` (this binary re-exec'd) in its own
// process group with the config-superset argv, redirecting its output to
// <workDir>/server.log, and returns its pid. It does NOT wait — the server runs
// until `down` SIGTERMs it. K3SM_WORK_DIR is exported so the M10 audit/PSA e2e
// read the same workdir.
func (m *Manager) spawnServer(ctx context.Context, name, workDir, podRoot string, apiPort, kinePort, kubeletPort int, network, runtimeName, execShimDir, pathShim, dnsShim string) (*serverProc, error) {
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("create workdir %s: %w", workDir, err)
	}
	// Pre-create the runtime root so a base the caller cannot write (a stale tree
	// owned by the other euid) fails HERE, with the path named, instead of inside
	// the detached server's first pod create.
	if err := os.MkdirAll(podRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create pod-root %s: %w", podRoot, err)
	}
	logPath := serverLogPath(workDir)
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create server log: %w", err)
	}
	defer lf.Close()

	cmd := exec.CommandContext(ctx, m.self, serverArgs(name, workDir, podRoot, apiPort, kinePort, kubeletPort, network, runtimeName, pathShim, dnsShim)...)
	cmd.Stdout, cmd.Stderr = lf, lf
	// Own process group so `down` can SIGTERM the whole supervised tree via -pid,
	// and detached from ctx cancellation (WaitDelay 0 + no Cancel) so the server
	// outlives the `k3sm dev up` CLI invocation.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return nil } // ctx cancel must NOT kill the detached server
	// Prepend the dev-bin cache (holding k3sm-execshim) to PATH so runtimed's
	// FindExecShim → exec.LookPath("k3sm-execshim") resolves the provisioned helper
	// in the detached server. execShimDir is empty on the hostprocess fallback (no
	// helper), which leaves PATH untouched.
	cmd.Env = append(withExecShimPath(os.Environ(), execShimDir), "K3SM_WORK_DIR="+workDir)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start k3sm server: %w", err)
	}
	p := &serverProc{name: name, pid: cmd.Process.Pid, logPath: logPath, exited: make(chan struct{})}
	// Release the child: a reaper goroutine Waits so the process is not left a
	// zombie if this CLI lingers, but the server keeps running independently. The
	// Wait result is no longer discarded — it is the account of WHY a bring-up
	// that looked healthy was not, so it is recorded before the close that
	// publishes it.
	go func() {
		p.waitErr = cmd.Wait()
		close(p.exited)
	}()
	return p, nil
}

// serverProc is the handle spawnServer returns for the detached control plane:
// its pid, where its output went, and the exit signal the reaper goroutine
// closes. waitErr is written strictly BEFORE exited closes and read only after
// <-exited, so the close is the happens-before edge (the same discipline the
// executor's supervised components use for the same reason).
type serverProc struct {
	name    string
	pid     int
	logPath string
	exited  chan struct{}
	waitErr error
}

// exitError describes the server's exit: the Wait result (its exit status) plus
// the tail of the log it died writing, so the operator sees the fatal line rather
// than an assertion that something is wrong. Call only after <-p.exited.
func (p *serverProc) exitError() error {
	return fmt.Errorf("%w: instance %q server (pid %d): %v; last log lines (%s):\n%s",
		ErrServerExited, p.name, p.pid, p.waitErr, p.logPath,
		executor.LogTail(p.logPath, bootLogTailLines))
}

// exitReportGrace bounds how long awaitOrExit waits for the reaper to publish an
// exit it has already established from the kernel. The close is imminent by
// construction (the child is gone; the reaper only needs a scheduling slot), so
// this is a hang guard, not a budget — on expiry the stage's own verdict is
// returned rather than nothing at all.
const exitReportGrace = 5 * time.Second

// awaitOrExit decides which verdict a bring-up stage reports, and the server's
// EXIT always wins.
//
// A stage's success is not the instance's success. `up` printed `instance "b" up`
// for a server whose datastore had already FATAL'd, because every wait it runs is
// bound to a readiness signal — a kubeconfig file on disk, an API object, a Ready
// node — and a signal that has already been emitted stays true after the process
// emitting it dies. So an exit the reaper has published beats err even when err
// is nil.
//
// When the stage FAILED, the kernel is asked directly before a deadline is
// allowed to author the error: exited is closed by a goroutine that may not have
// been scheduled yet, so a dead server can otherwise come back as an opaque
// timeout describing the symptom instead of the cause.
func (m *Manager) awaitOrExit(ctx context.Context, p *serverProc, err error) error {
	select {
	case <-p.exited:
		return p.exitError()
	default:
	}
	if err == nil {
		return nil
	}
	if !m.sys.ProcessAlive(p.pid) {
		select {
		case <-p.exited:
			return p.exitError()
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(exitReportGrace):
			// The reaper never reported. Prefer the stage's own verdict to hanging.
		}
	}
	return err
}

// serverLogPath is where spawnServer redirects a detached server's output. One
// helper so the writer and every error that quotes the file name the same path.
func serverLogPath(workDir string) string { return filepath.Join(workDir, "server.log") }

// kubeconfigWait bounds awaitKubeconfig. It is NOT raised to cover a slow boot: a
// deadline that moves to fit the worst observed run stops bounding anything, and the
// causes worth surviving are causes worth SEEING, which is what the log tail below is
// for.
const kubeconfigWait = 90 * time.Second

// bootLogTailLines is how many trailing server-log lines a bring-up timeout carries —
// enough to show what the boot was doing without dumping a whole log into an error.
const bootLogTailLines = 20

// awaitKubeconfig blocks until the detached server has written its admin
// kubeconfig (its readiness signal for the merge), bounded so a wedged bring-up
// fails with an actionable error instead of hanging.
func (m *Manager) awaitKubeconfig(ctx context.Context, kc, logPath string) error {
	return awaitKubeconfigFile(ctx, kubeconfigWait, kc, logPath)
}

// awaitKubeconfigFile is the pollable core of awaitKubeconfig, split out so the
// timeout's semantics are testable without spawning a server.
//
// The timeout QUOTES the server log rather than pointing at it. The server is
// detached, so its output is the only account of what the boot was doing, and an
// operator who has to already know the file exists learns nothing from the failure:
// the observed case was a boot whose log held nothing but `go: downloading` lines —
// the datastore binary was being built, progress was real, and the error said only
// that a file had not appeared.
func awaitKubeconfigFile(ctx context.Context, timeout time.Duration, kc, logPath string) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(kc); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("k3sm server did not write %s within %s; last log lines (%s):\n%s",
				kc, timeout, logPath, executor.LogTail(logPath, bootLogTailLines))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// defaultNamespaceBootstrapTimeout bounds awaitDefaultNamespaceBootstrap. The two
// objects are written by controllers that start with the control plane, so they
// normally land within a second or two; the budget is generous because the cost of
// waiting is a slower `dev up`, while the cost of NOT waiting is a spurious red in
// every suite that creates a pod immediately.
const defaultNamespaceBootstrapTimeout = 90 * time.Second

// awaitDefaultNamespaceBootstrap blocks until the default namespace carries BOTH
// objects a pod with a projected service-account token needs:
//
//   - the `default` ServiceAccount (written by the service-account controller) —
//     without it a pod naming it is REJECTED at admission; and
//   - the `kube-root-ca.crt` ConfigMap (written by the root-ca-cert-publisher) —
//     without it the kube-api-access projected volume cannot materialise.
//
// Both are polled with a typed client built from the instance's own kubeconfig.
// Each is latched once seen, so a transient error on one never re-tests the other.
func (m *Manager) awaitDefaultNamespaceBootstrap(ctx context.Context, kubeconfig string) error {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("build client config from %s: %w", kubeconfig, err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("build clientset for %s: %w", kubeconfig, err)
	}
	return awaitBootstrapObjects(ctx, defaultNamespaceBootstrapTimeout, kubeconfig,
		func(ctx context.Context) bool {
			_, gerr := cs.CoreV1().ServiceAccounts(metav1.NamespaceDefault).
				Get(ctx, "default", metav1.GetOptions{})
			return gerr == nil
		},
		func(ctx context.Context) bool {
			_, gerr := cs.CoreV1().ConfigMaps(metav1.NamespaceDefault).
				Get(ctx, "kube-root-ca.crt", metav1.GetOptions{})
			return gerr == nil
		})
}

// awaitBootstrapObjects is the pollable core of awaitDefaultNamespaceBootstrap,
// split out so its semantics are testable without an apiserver: each probe is
// LATCHED once it first succeeds, so a transient failure on one object never
// re-opens the other, and the timeout error names which object is still missing.
func awaitBootstrapObjects(ctx context.Context, timeout time.Duration, kubeconfig string,
	saPresent, cmPresent func(context.Context) bool) error {
	deadline := time.Now().Add(timeout)
	var saOK, cmOK bool
	for {
		if !saOK {
			saOK = saPresent(ctx)
		}
		if !cmOK {
			cmOK = cmPresent(ctx)
		}
		if saOK && cmOK {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("default namespace not bootstrapped within %s "+
				"(serviceaccount/default present=%t, configmap/kube-root-ca.crt present=%t) — "+
				"see the server.log beside %s", timeout, saOK, cmOK, kubeconfig)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// nodeRegistrationTimeout bounds the wait for a Ready node.
//
// Picked against the measured numbers and deliberately clear of them:
// registration was observed taking ~90s on lab hardware (2026-08-27), so a 90s
// bound — the sibling defaultNamespaceBootstrapTimeout's budget — would sit
// EXACTLY at the observed latency and flake. 5m matches cmd/k3sm's sibling
// nodeStartupTimeout (the node's own view of the same event) and leaves a wide
// margin over the observation, while still turning a bring-up that never
// registers into a bounded, reported failure. It does NOT claim 90s is the
// worst case: why registration takes that long is unresolved, and a start that
// exceeds this budget is reported, not diagnosed.
const nodeRegistrationTimeout = 5 * time.Minute

// nodeRegistrationWait resolves the node-registration wait Up applies: the
// injected seam when a test set one, else the production implementation. Up
// itself is not unit-reachable (it fork/execs a real server), so the resolution
// lives in its own method to keep that wiring testable.
func (m *Manager) nodeRegistrationWait() func(ctx context.Context, kubeconfig string) error {
	if m.awaitNodeRegistration != nil {
		return m.awaitNodeRegistration
	}
	return m.awaitNodeRegistered
}

// awaitNodeRegistered blocks until at least one node has registered with the
// instance's apiserver and reports Ready, polled with a typed client built from
// the instance's own kubeconfig.
func (m *Manager) awaitNodeRegistered(ctx context.Context, kubeconfig string) error {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("build client config from %s: %w", kubeconfig, err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("build clientset for %s: %w", kubeconfig, err)
	}
	return awaitReadyNode(ctx, nodeRegistrationTimeout, kubeconfig,
		func(ctx context.Context) (registered, ready int, err error) {
			list, lerr := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
			if lerr != nil {
				return 0, 0, lerr
			}
			for i := range list.Items {
				if nodeIsReady(&list.Items[i]) {
					ready++
				}
			}
			return len(list.Items), ready, nil
		})
}

// nodeIsReady reports whether n carries a Ready condition with status True. A
// node object that EXISTS is not yet a schedulable node — the scheduler skips it
// until the condition flips — so registration alone is not the readiness signal.
func nodeIsReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// awaitReadyNode is the pollable core of awaitNodeRegistered, split out so its
// semantics are testable without an apiserver. probe reports how many nodes are
// registered and how many of those are Ready; a probe error is transient (the
// apiserver may still be settling) so polling continues, but the last one is
// carried into the timeout message. Unlike awaitBootstrapObjects nothing is
// latched: the contract is that a Ready node exists NOW.
func awaitReadyNode(ctx context.Context, timeout time.Duration, kubeconfig string,
	probe func(context.Context) (registered, ready int, err error)) error {
	deadline := time.Now().Add(timeout)
	var registered, ready int
	var lastErr error
	for {
		r, rd, perr := probe(ctx)
		if perr != nil {
			lastErr = perr
		} else {
			lastErr = nil
			registered, ready = r, rd
			if ready > 0 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			detail := ""
			if lastErr != nil {
				detail = fmt.Sprintf(", last probe error: %v", lastErr)
			}
			return fmt.Errorf("no node registered Ready within %s "+
				"(nodes registered=%d, ready=%d%s) — "+
				"see the server.log beside %s", timeout, registered, ready, detail, kubeconfig)
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

// podRoot is the per-instance runtimed root passed to the detached server as
// --pod-root: <base>/<name>, where the base carries the euid (see
// PodRootBasePrefix). It is NOT under the registry root — a runtime root inside
// /Users makes every PVC-backed pod unschedulable-to-run under Seatbelt.
func (m *Manager) podRoot(name string) string {
	return filepath.Join(m.podRootBaseDir(), name)
}

// podRootBaseDir returns the configured pod-root base, defaulting to the
// euid-scoped PodRootBasePrefix.
func (m *Manager) podRootBaseDir() string {
	if m.podRootBase != "" {
		return m.podRootBase
	}
	return PodRootBasePrefix + "-" + strconv.Itoa(m.euid)
}

// datapathLockPath is the flock file guarding the --datapath singleton (under the
// registry root, shared across instances of the current user).
func (m *Manager) datapathLockPath() string {
	return filepath.Join(m.reg.root, "datapath.lock")
}

// kubeContextName is the ~/.kube/config context an instance merges as.
func kubeContextName(name string) string { return "k3sm-dev-" + name }
