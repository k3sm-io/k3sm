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
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/version"
)

// Probe budgets. Every one of them is short on purpose: `k3sm status` is the
// command an operator runs when something is already wrong, and a probe that
// hangs turns "the cluster is down" into "the tool is down too".
const (
	statusAPITimeout      = 3 * time.Second
	statusRuntimedTimeout = 2 * time.Second
	// logTailBudget is how far back from the end of a log file ReadTail reads.
	// A daemon log can be tens of megabytes; the last lines are what a status
	// report quotes, and reading the whole file to find them would be the most
	// expensive thing this command does.
	logTailBudget = 64 << 10
)

// newStatusRunner wires the production statusRunner: the real launchctl, the
// real filesystem, the resolved apiserver client, and the real clock.
func newStatusRunner(o statusOptions) statusRunner {
	color := status.ColorEnabled(os.Stdout, o.noColor, os.Getenv)
	return statusRunner{
		out:       os.Stdout,
		errOut:    os.Stderr,
		collect:   func(ctx context.Context) status.Report { return newStatusCollector().Collect(ctx) },
		stdoutTTY: status.IsTerminal(os.Stdout),
		stderrTTY: status.IsTerminal(os.Stderr),
		color:     color,
		sleep:     sleepUntil,
		readLog:   readTail,
		logPaths:  map[string]string{"netd": install.NetdLogPath(), "server": install.ServerLogPath()},
	}
}

// sleepUntil waits for d, reporting false when the context ended first — which
// is how both the --wait timeout and a Ctrl-C during --watch arrive.
func sleepUntil(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return ctx.Err() == nil
	}
}

// newStatusCollector assembles the collector from this process's actual
// environment. It is the ONLY place `k3sm status` touches the machine.
func newStatusCollector() status.Collector {
	euid := os.Geteuid()
	serviceUID := lookupServiceUID()
	workDir := statusWorkDir(euid, serviceUID)
	kube, source, kubeErr := newStatusKube(workDir)

	return status.Collector{
		Launchd:    launchctlProbe{},
		FS:         osStatusFS{},
		Kube:       kube,
		KubeErr:    kubeErr,
		KubeSource: source,
		Procs:      procTable{},
		Runtimed:   runtimedFor(euid, serviceUID, runtimed.DefaultSocketPath),
		DataRoot:   dataRootFS{},
		Paths:      statusPaths(workDir),
		EUID:       euid,
		ServiceUID: serviceUID,
		Version:    version.Get(),
		Host:       macOSVersionOrEmpty(),
		Hostname:   hostnameOrEmpty(),
	}
}

// statusWorkDir is the control-plane work dir this report is ABOUT.
//
// It is deliberately not workDirFromEnv(): that answers "where would MY server
// keep its state", which for an ordinary account is <home>/server — a directory
// the installed cluster has never written to. Reporting on it would say "no
// state.db yet" about a cluster with a perfectly good datastore. Root and the
// service user are the two identities whose own work dir IS the installed one,
// so only they resolve it; everyone else gets the installed default and, most
// often, an honest "not readable as this user" row.
func statusWorkDir(euid, serviceUID int) string {
	if d := os.Getenv("K3SM_WORK_DIR"); d != "" {
		return d
	}
	if runsAsControlPlane(euid, serviceUID) {
		if wd, err := executor.ResolveWorkDir(); err == nil {
			return wd
		}
	}
	return executor.DefaultWorkDir
}

// runsAsControlPlane reports whether this process is one of the two identities
// the control plane runs as. It shares its terms with status.RuntimedReachable
// but answers a different question — "is the installed work dir mine" rather
// than "may I open the runtime socket" — and the two are kept separate so a
// change to either does not silently move the other.
func runsAsControlPlane(euid, serviceUID int) bool {
	return euid == 0 || (serviceUID >= 0 && euid == serviceUID)
}

// hostnameOrEmpty is this Mac's short host name, used to pick THIS node out of a
// multi-node cluster. An unresolvable hostname yields the empty string, which
// simply leaves the node row to its fallback.
func hostnameOrEmpty() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// statusPaths names the installed locations for the report.
func statusPaths(workDir string) status.Paths {
	return status.Paths{
		Binary:          installedBinaryPath(),
		Link:            installedLinkPath(),
		LaunchDaemonDir: install.DefaultLaunchDaemonDir,
		NetdLabel:       install.NetdLabel,
		ServerLabel:     install.ServerLabel,
		DataRoot:        install.DefaultDataRoot,
		WorkDir:         workDir,
		NetdSocket:      install.DefaultNetdSocket,
		NetdLog:         install.NetdLogPath(),
		ServerLog:       install.ServerLogPath(),
	}
}

// installedBinaryPath and installedLinkPath are where `k3sm install` puts the
// binary and its launcher symlink. The installer derives the same two paths from
// its Config, whose accessors are unexported; the basename is shared here so the
// link and its target cannot be given different names.
func installedBinaryPath() string {
	return filepath.Join(install.DefaultInstallDir, installedBinaryName)
}

func installedLinkPath() string {
	return filepath.Join(install.DefaultLinkDir, installedBinaryName)
}

// installedBinaryName is the basename of the installed binary and its launcher.
const installedBinaryName = "k3sm"

// lookupServiceUID resolves the _k3sm service user's uid, or
// status.RuntimeReachableUnknownUID when the account does not exist. An
// unresolved uid fails closed everywhere it is used.
func lookupServiceUID() int {
	u, err := user.Lookup(install.DefaultServiceUser)
	if err != nil {
		return status.RuntimeReachableUnknownUID
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return status.RuntimeReachableUnknownUID
	}
	return uid
}

// macOSVersionOrEmpty reads this Mac's product version, reusing the doctor
// probe. A failure yields the empty string, which the report simply omits.
func macOSVersionOrEmpty() string {
	v, err := probeMacOSVersion()
	if err != nil {
		return ""
	}
	return v
}

// launchctlProbe is the real launchctl seam.
//
// CombinedOutput is deliberate: launchctl writes its "could not find service"
// diagnostic to stderr, and the parser needs the exit error — not the text — to
// decide a job is not loaded. The output itself is discarded on error, and is
// never carried into a row even on success, because it echoes the job's argv.
type launchctlProbe struct{}

// Print runs `launchctl print system/<label>`.
func (launchctlProbe) Print(label string) ([]byte, error) {
	return exec.Command("launchctl", "print", "system/"+label).CombinedOutput()
}

// PrintDisabled runs `launchctl print-disabled system`.
func (launchctlProbe) PrintDisabled() ([]byte, error) {
	return exec.Command("launchctl", "print-disabled", "system").CombinedOutput()
}

// osStatusFS is the real filesystem seam.
type osStatusFS struct{}

// Stat reports a path's presence and mode.
func (osStatusFS) Stat(path string) (fs.FileInfo, error) { return os.Stat(path) }

// Readlink reads a symlink's target.
func (osStatusFS) Readlink(path string) (string, error) { return os.Readlink(path) }

// ReadTail reads the last lines of a file.
func (osStatusFS) ReadTail(path string, lines int) ([]string, error) { return readTail(path, lines) }

// readTail returns the last n lines of path without reading the whole file: it
// seeks to the last logTailBudget bytes and drops the first (necessarily
// partial) line when it did seek.
func readTail(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	offset := int64(0)
	if info.Size() > logTailBudget {
		offset = info.Size() - logTailBudget
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if offset > 0 && len(all) > 0 {
		all = all[1:] // the first line was cut mid-way by the seek
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}

// restKube is the apiserver seam over a client-go REST client.
type restKube struct {
	client *kubernetes.Clientset
	server string
	tls    string
}

// RawGet performs an unstructured GET against an absolute apiserver path.
func (k restKube) RawGet(ctx context.Context, path string) ([]byte, error) {
	return k.client.Discovery().RESTClient().Get().AbsPath(path).DoRaw(ctx)
}

// Nodes lists every node.
func (k restKube) Nodes(ctx context.Context) ([]corev1.Node, error) {
	list, err := k.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// Pods lists every pod in every namespace.
func (k restKube) Pods(ctx context.Context) ([]corev1.Pod, error) {
	list, err := k.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// Server is the apiserver URL the client is configured for.
func (k restKube) Server() string { return k.server }

// TLSPosture says how the connection trusts the apiserver.
func (k restKube) TLSPosture() string { return k.tls }

// newStatusKube resolves credentials exactly as `k3sm kubectl` does — the work
// dir's admin kubeconfig for root and the service user, the invoking user's own
// ~/.kube/config with the k3sm context otherwise — and builds a client with a
// short timeout. A nil Kube with a non-nil error is a reportable posture, not a
// failure: the report says which credentials were missing.
func newStatusKube(workDir string) (status.Kube, string, error) {
	home, _ := os.UserHomeDir()
	cfg, err := resolveKubectlConfig(kubectlInputs{
		workDirOverride: os.Getenv("K3SM_WORK_DIR"),
		workDir:         workDir,
		kubeconfigEnv:   os.Getenv("KUBECONFIG"),
		home:            home,
		contextName:     installedContextName,
		exists:          fileExists,
	})
	if err != nil {
		return nil, "", err
	}

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cfg.kubeconfig != "" {
		rules.ExplicitPath = cfg.kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if cfg.context != "" {
		overrides.CurrentContext = cfg.context
	}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	restCfg, err := loader.ClientConfig()
	if err != nil {
		return nil, "", err
	}
	restCfg.Timeout = statusAPITimeout

	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, "", err
	}
	return restKube{client: cs, server: restCfg.Host, tls: tlsPosture(restCfg)}, kubeSource(cfg, rules), nil
}

// tlsPosture describes how a rest config trusts the apiserver, in the two words
// that actually differ between an installed cluster and a hand-made kubeconfig.
func tlsPosture(cfg *rest.Config) string {
	if cfg.TLSClientConfig.Insecure {
		return "insecure-skip-tls-verify"
	}
	return "ca pinned"
}

// kubeSource names the file and context the report says it used.
func kubeSource(cfg kubectlConfig, rules *clientcmd.ClientConfigLoadingRules) string {
	if cfg.kubeconfig != "" {
		return cfg.kubeconfig
	}
	path := "kubectl's own rules"
	if precedence := rules.Precedence; len(precedence) > 0 {
		path = precedence[0]
	}
	if cfg.context != "" {
		return fmt.Sprintf("%s context %q", path, cfg.context)
	}
	return path
}

// grpcRuntimed is the runtimed health seam over the daemon's unix control
// socket, reusing the same dialer `k3sm image` uses.
type grpcRuntimed struct{ socket string }

// Info asks the daemon for its runtime info under a short deadline.
func (g grpcRuntimed) Info(ctx context.Context) (*runtimev1.GetRuntimeInfoResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, statusRuntimedTimeout)
	defer cancel()
	cc, closer, err := dialRuntimed(ctx, g.socket)
	if err != nil {
		return nil, err
	}
	defer func() { _ = closer.Close() }()
	return runtimev1.NewRuntimeClient(cc).GetRuntimeInfo(ctx, &runtimev1.GetRuntimeInfoRequest{})
}

// runtimedFor returns the runtimed seam, or nil when this uid may not open the
// control socket. Returning nil is the point: the socket is mode 0600 in a 0700
// directory, so an ordinary account's dial can only ever produce a permission
// error, and printing that as a runtime fault would be a lie about the daemon.
func runtimedFor(euid, serviceUID int, socket string) status.Runtimed {
	if !status.RuntimedReachable(euid, serviceUID) {
		return nil
	}
	return grpcRuntimed{socket: socket}
}

// dataRootFS is the real dataroot.FS: the /etc/fstab read, the stat, and the
// statfs that together decide whether the data root is a mounted volume, a plain
// directory, or a shadow over an unmounted mount point.
type dataRootFS struct{}

// Stat reports the data root's mode and owner.
func (dataRootFS) Stat(path string) (fs.FileInfo, error) { return os.Stat(path) }

// Statfs reports the filesystem containing a path, with the mount point
// normalised back to the name the caller asked about.
//
// macOS symlinks /var onto /private/var, so statfs(2) asked about
// /var/lib/k3sm answers with a mount point of /private/var/lib/k3sm — a
// different string for the same directory. dataroot.Read compares that string
// to the directory it was given, so without this normalisation an installed,
// mounted data root reads as "declared in /etc/fstab and NOT mounted", which is
// the SHADOW verdict: a hard failure reported about a healthy Mac.
func (dataRootFS) Statfs(path string, st *unix.Statfs_t) error {
	if err := unix.Statfs(path, st); err != nil {
		return err
	}
	normalizeMountPoint(path, st, filepath.EvalSymlinks)
	return nil
}

// normalizeMountPoint rewrites st's mount point to path when the two name the
// same directory through a symlink.
//
// It rewrites ONLY on a proven equality — path resolves to exactly the mount
// point statfs reported — so the real shadow stays detectable: there, nothing is
// mounted at either name, statfs answers about some ancestor filesystem, and the
// resolution does not match.
func normalizeMountPoint(path string, st *unix.Statfs_t, resolve func(string) (string, error)) {
	on := cstring(st.Mntonname[:])
	if on == path || on == "" {
		return
	}
	resolved, err := resolve(path)
	if err != nil || resolved != on {
		return
	}
	if len(path) >= len(st.Mntonname) {
		return
	}
	st.Mntonname = [len(st.Mntonname)]byte{}
	copy(st.Mntonname[:], path)
}

// cstring decodes a NUL-terminated fixed-width kernel string field.
func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// ReadFile reads /etc/fstab.
func (dataRootFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// ReadDir lists a shadow directory's contents.
func (dataRootFS) ReadDir(path string) ([]fs.DirEntry, error) { return os.ReadDir(path) }
