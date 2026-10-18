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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/tcpseg"
	runtimed "k3sm.io/runtimed/pkg/runtime"

	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/netdsvc"
	"k3sm.io/k3sm/pkg/shadow"
	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/svcstatus"
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
	// logUnreadableLine is what the status report quotes instead of a log tail
	// this account may not read. The daemon logs are install.LogFileMode, group
	// admin, so an ordinary account gets EACCES on every one of them.
	logUnreadableLine = "not readable by this account; run with sudo or as a member of admin"
)

// newStatusRunner wires the production statusRunner: the real launchctl, the
// real filesystem, the resolved apiserver client, and the real clock.
func newStatusRunner(o statusOptions) statusRunner {
	color := status.ColorEnabled(os.Stdout, o.noColor, os.Getenv)
	role, _ := installedRole()
	return statusRunner{
		out:       os.Stdout,
		errOut:    os.Stderr,
		collect:   func(ctx context.Context) status.Report { return o.scopeDatavol(newStatusCollector()).Collect(ctx) },
		probe:     func() status.DaemonsReport { return o.scopeDatavol(newDaemonsCollector()).CollectDaemons() },
		stdoutTTY: status.IsTerminal(os.Stdout),
		stderrTTY: status.IsTerminal(os.Stderr),
		color:     color,
		sleep:     sleepUntil,
		readLog:   readTail,
		logPaths: map[string]string{
			"netd":   install.NetdLogPath(),
			"server": install.ServerLogPath(),
			"agent":  install.AgentLogPath(),
		},
		logTargets: defaultLogTargets(role),
		top:        lazyTop(newTopCollector),
		appPresent: func() bool { return fileExists(appBundlePath) },
		stream:     newStatusStream(o),
	}
}

// lazyTop builds the top collector on the first frame and keeps it for every
// later one, so the other views never resolve its client and a --watch loop
// keeps one metrics sample between frames.
func lazyTop(build func(context.Context) *status.TopCollector) func(context.Context, status.TopOptions) status.TopReport {
	var c *status.TopCollector
	return func(ctx context.Context, o status.TopOptions) status.TopReport {
		if c == nil {
			c = build(ctx)
		}
		return c.Collect(ctx, o)
	}
}

// newTopCollector resolves the top view's apiserver client (chooseTopKube):
// under sudo, the invoking user's own kubeconfig when it can list nodes;
// otherwise the client the full report would use, which is the role's
// credentials, and on a worker whose node credential this account cannot read,
// the account's own kubeconfig context for the server it joined.
func newTopCollector(ctx context.Context) *status.TopCollector {
	kube, err := chooseTopKube(ctx, topSudoInputsFromEnv(), reportTopKube)
	return &status.TopCollector{Kube: kube, KubeErr: err, Now: time.Now}
}

// reportTopKube is the client the full report would use, for the top view.
func reportTopKube() (status.Kube, error) {
	euid := os.Geteuid()
	role, _ := installedRole()
	paths := statusPaths(statusWorkDir(euid, lookupServiceUID()))
	kube, _, err := newStatusKube(statusKubeInputsFor(role, paths))
	if kube == nil {
		if user := statusUserKubeFor(role, statusAgentJoinServer, installedStatusDir()); user != nil {
			if k, _, uerr := user(); uerr == nil {
				kube, err = k, nil
			}
		}
	}
	return kube, err
}

// appBundlePath is where k3sm.app is installed.
const appBundlePath = "/Applications/k3sm.app"

// installedRole reports which node THIS Mac is installed as, read from the two
// node-daemon plists on disk, plus whether it is installed at all.
//
// It is the cmd-side reader of the same decision `k3sm status` makes from its
// own FS seam (install.RoleFromPlists): the verbs that cannot build a Collector
// — `status logs`, which reads a file, and `doctor`, which predicts — need the
// role too, and a second rule for it would eventually disagree with the report.
func installedRole() (install.Role, bool) {
	server := fileExists(installedPlistPath(install.ServerLabel))
	agent := fileExists(installedPlistPath(install.AgentLabel))
	return install.RoleFromPlists(server, agent)
}

// installedPlistPath is the LaunchDaemon plist a label is installed as.
func installedPlistPath(label string) string {
	return filepath.Join(install.DefaultLaunchDaemonDir, label+".plist")
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
	// The installed ROLE is read before the credentials, because it decides
	// which credentials there are to read: a worker holds a node credential
	// pointing at another Mac, and no admin kubeconfig and no loopback
	// apiserver of its own. Resolving on the euid alone is what made a worker
	// probe a control plane it does not run.
	role, _ := installedRole()
	paths := statusPaths(workDir)
	statusDir := installedStatusDir()
	kube, source, kubeErr := newStatusKube(statusKubeInputsFor(role, paths))

	return status.Collector{
		Launchd:    launchctlProbe{},
		FS:         osStatusFS{},
		Kube:       kube,
		KubeErr:    kubeErr,
		KubeSource: source,
		Procs:      procTable{},
		Runtimed:   runtimedFor(euid, serviceUID, runtimed.DefaultSocketPath),
		DataRoot:   dataRootFS{},
		// The diskutil read surface, for the one figure statfs cannot answer:
		// how much a quota-less data volume is using. `diskutil apfs list` needs
		// no privilege, so this is wired for every caller, not just root.
		Volumes: datavol.NewDarwin().Volumes,
		// The installer's own reader of the server plist's argv, so the row
		// reports exactly what a reinstall would carry over.
		ServerArgs: install.OperatorServerArgs,
		// netd's node resolver entry, read from the dynamic store (no
		// privilege needed to read a State: key).
		NodeResolverPresent: nodeResolverPresent,
		// One query to the node resolver at the DNS VIP, over UDP (and TCP
		// when UDP is silent), and the node daemon's arguments for the VIP it
		// serves on. The VIP is a lo0 alias, so this needs no privilege.
		DNS: status.NetDNS{},
		NodeArgs: func(role install.Role) ([]string, error) {
			return install.InstalledNodeArgs(install.NewDarwinSystem(), role)
		},
		// The live host binaries' cdhashes, for the shadow binary drift check.
		CDHash: func(path string) (string, error) {
			return shadow.CDHash(context.Background(), path)
		},
		// The cluster's Interconnect, read over the same client as every other
		// apiserver row.
		Interconnect:   statusInterconnect(kube),
		StopMarker:     statusStopMarker,
		Network:        statusNetwork,
		NetworkApplied: statusNetworkApplied,
		// The join target of a worker, through the installer's one reader of
		// the agent plist's --server (the agent arguments record does not carry
		// it, and the plist is world-readable, so this works without sudo).
		AgentJoinServer: statusAgentJoinServer,
		// The Service proxy's record against one uncached Services and
		// EndpointSlices LIST, over the same client as every apiserver row.
		Services: statusServices(kube),
		// The certificate the apiserver presents, for the serving-cert row of
		// an account that cannot read the certificate file.
		ServingChain: statusServingChain(kube),
		// On an agent, the invoking account's own kubeconfig, for when the
		// node credential is not readable from this account.
		UserKube: statusUserKubeFor(role, statusAgentJoinServer, statusDir),
		// One SelfSubjectReview with whichever client the report ends up
		// reading the cluster with, so the kubeconfig row can tell a refused
		// credential from one that was merely found.
		ReviewSelf: statusReviewSelf,
		// What proves, on a server, that the apiserver the report dials is
		// this Mac's own: loopback or one of its addresses, at the apiserver
		// port. A server installed with a non-default --api-port fails it, and
		// those rows then stay unknown as an ordinary account.
		ServerAnchor: status.NodeAnchor(statusEndpoints(statusDir), status.ServerAnchor(executor.DefaultAPIServerPort, localAddrs())),
		Paths:        paths,
		EUID:         euid,
		ServiceUID:   serviceUID,
		Version:      version.Get(),
		Host:         macOSVersionOrEmpty(),
		Hostname:     hostnameOrEmpty(),
	}
}

// statusAgentJoinServer returns the --server value of the installed agent
// plist, and nothing else from its argv.
func statusAgentJoinServer() (string, error) {
	return install.AgentJoinServer(install.NewDarwinSystem(), install.Config{})
}

// statusStopMarker reads the stop marker through the installer's own reader.
func statusStopMarker() (install.StopMarker, bool, error) {
	return install.ReadStopMarker(install.NewDarwinSystem(), install.DefaultStopMarkerPath)
}

// statusNetwork reads the LAN access record through the installer's own
// reader; the record is world-readable, so this works for any user.
func statusNetwork() (install.NetworkRecord, bool, error) {
	return install.ReadNetworkRecord(install.ReadNetworkRecordFile, install.DefaultNetworkRecordPath)
}

// statusNetworkApplied reads the node daemon's applied report; it is in the
// daemon's own work dir, so only root (and the service user) can read it.
func statusNetworkApplied(role install.Role) ([]byte, error) {
	return os.ReadFile(install.NetworkAppliedPath(install.DefaultDataRoot, role))
}

// statusInterconnect is the report's Interconnect reader over kube: one GET of
// the cluster's Interconnect, nil-with-no-error when there is none. Without a
// client there is nothing to read, and the row is left out.
func statusInterconnect(kube status.Kube) func(context.Context) (*netv1alpha1.Interconnect, error) {
	if kube == nil {
		return nil
	}
	return func(ctx context.Context) (*netv1alpha1.Interconnect, error) {
		return status.ReadInterconnect(ctx, kube)
	}
}

// statusServices is the services row's comparer over kube's clientset, or nil
// (no row) when there is no client.
func statusServices(kube status.Kube) status.ServicesComparer {
	rk, ok := kube.(restKube)
	if !ok || rk.client == nil {
		return nil
	}
	return svcstatus.Comparer{Client: rk.client, Timeout: statusAPITimeout}
}

// statusReviewSelf asks the apiserver behind kube who its credential
// authenticates as, with one SelfSubjectReview create, which the default
// system:basic-user role grants every authenticated identity. A client that is
// not the production one cannot be asked, and says so.
func statusReviewSelf(ctx context.Context, kube status.Kube) (string, error) {
	rk, ok := kube.(restKube)
	if !ok || rk.client == nil {
		return "", errors.New("no clientset to review the credential with")
	}
	ctx, cancel := context.WithTimeout(ctx, statusAPITimeout)
	defer cancel()
	review, err := rk.client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	return review.Status.UserInfo.Username, nil
}

// statusServingChain reads the certificate chain the apiserver behind kube
// presents in a TLS handshake, with the CA kube's kubeconfig pins, or is nil
// (the row stays unknown) when there is no client.
//
// The handshake skips verification ONLY to read the presented chain: nothing is
// sent over the connection, and the row verifies the chain against the pinned CA
// itself, so that it can say which check failed rather than only that one did.
func statusServingChain(kube status.Kube) func(context.Context) (status.PresentedChain, error) {
	rk, ok := kube.(restKube)
	if !ok || rk.cfg == nil {
		return nil
	}
	cfg := rk.cfg
	return func(ctx context.Context) (status.PresentedChain, error) {
		u, err := url.Parse(cfg.Host)
		if err != nil {
			return status.PresentedChain{}, fmt.Errorf("parse the apiserver URL %q: %w", cfg.Host, err)
		}
		pc := status.PresentedChain{Server: cfg.Host, Host: u.Hostname()}
		if cfg.TLSClientConfig.ServerName != "" {
			pc.Host = cfg.TLSClientConfig.ServerName
		}
		pc.CA = cfg.TLSClientConfig.CAData
		if len(pc.CA) == 0 && cfg.TLSClientConfig.CAFile != "" {
			if pc.CA, err = os.ReadFile(cfg.TLSClientConfig.CAFile); err != nil {
				return pc, fmt.Errorf("read the kubeconfig's CA file: %w", err)
			}
		}
		addr := u.Host
		if u.Port() == "" {
			addr = net.JoinHostPort(u.Hostname(), "443")
		}
		ctx, cancel := context.WithTimeout(ctx, statusAPITimeout)
		defer cancel()
		raw, err := (&tcpseg.Dialer{Timeout: statusAPITimeout}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return pc, err
		}
		tc := tls.Client(raw, &tls.Config{
			ServerName: pc.Host,
			MinVersion: tls.VersionTLS12,
			// Read-only: the chain is verified against pc.CA by the row.
			InsecureSkipVerify: true,
		})
		defer func() { _ = tc.Close() }()
		if err := tc.HandshakeContext(ctx); err != nil {
			return pc, err
		}
		pc.Chain = tc.ConnectionState().PeerCertificates
		return pc, nil
	}
}

// newDaemonsCollector assembles the collector for the launchd-only daemons
// probe. It wires launchd, the filesystem, the process table and the data-root
// reader, and NOTHING that reaches the apiserver or the runtime socket: no
// kubeconfig is resolved and no client is built, which is what keeps the probe
// cheap enough to poll.
func newDaemonsCollector() status.Collector {
	euid := os.Geteuid()
	serviceUID := lookupServiceUID()
	return status.Collector{
		Launchd:    launchctlProbe{},
		FS:         osStatusFS{},
		Procs:      procTable{},
		DataRoot:   dataRootFS{},
		StopMarker: statusStopMarker,
		// The LAN access record is world-readable; the daemon's applied
		// report is root-only, so the probe leaves it out.
		Network:    statusNetwork,
		Paths:      statusPaths(statusWorkDir(euid, serviceUID)),
		EUID:       euid,
		ServiceUID: serviceUID,
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
		AgentLabel:      install.AgentLabel,
		AgentLog:        install.AgentLogPath(),
		// The node credential store is the agent work dir — the directory the
		// first file a successful join writes lives in — so the report and the
		// installer's own verifier are looking at exactly one place.
		AgentCredentialDir: filepath.Dir(install.AgentCredentialPath(install.DefaultDataRoot)),
		DatavolLabel:       install.DatavolLabel,
		DatavolLog:         install.DatavolLogPath(),
		DataRoot:           install.DefaultDataRoot,
		WorkDir:            workDir,
		NetdSocket:         install.DefaultNetdSocket,
		NetdLog:            install.NetdLogPath(),
		ServerLog:          install.ServerLogPath(),
		ShadowManifest:     shadow.ManifestPath(install.DefaultInstallDir),
	}
}

// nodeResolverPresent reports whether netd's node resolver entry is in the
// host's dynamic store.
func nodeResolverPresent() (bool, error) {
	store, err := netdsvc.OpenSystemStore()
	if err != nil {
		return false, err
	}
	defer func() { _ = store.Close() }() // a read-only session; nothing to flush
	return store.Present(netdsvc.NodeResolverKey)
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

// ReadTail reads the last lines of a file for the STATUS REPORT, degrading a
// permission error to logUnreadableLine rather than propagating it.
//
// The daemon logs are install.LogFileMode, group admin, so an ordinary account
// gets EACCES on every one of them; that is the intended posture, not a fault,
// and a report that quotes the reason in the row is more use than one that
// drops the row. The `k3sm status logs` view does NOT come through here — it
// calls readTail directly, because a command whose whole job is to print a log
// must still exit non-zero and name the sudo that would work.
func (osStatusFS) ReadTail(path string, lines int) ([]string, error) {
	out, err := readTail(path, lines)
	if errors.Is(err, fs.ErrPermission) {
		return []string{logUnreadableLine}, nil
	}
	return out, err
}
func (osStatusFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// readTail returns the last n lines of path without reading the whole file: it
// seeks to the last logTailBudget bytes and drops the first (necessarily
// partial) line when it did seek.
//
// Every error, permission included, is the caller's to interpret: `k3sm status
// logs` turns EACCES into a sudo hint and a non-zero exit, while the report
// seam above turns it into a row.
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
	// cfg is the rest config the client was built from, which the serving-cert
	// row's handshake reads the URL and the pinned CA from.
	cfg *rest.Config
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

// statusKubeInputs is everything the report's credential choice reads, injected
// so the choice is a pure function of the role and the installed paths rather
// than of this process.
type statusKubeInputs struct {
	// role is the node THIS Mac is installed as, and it is the first thing the
	// choice reads: the two roles hold different credentials and address
	// different apiservers.
	role install.Role
	// nodeKubeconfig is the joined worker's own credential — the kubeconfig
	// `k3sm agent` writes on a successful join (install.AgentCredentialPath).
	nodeKubeconfig string
	// workDir is the control-plane work dir, read on the SERVER role only.
	workDir string
	// workDirOverride is K3SM_WORK_DIR verbatim, kubeconfigEnv is $KUBECONFIG,
	// and home is the invoking user's home — the three environment facts
	// resolveKubectlConfig reads for a control plane.
	workDirOverride string
	kubeconfigEnv   string
	home            string
	// exists reports whether a path is present (fileExists in production).
	exists func(string) bool
	// stat reports WHY a path is unusable, which exists cannot: fileExists
	// swallows EACCES into the same false a missing file produces, and on the
	// agent work dir — service-user-owned, mode 0700 — EACCES is the ordinary
	// answer for an unprivileged run. Reporting that as "no node credential"
	// would tell an operator to re-join a worker that is perfectly joined.
	// A nil stat means os.Stat.
	stat func(string) error
}

// statPath reports why a path is unusable, or nil when it is there and
// readable.
func (in statusKubeInputs) statPath(path string) error {
	if in.stat != nil {
		return in.stat(path)
	}
	_, err := os.Stat(path)
	return err
}

// statusKubeInputsFor gathers the credential choice's inputs for the role this
// Mac is installed as.
func statusKubeInputsFor(role install.Role, paths status.Paths) statusKubeInputs {
	home, _ := os.UserHomeDir()
	return statusKubeInputs{
		role:            role,
		nodeKubeconfig:  install.AgentCredentialPath(paths.DataRoot),
		workDir:         paths.WorkDir,
		workDirOverride: os.Getenv("K3SM_WORK_DIR"),
		kubeconfigEnv:   os.Getenv("KUBECONFIG"),
		home:            home,
		exists:          fileExists,
	}
}

// statusKubeconfig picks the credentials `k3sm status` reports on and probes the
// apiserver with, keyed on the installed ROLE.
//
// A worker is why this is not simply resolveKubectlConfig. It holds exactly one
// credential — the node kubeconfig a join wrote — and no control plane of its
// own, so the server work dir's admin kubeconfig is not its kubeconfig even
// when a stale one is sitting there from an earlier server-era install, and the
// loopback apiserver that kubeconfig names is not a thing this Mac serves.
// Reporting either would tell an operator their worker is degraded for a reason
// a worker cannot have. The role therefore wins outright here, K3SM_WORK_DIR
// included: that variable names a control-plane work dir, and this node has
// none.
//
// The probe target follows from the file: the client is built from the node
// kubeconfig, so the URL it dials is that kubeconfig's own cluster server —
// the same string nodecred.Credential.APIServerURL reports, because both read
// the cluster entry of this one file. It is deliberately NOT the assignment's
// APIServers list: that is every advertised endpoint of an HA control plane,
// and this row names ONE probe target and says whether it answered. Aggregating
// several endpoints into one row is a different shape than the row has.
func statusKubeconfig(in statusKubeInputs) (kubectlConfig, error) {
	if in.role == install.RoleAgent {
		if in.nodeKubeconfig == "" {
			return kubectlConfig{}, errors.New("no node credential path for this Mac")
		}
		switch err := in.statPath(in.nodeKubeconfig); {
		case err == nil:
			return kubectlConfig{kubeconfig: in.nodeKubeconfig}, nil
		case errors.Is(err, fs.ErrPermission):
			return kubectlConfig{}, fmt.Errorf("node credential %s is not readable by this account (re-run with sudo)", in.nodeKubeconfig)
		default:
			return kubectlConfig{}, fmt.Errorf("no node credential at %s", in.nodeKubeconfig)
		}
	}
	return resolveKubectlConfig(kubectlInputs{
		workDirOverride: in.workDirOverride,
		workDir:         in.workDir,
		kubeconfigEnv:   in.kubeconfigEnv,
		home:            in.home,
		contextName:     installedKubeconfigName(),
		exists:          in.exists,
	})
}

// newStatusKube resolves the report's credentials (statusKubeconfig) and builds
// a client with a short timeout. A nil Kube with a non-nil error is a reportable
// posture, not a failure: the report says which credentials were missing.
//
// On a control plane the resolution is exactly `k3sm kubectl`'s — the work dir's
// admin kubeconfig for root and the service user, the invoking user's own
// ~/.kube/config with the k3sm context otherwise.
func newStatusKube(in statusKubeInputs) (status.Kube, string, error) {
	cfg, err := statusKubeconfig(in)
	if err != nil {
		return nil, "", err
	}
	return buildStatusKube(cfg)
}

// statusEndpoints reads the endpoints record this node published, or nil
// (a node older than the record), from statusDir.
func statusEndpoints(statusDir string) *status.EndpointsRecord {
	return status.ReadEndpointsRecord(os.ReadFile, status.EndpointsPath(statusDir))
}

// installedStatusDir is the installed status directory, where the node
// publishes its endpoints record.
func installedStatusDir() string {
	return install.StateStatus.Path(install.DefaultDataRoot)
}

// localAddrs lists this Mac's interface addresses, for the server anchor. A
// failed read lists none, which leaves loopback as the only anchor.
func localAddrs() []netip.Addr {
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range ifaddrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out
}

// statusUserKubeFor returns, on an agent, the reader of the invoking account's
// own kubeconfig the report falls back to when the node credential is not
// readable (status.Collector.UserKube); nil on a server, which resolves the
// user's kubeconfig already.
//
// joinServer reads the agent's --server, which anchors the context: only a
// context whose server is on that host is used.
func statusUserKubeFor(role install.Role, joinServer func() (string, error), statusDir string) func() (status.Kube, string, error) {
	if role != install.RoleAgent {
		return nil
	}
	return func() (status.Kube, string, error) {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		raw, err := rules.Load()
		if err != nil {
			return nil, "", err
		}
		join, err := joinServer()
		if err != nil {
			return nil, "", fmt.Errorf("the server this Mac joined is unknown, so no context can be shown to point at it: %w", err)
		}
		name := installedKubeconfigName()
		ctxName, ok := status.UserKubeContext(raw, name, status.NodeAnchor(statusEndpoints(statusDir), status.JoinAnchor(join)))
		if !ok {
			return nil, "", fmt.Errorf("neither the %q context nor the current one points at the server this Mac joined", name)
		}
		return buildStatusKube(kubectlConfig{context: ctxName})
	}
}

// buildStatusKube builds the report's apiserver client for one resolved
// kubeconfig and context, with the probe timeout.
func buildStatusKube(cfg kubectlConfig) (status.Kube, string, error) {
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
	return restKube{client: cs, server: restCfg.Host, tls: tlsPosture(restCfg), cfg: restCfg}, kubeSource(cfg, rules), nil
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
