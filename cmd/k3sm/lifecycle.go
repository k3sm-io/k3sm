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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	"k3sm.io/darwin-net/pkg/netd/wire"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/kubeclient"
)

// The lifecycle verbs: `k3sm stop`, `k3sm start`, `k3sm restart`. The
// sequences live in pkg/install (Stop, Start, Restart); this file owns the
// flags, the exit codes, and the two cluster-facing calls the sequences make
// through Config: cordoning the Node, and asking netd to remove the mesh.

// The lifecycle exit codes. A stop that left something behind exits with
// install.StopExitLeftoverBase plus one bit per class (see stopUsage).
const (
	exitLifecycleFailed = 1
	exitLifecycleUsage  = 2
	// exitNeedsRoot is a lifecycle verb run without root: nothing was done.
	exitNeedsRoot = 3
)

// StoppedByUserAnnotation is the Node annotation a stop sets and a start
// clears. Its value is a stopAnnotation, JSON-encoded.
const StoppedByUserAnnotation = "k3sm.io/stopped-by-user"

// stopAnnotation is the value of StoppedByUserAnnotation. Cordoned records
// whether the stop did the cordon (the Node was schedulable before it), so a
// start never uncordons a Node an administrator cordoned for another reason.
type stopAnnotation struct {
	Actor    string    `json:"actor"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
	Cordoned bool      `json:"cordoned"`
}

// lifecycleGeteuid is os.Geteuid, a seam so the root refusal is testable.
var lifecycleGeteuid = os.Geteuid

// netdRemoveMeshVerb is the hidden subcommand `k3sm stop` runs, as the k3sm
// service user, to send netd its RemoveMesh RPC: netd admits only that uid on
// its socket, and the stop runs as root.
const netdRemoveMeshVerb = "__netd-remove-mesh"

func stopUsage() string {
	return fmt.Sprintf(`Usage: sudo k3sm stop [--reason TEXT] [--actor user|auto]

Stop k3sm on this Mac completely, and keep it stopped across reboots until
'sudo k3sm start'. In order: mark the node stopping, cordon and annotate it
(best effort), disable and stop the node daemon, remove the wireguard mesh,
stop every pod (SIGTERM, 10s grace, then SIGKILL) and any vm helper, remove
k3sm's addresses from lo0 and the interconnect, disable and stop netd, and
mark the node stopped. The daemon plists stay installed. Re-running it is
safe: it finishes an interrupted stop, and does nothing on a stopped node.

On a server this stops the cluster's control plane: joined workers lose it
until 'sudo k3sm start'.

Time bound: at most %s on a server (cordon 15s, the node daemon's 60s
ExitTimeOut plus 15s for launchd, RemoveMesh 15s, pod grace 10s, vm helpers
5s, netd 30s); a worker's is no longer. The stop is cut off at that bound
plus 30s, or by SIGINT, SIGTERM or SIGHUP; it then exits naming what it left
behind, and re-running it converges.

Exit codes:
  0      stopped, or already stopped
  1      refused or failed before anything was stopped
  2      usage
  3      not run as root (nothing was done)
  32+N   stopped part-way: the node stays marked stopping and N names what was
         left behind, one bit each: 1 the node daemon, 2 pods or vm helpers or
         control-plane processes, 4 the mesh, 8 lo0/interconnect/pf state,
         16 netd, 32 the stop marker. Re-run 'sudo k3sm stop' to converge.

Flags:
  --reason TEXT   why, recorded in the stop marker and the logs
  --actor WHO     user (default), or auto for an automatic stop
`, install.StopTimeBound())
}

// lifecycleFlags parses the flags every lifecycle verb shares, plus the
// verb's own flags, which extra (when non-nil) registers. A parse failure has
// already been printed.
func lifecycleFlags(verb string, args []string, stderr io.Writer, usage string, extra func(fs *flag.FlagSet)) (actor, reason string, ok bool) {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	fs.StringVar(&reason, "reason", "k3sm "+verb, "why, recorded in the logs")
	fs.StringVar(&actor, "actor", install.ActorUser, "user or auto")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return "", "", false
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "k3sm %s: unexpected arguments %q\n", verb, fs.Args())
		return "", "", false
	}
	return actor, reason, true
}

// lifecycleExit prints err and maps it to the verb's exit code.
func lifecycleExit(verb string, err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	fmt.Fprintf(stderr, "k3sm %s: %v\n", verb, err)
	if errors.Is(err, install.ErrNodeStillCordoned) {
		fmt.Fprintf(stderr, "%s: the daemons are up; re-run 'sudo k3sm start' to uncordon it\n", install.StillCordonedMarker)
	}
	var serr *install.StopIncompleteError
	if errors.As(err, &serr) {
		return serr.ExitCode()
	}
	return exitLifecycleFailed
}

// requireRoot refuses a lifecycle verb run without root.
func requireRoot(verb string, stderr io.Writer) bool {
	if lifecycleGeteuid() == 0 {
		return true
	}
	fmt.Fprintf(stderr, "k3sm %s must run as root: use 'sudo k3sm %s' (nothing was done)\n", verb, verb)
	return false
}

// runStop is `k3sm stop`.
func runStop(args []string, stderr io.Writer) int {
	actor, reason, ok := lifecycleFlags("stop", args, stderr, stopUsage(), nil)
	if !ok {
		return exitLifecycleUsage
	}
	if !requireRoot("stop", stderr) {
		return exitNeedsRoot
	}
	sys := install.NewDarwinSystem()
	ctx, cancel := lifecycleContext(install.StopTimeBound())
	defer cancel()
	return lifecycleExit("stop", install.Stop(ctx, sys, lifecycleConfig(sys, stderr), actor, reason), stderr)
}

// lifecycleConfig wires a lifecycle verb's Config: the logger and the
// cluster-facing calls.
func lifecycleConfig(sys install.System, stderr io.Writer) install.Config {
	return install.Config{
		Logger:        newDaemonLogger(stderr, slog.LevelInfo),
		MarkNode:      nodeMarker(sys, install.DefaultDataRoot),
		RemoveMesh:    netdRemoveMesh(install.DefaultNetdSocket),
		JoinedWorkers: joinedWorkers(sys, install.DefaultDataRoot),
	}
}

// joinedWorkers returns the Config.JoinedWorkers call a server stop makes:
// the Nodes the control plane knows, through the admin kubeconfig, other
// than this server's own.
func joinedWorkers(sys install.System, dataRoot string) func(ctx context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		kubeconfig, self, err := lifecycleNodeIdentity(sys, dataRoot)
		if err != nil {
			return 0, err
		}
		_, cs, err := kubeclient.FromPath(kubeconfig)
		if err != nil {
			return 0, fmt.Errorf("load kubeconfig %s: %w", kubeconfig, err)
		}
		return countJoinedWorkers(ctx, cs, self)
	}
}

// countJoinedWorkers counts the Nodes other than self.
func countJoinedWorkers(ctx context.Context, cs kubernetes.Interface, self string) (int, error) {
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("list nodes: %w", err)
	}
	n := 0
	for _, node := range nodes.Items {
		if node.Name != self {
			n++
		}
	}
	return n, nil
}

// lifecycleContext is the context a stop or start runs under: cancelled by
// SIGINT, SIGTERM or SIGHUP, and by a deadline of bound plus
// install.LifecycleMargin,
// so the bound the help states is enforced. An interrupted stop leaves its
// marker at stopping, and a rerun converges.
func lifecycleContext(bound time.Duration) (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	ctx, cancel := context.WithTimeout(ctx, bound+install.LifecycleMargin)
	return ctx, func() { cancel(); stop() }
}

// nodeMarker returns the Config.MarkNode call: it finds this Mac's Node and
// the credential to reach it with, then cordons/annotates it or undoes that
// (markNodeObject).
//
// A worker uses its own node credential, which may patch only its own Node
// (the Node authorizer); its name is the credential's certificate CN. A server
// uses the admin kubeconfig its control plane writes, and the node name the
// installed server runs with (--node-name, else the hostname-derived default).
func nodeMarker(sys install.System, dataRoot string) func(ctx context.Context, stopped bool, actor, reason string) error {
	return func(ctx context.Context, stopped bool, actor, reason string) error {
		kubeconfig, name, err := lifecycleNodeIdentity(sys, dataRoot)
		if err != nil {
			// Read from local files, so a start's uncordon does not retry it.
			return fmt.Errorf("%w: %w", install.ErrNodeIdentity, err)
		}
		_, cs, err := kubeclient.FromPath(kubeconfig)
		if err != nil {
			return fmt.Errorf("load kubeconfig %s: %w", kubeconfig, err)
		}
		return markNodeObject(ctx, cs, name, stopped, actor, reason, time.Now())
	}
}

// lifecycleNodeIdentity returns the kubeconfig and node name nodeMarker uses.
func lifecycleNodeIdentity(sys install.System, dataRoot string) (kubeconfig, name string, err error) {
	if _, agent, err := install.RoleInstalled(sys, install.RoleAgent); err != nil {
		return "", "", err
	} else if agent {
		store := nodeCredentialStore{dir: filepath.Dir(install.AgentCredentialPath(dataRoot))}
		_, cred, err := store.Status(time.Now())
		if err != nil {
			return "", "", fmt.Errorf("read this node's credential: %w", err)
		}
		if cred == nil {
			return "", "", errors.New("this node holds no usable credential")
		}
		name, err := nodeNameFromClientCert(cred.ClientCertPEM)
		if err != nil {
			return "", "", err
		}
		return install.AgentCredentialPath(dataRoot), name, nil
	}
	args, err := install.InstalledServerArgs(sys.ReadFile, filepath.Join(install.DefaultLaunchDaemonDir, install.ServerLabel+".plist"), dataroot.DefaultServerArgsRecordPath)
	if err != nil {
		return "", "", err
	}
	name = install.ServerArgValue(args, "node-name")
	if name == "" {
		name = defaultNodeName()
	}
	return filepath.Join(dataRoot, "server", "k3sm.kubeconfig"), name, nil
}

// markNodeObject cordons the Node and sets StoppedByUserAnnotation (stopped),
// or removes the annotation and uncordons the Node if, and only if, the stop
// did the cordon (!stopped). A start on a Node with no annotation changes
// nothing. A rerun of a stop keeps the first stop's Cordoned answer.
//
// The patch carries the resourceVersion the decision was made on, so a
// concurrent writer (the node daemon's own status updates, an administrator's
// cordon) turns it into a 409 instead of a patch over a Node the decision no
// longer describes; the Get-decide-Patch is then re-run.
func markNodeObject(ctx context.Context, cs kubernetes.Interface, name string, stopped bool, actor, reason string, now time.Time) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return markNodeOnce(ctx, cs, name, stopped, actor, reason, now)
	})
}

// markNodeOnce is one Get-decide-Patch of markNodeObject.
func markNodeOnce(ctx context.Context, cs kubernetes.Interface, name string, stopped bool, actor, reason string, now time.Time) error {
	node, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node %s: %w", name, err)
	}
	var prior *stopAnnotation
	if raw, ok := node.Annotations[StoppedByUserAnnotation]; ok {
		var a stopAnnotation
		if json.Unmarshal([]byte(raw), &a) == nil {
			prior = &a
		}
	}
	var patch map[string]any
	if stopped {
		a := stopAnnotation{Actor: actor, Reason: reason, At: now.UTC(), Cordoned: !node.Spec.Unschedulable}
		if prior != nil {
			a.Cordoned = prior.Cordoned
		}
		value, err := json.Marshal(a)
		if err != nil {
			return err
		}
		patch = map[string]any{
			"metadata": map[string]any{
				"resourceVersion": node.ResourceVersion,
				"annotations":     map[string]any{StoppedByUserAnnotation: string(value)},
			},
			"spec": map[string]any{"unschedulable": true},
		}
	} else {
		if _, ok := node.Annotations[StoppedByUserAnnotation]; !ok {
			return nil
		}
		patch = map[string]any{"metadata": map[string]any{
			"resourceVersion": node.ResourceVersion,
			"annotations":     map[string]any{StoppedByUserAnnotation: nil},
		}}
		if prior != nil && prior.Cordoned {
			patch["spec"] = map[string]any{"unschedulable": false}
		}
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	if _, err := cs.CoreV1().Nodes().Patch(ctx, name, types.MergePatchType, data, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch node %s: %w", name, err)
	}
	return nil
}

// netdRemoveMesh returns the Config.RemoveMesh call. netd's peer verifier
// admits only the k3sm service user, so the root stop runs this binary's
// hidden netdRemoveMeshVerb as that user (serviceCredential: none of root's
// groups), from /, with an empty environment, and the child sends the RPC. The child's output is the error text on failure.
func netdRemoveMesh(socket string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		u, err := user.Lookup(install.DefaultServiceUser)
		if err != nil {
			return fmt.Errorf("look up %s: %w", install.DefaultServiceUser, err)
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return fmt.Errorf("uid of %s: %w", install.DefaultServiceUser, err)
		}
		gid, err := strconv.ParseUint(u.Gid, 10, 32)
		if err != nil {
			return fmt.Errorf("gid of %s: %w", install.DefaultServiceUser, err)
		}
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate this binary: %w", err)
		}
		cmd := exec.CommandContext(ctx, self, netdRemoveMeshVerb, "--socket", socket)
		cmd.Env = []string{}
		cmd.Dir = "/"
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: serviceCredential(uint32(uid), uint32(gid))}
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// serviceCredential is the identity the RemoveMesh child runs as: the
// service user's uid, its own primary gid, and a supplementary group list of
// exactly that gid. NoSetGroups stays false so the child does NOT inherit
// root's supplementary groups (wheel, admin and the rest).
func serviceCredential(uid, gid uint32) *syscall.Credential {
	return &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{gid}, NoSetGroups: false}
}

// runNetdRemoveMesh is the hidden netdRemoveMeshVerb: one RemoveMesh RPC to
// the netd socket, bounded. It grants nothing: netd decides by the caller's
// uid whether to answer.
func runNetdRemoveMesh(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet(netdRemoveMeshVerb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", install.DefaultNetdSocket, "netd socket")
	if err := fs.Parse(args); err != nil {
		return exitLifecycleUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := wire.NewClient(*socket).RemoveMesh(ctx); err != nil {
		fmt.Fprintln(stderr, "netd RemoveMesh:", err)
		return exitLifecycleFailed
	}
	return 0
}

// startUsage is `k3sm start --help`.
var startUsage = fmt.Sprintf(`Usage: sudo k3sm start [--reason TEXT] [--actor user|auto]
       k3sm start --print-time-bound

Start k3sm on this Mac after 'k3sm stop': clear what a stop may have left
(finishing an interrupted one), remove the stop marker, enable and start netd
and then the node daemon, and uncordon the node a stop cordoned, retrying
until the apiserver answers (at most %s). On a node that is already running
it restarts nothing: it finishes an uncordon an earlier start ran out of time
for, and otherwise makes one best-effort uncordon attempt.

It is cut off after %s, or by SIGINT, SIGTERM or SIGHUP; the stop marker
stays until the daemons are up, so re-running it is safe.

--print-time-bound prints that cut-off as a whole number of seconds and
exits 0, without root and without doing anything else, so a caller can wait
on a start for exactly as long as the start itself runs.

Exit codes: 0 started or already running; 1 failed, or the daemons are up but
the node is still cordoned (stderr then carries the line "%s: ...";
re-run 'sudo k3sm start' to uncordon it); 2 usage; 3 not run as root.
`, install.UncordonBound(), install.StartCutoff(), install.StillCordonedMarker)

// restartUsage is `k3sm restart --help`.
const restartUsage = `Usage: sudo k3sm restart [--start] [--reason TEXT] [--actor user|auto]

Restart the k3sm daemons; pods keep running. On a node stopped with 'k3sm stop'
it refuses, unless --start is given, which starts the node instead.

Exit codes: 0 restarted; 1 failed or refused; 2 usage; 3 not run as root.
`

// startTimeBoundSeconds is what `k3sm start --print-time-bound` prints:
// install.StartCutoff, the deadline lifecycleContext enforces on a start, in
// whole seconds rounded up.
func startTimeBoundSeconds() int64 {
	return int64((install.StartCutoff() + time.Second - 1) / time.Second)
}

// runStart is `k3sm start`.
func runStart(args []string, stdout, stderr io.Writer) int {
	var printBound bool
	actor, reason, ok := lifecycleFlags("start", args, stderr, startUsage, func(fs *flag.FlagSet) {
		fs.BoolVar(&printBound, "print-time-bound", false, "print the start's cut-off in seconds and exit")
	})
	if !ok {
		return exitLifecycleUsage
	}
	if printBound {
		// Before the root check, and nothing after it: no daemon is contacted.
		if _, err := fmt.Fprintf(stdout, "%d\n", startTimeBoundSeconds()); err != nil {
			return exitLifecycleFailed
		}
		return 0
	}
	if !requireRoot("start", stderr) {
		return exitNeedsRoot
	}
	sys := install.NewDarwinSystem()
	ctx, cancel := lifecycleContext(install.StartTimeBound())
	defer cancel()
	return lifecycleExit("start", install.Start(ctx, sys, lifecycleConfig(sys, stderr), actor, reason), stderr)
}

// runRestart is `k3sm restart`.
func runRestart(args []string, stderr io.Writer) int {
	var start bool
	actor, reason, ok := lifecycleFlags("restart", args, stderr, restartUsage, func(fs *flag.FlagSet) {
		fs.BoolVar(&start, "start", false, "start the node if the user stopped it")
	})
	if !ok {
		return exitLifecycleUsage
	}
	if !requireRoot("restart", stderr) {
		return exitNeedsRoot
	}
	sys := install.NewDarwinSystem()
	cfg := lifecycleConfig(sys, stderr)
	cfg.Start = start
	ctx := context.Background()
	if start {
		// --start may be a start: the same bound, and the same signals, as
		// `k3sm start`, so its help and its behaviour agree.
		var cancel context.CancelFunc
		ctx, cancel = lifecycleContext(install.StartTimeBound())
		defer cancel()
	}
	return lifecycleExit("restart", install.Restart(ctx, sys, cfg, actor, reason), stderr)
}
