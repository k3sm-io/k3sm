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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/update"
	"k3sm.io/k3sm/pkg/updatectl"
	"k3sm.io/k3sm/pkg/version"
)

// updateUsage is `k3sm update --help`.
const updateUsage = `k3sm update — check for a newer k3sm release and roll the cluster to one

Usage:
  k3sm update check [-o text|json]
  k3sm update apply [--version <tag>] [--drain] [--allow-downgrade]
                    [--signature if-signed|required] [--yes]
                    [--pin-sha256 <digest> [--manifest-sha256 <digest>]]
  k3sm update apply --clear-pin
  k3sm update status [-o text|json] [--watch]
  k3sm update cancel
  k3sm update abort

  check   resolve the latest release the way install.sh does, and compare this
          Mac's k3sm and every node's with it; the result is also recorded
          for the update row of ` + "`k3sm status`" + ` (as root or the service user)
  apply   print the plan (the nodes in roll order, workers first and the
          server last, with their versions; the target; drain; the signature
          policy), ask for confirmation, then create the Update named
          "current" that the server's update controller rolls; the target is
          the latest release unless --version names one. It refuses while an
          Update is still in progress, and replaces a finished one
  status  the Update's phase, the resolved release, each node's progress and
          the conditions; --watch re-prints on every change until it finishes
  cancel  stop the roll: the node being updated finishes, the nodes not yet
          started are left on the release they run (a cancel is not a
          rollback)
  abort   the recovery after a failed step: clear the k3sm.io/update-*
          annotations on every node, uncordon each node the controller
          cordoned (never one you cordoned), and mark the Update Cancelled

Flags:
  -o text|json        output format (check, status; default text)
  --version <tag>     the release to move to (apply; default the latest)
  --drain             evict each node's pods before updating it, except the
                      server's (apply)
  --allow-downgrade   permit a release older than a node runs (apply)
  --signature if-signed|required
                      the code-signature policy for the release (apply;
                      default if-signed: the installed build's signer)
  --yes               do not ask for confirmation (apply; required when
                      stdin is not a terminal)
  --pin-sha256 <digest>
                      bind the roll to this darwin/arm64 archive sha256 (apply;
                      root only; needs --version): the release pin is written
                      to the server before the Update is created, and the
                      update controller refuses the release, before any node
                      is cordoned, unless its checksums file carries exactly
                      this digest
  --manifest-sha256 <digest>
                      also bind the release's payload manifest to this sha256
                      (apply; needs --pin-sha256): the update controller
                      refuses the release, before any node is cordoned,
                      unless its manifest file has exactly this digest; take
                      the digest from a source other than the release host
                      (a digest read from the host binds nothing)
  --clear-pin         remove the release pin and exit (apply; root only); a pin
                      directory that cannot be trusted is moved aside, and the
                      aside entries stay in the work dir for the service user
                      to remove
  --watch             keep printing until the update finishes (status)

Every subcommand reaches the cluster with the credentials
` + "`k3sm status`" + ` uses: the server's admin kubeconfig as root or the service
user, the k3sm context of ~/.kube/config otherwise. Only check also works
with no reachable cluster: it then compares this Mac's k3sm alone with the
latest release.

Exit codes: 0 done, 1 it could not be done (the error says why), 2 usage, or
apply without --yes on a stdin that is not a terminal.
`

// updateEnv is everything `k3sm update` reads and writes, injected so the verb
// runs against a fake release index and cluster in tests.
type updateEnv struct {
	out, errOut io.Writer
	// inputs are the check's inputs; inputs.Kube is nil when kubeErr says why
	// no cluster could be asked.
	inputs  update.Inputs
	kubeErr error
	// workDir is the server work dir; the check refreshes the record in the
	// status directory beside it (status.Dir).
	workDir string
	// dyn reads and writes the Update objects; nil when kubeErr says why.
	dyn dynamic.Interface
	// in is apply's confirmation input, and inTerminal whether it is a
	// terminal (a non-terminal stdin without --yes refuses).
	in         io.Reader
	inTerminal bool
	// watchEvery is how often `status --watch` re-reads; zero is
	// updateWatchEvery.
	watchEvery time.Duration
	// root is whether this process runs as root, the only identity that may
	// write or clear the release pin.
	root bool
	// writePin and clearPin write and remove the release pin under workDir;
	// nil means updatectl.WriteReleasePin and updatectl.ClearReleasePin.
	writePin func(workDir string, pin updatectl.ReleasePin) error
	clearPin func(workDir string) (updatectl.Cleared, error)
}

// newUpdateEnv wires the production environment: the GitHub release index, the
// installed version, and the cluster `k3sm status` reports on.
func newUpdateEnv() updateEnv {
	euid := os.Geteuid()
	workDir := statusWorkDir(euid, lookupServiceUID())
	role, _ := installedRole()
	env := updateEnv{
		out:     os.Stdout,
		errOut:  os.Stderr,
		inputs:  update.Inputs{BaseURL: checkBase(installedReleaseBase(role)), Installed: version.Get()},
		workDir: workDir,
		in:      os.Stdin,
		root:    euid == 0,
	}
	if fi, err := os.Stdin.Stat(); err == nil {
		env.inTerminal = fi.Mode()&fs.ModeCharDevice != 0
	}
	cs, dyn, err := statusClients(statusKubeInputsFor(role, statusPaths(workDir)))
	if err != nil {
		env.kubeErr = err
	} else {
		env.inputs.Kube, env.dyn = cs, dyn
	}
	return env
}

// statusClients are the clientset and a dynamic client over the apiserver
// client `k3sm status` resolves (newStatusKube), so the verb reads the Nodes
// and the Update of the cluster the report describes, over the same
// credentials.
func statusClients(in statusKubeInputs) (kubernetes.Interface, dynamic.Interface, error) {
	k, _, err := newStatusKube(in)
	if err != nil {
		return nil, nil, err
	}
	rk, ok := k.(restKube)
	if !ok {
		return nil, nil, fmt.Errorf("the status client is a %T, not a clientset", k)
	}
	dyn, err := dynamic.NewForConfig(rk.cfg)
	if err != nil {
		return nil, nil, err
	}
	return rk.client, dyn, nil
}

// runUpdate is `k3sm update <subcommand>`; it returns the exit code.
func runUpdate(ctx context.Context, args []string, env updateEnv) int {
	if len(args) == 0 {
		fmt.Fprint(env.errOut, updateUsage)
		return exitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(env.out, updateUsage)
		return 0
	case "check":
		return runUpdateCheck(ctx, args[1:], env)
	case "apply":
		return runUpdateApply(ctx, args[1:], env)
	case "status":
		return runUpdateStatus(ctx, args[1:], env)
	case "cancel":
		return runUpdateCancel(ctx, args[1:], env)
	case "abort":
		return runUpdateAbort(ctx, args[1:], env)
	}
	fmt.Fprintf(env.errOut, "k3sm update: unknown subcommand %q\n\n%s", args[0], updateUsage)
	return exitUsage
}

// runUpdateCheck runs one check, records it for `k3sm status`, and prints it.
// A record it may not write (an ordinary account, which cannot write the
// service user's status directory) is a note on stderr, never a failed check.
func runUpdateCheck(ctx context.Context, args []string, env updateEnv) int {
	fsFlags := flag.NewFlagSet("update check", flag.ContinueOnError)
	fsFlags.SetOutput(env.errOut)
	format := fsFlags.String("o", "text", "output format: text or json")
	if err := fsFlags.Parse(args); err != nil {
		return exitUsage
	}
	if fsFlags.NArg() > 0 || (*format != "text" && *format != "json") {
		fmt.Fprint(env.errOut, updateUsage)
		return exitUsage
	}
	if env.kubeErr != nil {
		fmt.Fprintf(env.errOut, "k3sm update: not comparing the cluster's nodes: %v\n", env.kubeErr)
	}
	rep, checkErr := update.Check(ctx, env.inputs)
	if env.workDir != "" {
		if err := writeUpdateRecord(env.workDir, rep.Record(checkErr)); err != nil {
			fmt.Fprintln(env.errOut, updateNotRecorded(err))
		}
	}
	if checkErr != nil {
		fmt.Fprintln(env.errOut, "k3sm update check:", checkErr)
		return exitInternalError
	}
	if *format == "json" {
		enc := json.NewEncoder(env.out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(env.errOut, "k3sm update check:", err)
			return exitInternalError
		}
		return 0
	}
	renderUpdate(env.out, rep)
	return 0
}

// renderUpdate prints the report for a person.
func renderUpdate(w io.Writer, rep update.Report) {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	latest := rep.Latest.Tag
	if rep.Latest.Published != "" {
		latest += ", published " + rep.Latest.Published
	}
	fmt.Fprintf(tw, "latest\t%s\n", latest)
	if rep.Latest.KubeVersion != "" {
		fmt.Fprintf(tw, "kubernetes\t%s\n", rep.Latest.KubeVersion)
	}
	installed := rep.InstalledState
	if !rep.InstalledDirty {
		installed = withUntagged(installed, rep.Installed, rep.Latest.Tag, status.BuildState)
	}
	fmt.Fprintf(tw, "installed\t%s (%s)\n", rep.Installed, installed)
	if len(rep.Nodes) > 0 {
		fmt.Fprintf(tw, "\nNODE\tVERSION\tSTATE\n")
		// Node names and versions are what each node says of itself, so they
		// are control-stripped before they reach a terminal.
		for _, n := range rep.Nodes {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", status.ClipText(n.Name, 253), status.ClipText(n.Version, 128), withUntagged(n.State, n.Version, rep.Latest.Tag, status.NodeBuildState))
		}
	}
	_ = tw.Flush()
}

// withUntagged appends ", untagged build of X.Y.Z" to state when ver is a
// build of an untagged commit that compares as state (buildState is
// status.BuildState or status.NodeBuildState), and returns state unchanged
// otherwise.
func withUntagged(state, ver, latest string, buildState func(have, latest string) (string, string)) string {
	if s, of := buildState(ver, latest); of != "" && s == state {
		return state + ", " + status.UntaggedLabel(of)
	}
	return state
}

// updateNotRecorded is what `k3sm update check` says when it could not write
// the record `k3sm status` reads. A permission error is the common case (an
// account that is not root may not write the status directory) and is named
// as such, without the temporary file's path; any other error keeps its text.
func updateNotRecorded(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "k3sm update: not recorded for `k3sm status`: writing the record needs root; run with sudo to record it"
	}
	return fmt.Sprintf("k3sm update: not recorded for `k3sm status` (%v); run with sudo to record it", err)
}

// errNoStatusDir is a work dir with no status directory beside it (a work dir
// outside an install): there is nowhere for `k3sm status` to read a record.
var errNoStatusDir = errors.New("no status directory")

// writeUpdateRecord writes rec to status.UpdatePath(workDir), 0644, in the
// user-readable status directory (status.Dir), through writeFileAtomic like the
// server's other records there. The directory is install's; this never creates
// it. Before any write it is Lstat'ed and held to checkStatusDir: a real
// directory, owned by root or the work dir's owner.
func writeUpdateRecord(workDir string, rec status.UpdateRecord) error {
	dir := status.Dir(workDir)
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w at %s", errNoStatusDir, dir)
	}
	if err != nil {
		return err
	}
	owner, err := fileOwner(workDir)
	if err != nil {
		return err
	}
	if err := checkStatusDir(dir, fi, owner); err != nil {
		return err
	}
	return writeFileAtomic(status.UpdatePath(workDir), rec, 0o644)
}

// checkStatusDir refuses a status directory the record must not be written
// into: anything but a real directory (a symlink could point the write
// anywhere the writer may write), or one owned by neither root nor the work
// dir's owner (whoever owns it controls what sits beside the record).
func checkStatusDir(dir string, fi fs.FileInfo, workDirOwner uint32) error {
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write the update record: %s is a symlink, not a directory", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("refusing to write the update record: %s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("refusing to write the update record: cannot read the owner of %s", dir)
	}
	if st.Uid != 0 && st.Uid != workDirOwner {
		return fmt.Errorf("refusing to write the update record: %s is owned by uid %d, neither root nor the work dir's owner (uid %d)", dir, st.Uid, workDirOwner)
	}
	return nil
}

// fileOwner is the uid that owns path.
func fileOwner(path string) (uint32, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot read the owner of %s", path)
	}
	return st.Uid, nil
}

// updateCheckDue is how long a server waits before its next update check: the
// remainder of interval since the recorded check, so a restart does not ask
// the index again within the hour. An absent or unreadable record is due now.
func updateCheckDue(workDir string, now time.Time, interval time.Duration) time.Duration {
	raw, err := os.ReadFile(status.UpdatePath(workDir))
	if err != nil {
		return 0
	}
	var rec status.UpdateRecord
	if json.Unmarshal(raw, &rec) != nil {
		return 0
	}
	if wait := rec.CheckedAt.Add(interval).Sub(now); wait > 0 && wait <= interval {
		return wait
	}
	return 0
}

// updateRecorder keeps the update record for `k3sm status` fresh on a server:
// the release check at most once an interval, and the managed update in
// progress every rollEvery, so a roll started anywhere shows in the update row.
type updateRecorder struct {
	workDir string
	// check is one release check (update.Check against the release index).
	check func(ctx context.Context) (update.Report, error)
	// dyn reads the Update; nil records no roll.
	dyn dynamic.Interface
	// interval is the check interval, rollEvery the roll poll.
	interval, rollEvery time.Duration
	now                 func() time.Time
	logger              *slog.Logger
	// publish puts the record's latest release on this server's Node
	// (status.UpdateAnnotations), where a worker's `k3sm status` reads it;
	// nil publishes nothing.
	publish func(ctx context.Context, annotations map[string]string) error
}

// checkBase is the release index a check reads: the validated release base,
// or GitHub's when there is none.
func checkBase(baseURL string) string {
	if baseURL == "" {
		return update.DefaultBaseURL
	}
	return baseURL
}

// installedReleaseBase is the --update-release-base recorded on the installed
// server, read the way the server's other arguments are (the plist, else the
// arguments record), or "" when there is none or it cannot be read.
func installedReleaseBase(role install.Role) string {
	if role != install.RoleServer {
		return ""
	}
	args, err := install.InstalledServerArgs(os.ReadFile, installedPlistPath(install.ServerLabel), dataroot.DefaultServerArgsRecordPath)
	if err != nil {
		return ""
	}
	return releaseBaseURL(install.ServerArgValue(args, update.ReleaseBaseFlag))
}

// runUpdateRecorder starts the server's update recorder: the hourly check
// against the release index (baseURL, the recorded --update-release-base, or
// GitHub's when empty) and the Update poll over dyn.
func runUpdateRecorder(ctx context.Context, workDir, nodeName, baseURL string, cs kubernetes.Interface, dyn dynamic.Interface, logger *slog.Logger) {
	updateRecorder{
		publish: nodeAnnotationPublisher(cs, nodeName),
		workDir: workDir,
		check: func(ctx context.Context) (update.Report, error) {
			return update.Check(ctx, update.Inputs{BaseURL: checkBase(baseURL), Kube: cs, Installed: version.Get()})
		},
		dyn:       dyn,
		interval:  status.UpdateRecordInterval,
		rollEvery: status.UpdateRollEvery,
		now:       time.Now,
		logger:    logger,
	}.run(ctx)
}

// run refreshes the record until ctx ends. Every failure is logged and
// survivable: a check is a report, never a reason to stop a server, and a
// failed one is itself recorded so the row says why. The one goroutine owns
// roll, so the check's record carries the roll last seen and the roll's
// refresh keeps the last check's fields.
func (r updateRecorder) run(ctx context.Context) {
	check := time.NewTimer(updateCheckDue(r.workDir, r.now(), r.interval))
	defer check.Stop()
	poll := time.NewTimer(0)
	defer poll.Stop()
	var roll *status.UpdateRoll
	var published map[string]string
	for {
		select {
		case <-ctx.Done():
			return
		case <-check.C:
			rep, err := r.check(ctx)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				r.logger.Info("could not check for a k3sm update", "err", err)
			}
			rec := rep.Record(err)
			rec.Roll = roll
			r.write(rec)
			published = r.publishRecord(ctx, published)
			check.Reset(r.interval)
		case <-poll.C:
			poll.Reset(r.rollEvery)
			// Also on the poll: the Node may not be registered at the first
			// check, and `k3sm update check` rewrites the record on its own.
			published = r.publishRecord(ctx, published)
			if r.dyn == nil {
				continue
			}
			u, err := getUpdate(ctx, r.dyn)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				// The CRD not served yet, or the apiserver away: the last
				// roll ages out of the row on its own (UpdateRollStaleAfter).
				r.logger.Debug("could not read the Update for `k3sm status`", "err", err)
				continue
			}
			next := updateRollFrom(u, r.now())
			if next == nil && roll == nil {
				continue
			}
			roll = next
			rec := readUpdateRecord(r.workDir)
			rec.Roll = roll
			r.write(rec)
		}
	}
}

// publishRecord publishes the recorded latest release when it differs from
// what was last published, and returns what is now published. A failure is
// logged and retried on the next poll; a record with no usable latest release
// publishes nothing, so the Node keeps the last good one.
func (r updateRecorder) publishRecord(ctx context.Context, published map[string]string) map[string]string {
	if r.publish == nil {
		return published
	}
	want := status.UpdateAnnotations(readUpdateRecord(r.workDir))
	if want == nil || sameAnnotations(want, published) {
		return published
	}
	if err := r.publish(ctx, want); err != nil {
		if ctx.Err() == nil {
			r.logger.Debug("could not publish the latest release on this server's Node", "err", err)
		}
		return published
	}
	return want
}

// sameAnnotations reports whether a and b hold the same keys and values.
func sameAnnotations(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// nodeAnnotationPublisher merge-patches annotations onto the Node named
// nodeName with the server's own client, or nil when there is no client or
// no Node name. Only the published keys move; every other annotation stays.
func nodeAnnotationPublisher(cs kubernetes.Interface, nodeName string) func(context.Context, map[string]string) error {
	if cs == nil || nodeName == "" {
		return nil
	}
	return func(ctx context.Context, annotations map[string]string) error {
		body, err := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": annotations}})
		if err != nil {
			return err
		}
		if _, err := cs.CoreV1().Nodes().Patch(ctx, nodeName, types.MergePatchType, body, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("annotate node %s: %w", nodeName, err)
		}
		return nil
	}
}

// write records rec, logging a failure (a work dir outside an install has no
// status directory, which is not one).
func (r updateRecorder) write(rec status.UpdateRecord) {
	if err := writeUpdateRecord(r.workDir, rec); err != nil && !errors.Is(err, errNoStatusDir) {
		r.logger.Warn("could not record the update check for `k3sm status`", "path", status.UpdatePath(r.workDir), "err", err)
	}
}

// readUpdateRecord is the record on disk, or an empty one when there is none
// or it does not parse (the next check rewrites it whole).
func readUpdateRecord(workDir string) status.UpdateRecord {
	var rec status.UpdateRecord
	if raw, err := os.ReadFile(status.UpdatePath(workDir)); err == nil {
		if json.Unmarshal(raw, &rec) != nil {
			rec = status.UpdateRecord{}
		}
	}
	return rec
}

// updateRollFrom is the roll the update row reports for u, observed at now:
// nil when there is no Update or it has finished. The node is the first one
// that has started and not ended. A field the record would refuse (a tag or a
// phase of an unexpected shape) is left out rather than invalidating the
// record; an unusable tag means no roll, since the controller fails it.
func updateRollFrom(u *updatesv1alpha1.Update, now time.Time) *status.UpdateRoll {
	if u == nil || updateFinished(u) || !version.ValidTag(u.Spec.Version) {
		return nil
	}
	word := func(s string) string {
		if status.UpdatePhaseWord(s) {
			return s
		}
		return ""
	}
	r := &status.UpdateRoll{ObservedAt: now.UTC().Truncate(time.Second), Version: u.Spec.Version, Phase: word(string(u.Status.Phase))}
	for _, n := range u.Status.Nodes {
		switch n.Phase {
		case "", updatesv1alpha1.UpdateNodePhasePending, updatesv1alpha1.UpdateNodePhaseDone,
			updatesv1alpha1.UpdateNodePhaseSkipped, updatesv1alpha1.UpdateNodePhaseCancelled:
			continue
		}
		if len(validation.IsDNS1123Subdomain(n.Name)) == 0 {
			r.Node, r.NodePhase = n.Name, word(string(n.Phase))
		}
		break
	}
	return r
}

// updateGVR is the Update resource the managed-update subcommands read and
// write through the dynamic client (apis publishes the types, not a clientset).
var updateGVR = schema.GroupVersionResource{
	Group: updatesv1alpha1.GroupName, Version: updatesv1alpha1.SchemeGroupVersion.Version, Resource: "updates",
}

// updateWatchEvery is how often `k3sm update status --watch` re-reads the
// Update by default.
const updateWatchEvery = 2 * time.Second

// updateAnnotationPrefix is the prefix of every Node annotation an update
// writes: the controller's handover (update-version, update-payload,
// update-payload-sig, update-signer), the
// node-side's report (update-phase) and the controller's own bookkeeping
// (update-cordoned, update-handed-over-at, update-ready-at), and a control
// plane's report of an admin token rotation (update-admin-token-rotated-at).
const updateAnnotationPrefix = "k3sm.io/update-"

// errNoUpdate is a cluster with no Update named current.
var errNoUpdate = fmt.Errorf("no Update named %q", updatesv1alpha1.UpdateName)

// updateClients returns the clients the managed-update subcommands need, or
// the error that says why none could be built.
func updateClients(env updateEnv) (kubernetes.Interface, dynamic.Interface, error) {
	if env.kubeErr != nil {
		return nil, nil, env.kubeErr
	}
	if env.inputs.Kube == nil || env.dyn == nil {
		return nil, nil, errors.New("no cluster client")
	}
	return env.inputs.Kube, env.dyn, nil
}

// getUpdate reads the singleton Update; nil with a nil error when there is none.
func getUpdate(ctx context.Context, dyn dynamic.Interface) (*updatesv1alpha1.Update, error) {
	obj, err := dyn.Resource(updateGVR).Get(ctx, updatesv1alpha1.UpdateName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the Update %s: %w", updatesv1alpha1.UpdateName, err)
	}
	u := &updatesv1alpha1.Update{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, u); err != nil {
		return nil, fmt.Errorf("decode the Update %s: %w", updatesv1alpha1.UpdateName, err)
	}
	return u, nil
}

// updateFinished reports whether u has reached an end state, by the same
// predicate the controller uses: the Progressing condition is False with the
// reason Succeeded, Failed or Cancelled. The phase is display only and is not
// read.
func updateFinished(u *updatesv1alpha1.Update) bool {
	p := meta.FindStatusCondition(u.Status.Conditions, updatectl.ConditionProgressing)
	if p == nil || p.Status != metav1.ConditionFalse {
		return false
	}
	switch p.Reason {
	case updatectl.ReasonSucceeded, updatectl.ReasonFailed, updatectl.ReasonCancelled:
		return true
	}
	return false
}

// updateEndedAs reports whether u is finished with the Progressing reason
// reason (updatectl.ReasonSucceeded, ReasonFailed or ReasonCancelled).
func updateEndedAs(u *updatesv1alpha1.Update, reason string) bool {
	p := meta.FindStatusCondition(u.Status.Conditions, updatectl.ConditionProgressing)
	return updateFinished(u) && p.Reason == reason
}

// updatePhase is u's phase for a message; an Update the controller has not
// reconciled yet has none.
func updatePhase(u *updatesv1alpha1.Update) string {
	if u.Status.Phase == "" {
		return "not yet reconciled"
	}
	return status.ClipText(string(u.Status.Phase), 64)
}

// controllerNode is the server the update controller runs on: the holder of
// its leader Lease, whose identity is the server's node name. Empty when the
// Lease cannot be read; the plan then says the order of the servers is not
// known.
func controllerNode(ctx context.Context, cs kubernetes.Interface) string {
	l, err := cs.CoordinationV1().Leases(updatectl.LeaseNamespace).Get(ctx, updatectl.LeaseName, metav1.GetOptions{})
	if err != nil || l.Spec.HolderIdentity == nil {
		return ""
	}
	return *l.Spec.HolderIdentity
}

// runUpdateApply is `k3sm update apply`: plan, confirm, create.
func runUpdateApply(ctx context.Context, args []string, env updateEnv) int {
	fsFlags := flag.NewFlagSet("update apply", flag.ContinueOnError)
	fsFlags.SetOutput(env.errOut)
	tag := fsFlags.String("version", "", "the release tag to move to (default: the latest release)")
	drain := fsFlags.Bool("drain", false, "evict each node's pods before updating it")
	allowDowngrade := fsFlags.Bool("allow-downgrade", false, "permit a release older than a node runs")
	signature := fsFlags.String("signature", string(updatesv1alpha1.UpdateSignatureIfSigned), "code-signature policy: if-signed or required")
	yes := fsFlags.Bool("yes", false, "do not ask for confirmation")
	pinSHA := fsFlags.String("pin-sha256", "", "bind the roll to this archive sha256 (root only; needs --version)")
	manifestSHA := fsFlags.String("manifest-sha256", "", "also bind the release's payload manifest to this sha256 (needs --pin-sha256)")
	clearPin := fsFlags.Bool("clear-pin", false, "remove the release pin and exit (root only)")
	if err := fsFlags.Parse(args); err != nil {
		return exitUsage
	}
	sig := updatesv1alpha1.UpdateSignaturePolicy(*signature)
	if fsFlags.NArg() > 0 || (sig != updatesv1alpha1.UpdateSignatureIfSigned && sig != updatesv1alpha1.UpdateSignatureRequired) {
		fmt.Fprint(env.errOut, updateUsage)
		return exitUsage
	}
	if *clearPin {
		return runUpdateClearPin(fsFlags, env)
	}
	pinning, manifestPinning := false, false // the flag was given, even empty
	fsFlags.Visit(func(f *flag.Flag) {
		pinning = pinning || f.Name == "pin-sha256"
		manifestPinning = manifestPinning || f.Name == "manifest-sha256"
	})
	if manifestPinning && !pinning {
		fmt.Fprintln(env.errOut, "k3sm update apply: --manifest-sha256 extends the release pin; pass --pin-sha256 too")
		return exitUsage
	}
	if pinning {
		if !env.root {
			fmt.Fprintln(env.errOut, "k3sm update apply: --pin-sha256 writes the server's release pin and must run as root")
			return exitInternalError
		}
		if *tag == "" {
			fmt.Fprintln(env.errOut, "k3sm update apply: --pin-sha256 binds one release; name it with --version")
			return exitUsage
		}
		if err := (updatectl.ReleasePin{Version: *tag, SHA256: *pinSHA}).Validate(); err != nil {
			fmt.Fprintln(env.errOut, "k3sm update apply: --pin-sha256:", err)
			return exitUsage
		}
		if manifestPinning {
			// Validate accepts an empty manifest digest (an archive-only pin),
			// so a given-but-empty flag is refused here.
			err := (updatectl.ReleasePin{Version: *tag, SHA256: *pinSHA, ManifestSHA256: *manifestSHA}).Validate()
			if err == nil && *manifestSHA == "" {
				err = errors.New("the pinned manifest sha256 is not 64 lowercase hex digits")
			}
			if err != nil {
				fmt.Fprintln(env.errOut, "k3sm update apply: --manifest-sha256:", err)
				return exitUsage
			}
		}
		if env.workDir == "" {
			fmt.Fprintln(env.errOut, "k3sm update apply: no server work dir to write the release pin in")
			return exitInternalError
		}
	}
	if *tag != "" && !version.ValidTag(*tag) {
		fmt.Fprintf(env.errOut, "k3sm update apply: --version %q is not a release tag\n", status.ClipText(*tag, 128))
		return exitUsage
	}
	if !*yes && !env.inTerminal {
		fmt.Fprintln(env.errOut, "k3sm update apply: refusing to start an update without confirmation: stdin is not a terminal; pass --yes")
		return exitUsage
	}
	cs, dyn, err := updateClients(env)
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update apply: cannot reach the cluster:", err)
		return exitInternalError
	}
	existing, err := getUpdate(ctx, dyn)
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update apply:", err)
		return exitInternalError
	}
	if existing != nil && !updateFinished(existing) {
		fmt.Fprintf(env.errOut, "k3sm update apply: the Update %s to %s is %s; follow it with `k3sm update status --watch`, or stop it with `k3sm update cancel`\n",
			updatesv1alpha1.UpdateName, status.ClipText(existing.Spec.Version, 128), updatePhase(existing))
		return exitInternalError
	}
	target := *tag
	if target == "" {
		rel, err := update.Latest(ctx, env.inputs)
		if err != nil {
			fmt.Fprintln(env.errOut, "k3sm update apply: resolve the latest release:", err)
			return exitInternalError
		}
		target = rel.Tag
	}
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update apply: list nodes:", err)
		return exitInternalError
	}
	plan := update.NewPlan(target, nodes.Items, controllerNode(ctx, cs), *drain, string(sig), *allowDowngrade)
	plan.Render(env.out)
	if !*yes {
		fmt.Fprintf(env.out, "\nStart the update to %s? [y/N] ", status.ClipText(target, 128))
		line, _ := bufio.NewReader(env.in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Fprintln(env.out, "Not started.")
			return exitInternalError
		}
	}
	if pinning {
		// Before the Update exists, so the controller's first resolve already
		// sees the pin. No Update is in progress (refused above), so no roll
		// has resolved its release yet.
		write := env.writePin
		if write == nil {
			write = updatectl.WriteReleasePin
		}
		pin := updatectl.ReleasePin{Version: target, SHA256: *pinSHA, ManifestSHA256: *manifestSHA, At: time.Now().UTC().Truncate(time.Second)}
		if err := write(env.workDir, pin); err != nil {
			fmt.Fprintln(env.errOut, "k3sm update apply:", err)
			return exitInternalError
		}
		fmt.Fprintf(env.out, "Pinned %s to sha256:%s.\n", status.ClipText(target, 128), *pinSHA)
		if *manifestSHA != "" {
			fmt.Fprintf(env.out, "Pinned the payload manifest of %s to sha256:%s.\n", status.ClipText(target, 128), *manifestSHA)
		}
	}
	if existing != nil {
		uid := existing.UID
		err := dyn.Resource(updateGVR).Delete(ctx, updatesv1alpha1.UpdateName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		if err != nil && !apierrors.IsNotFound(err) {
			fmt.Fprintf(env.errOut, "k3sm update apply: remove the finished Update %s: %v\n", updatesv1alpha1.UpdateName, err)
			return exitInternalError
		}
		fmt.Fprintf(env.out, "Removed the finished Update %s to %s (%s).\n", updatesv1alpha1.UpdateName, status.ClipText(existing.Spec.Version, 128), updatePhase(existing))
	}
	obj, err := newUpdateObject(updatesv1alpha1.UpdateSpec{
		Version:        target,
		Strategy:       updatesv1alpha1.UpdateStrategy{Drain: *drain},
		Verify:         updatesv1alpha1.UpdateVerify{Signature: sig},
		AllowDowngrade: *allowDowngrade,
	})
	if err == nil && pinning {
		// The controller refuses this Update unless a trusted pin for target
		// matches, so a pin lost before it resolves fails the roll closed.
		obj.SetAnnotations(map[string]string{updatectl.ReleasePinRequiredAnnotation: target})
	}
	if err == nil {
		_, err = dyn.Resource(updateGVR).Create(ctx, obj, metav1.CreateOptions{})
	}
	if err != nil {
		fmt.Fprintf(env.errOut, "k3sm update apply: create the Update %s: %v\n", updatesv1alpha1.UpdateName, err)
		return exitInternalError
	}
	fmt.Fprintf(env.out, "Created the Update %s to %s. Follow it with `k3sm update status --watch`.\n", updatesv1alpha1.UpdateName, status.ClipText(target, 128))
	return 0
}

// runUpdateClearPin is `k3sm update apply --clear-pin`: remove the release pin
// and exit. It takes no other apply flag and reaches no cluster.
func runUpdateClearPin(fsFlags *flag.FlagSet, env updateEnv) int {
	other := ""
	fsFlags.Visit(func(f *flag.Flag) {
		if f.Name != "clear-pin" && f.Name != "yes" {
			other = f.Name
		}
	})
	if other != "" {
		fmt.Fprintf(env.errOut, "k3sm update apply: --clear-pin takes no other flag (got --%s)\n", other)
		return exitUsage
	}
	if !env.root {
		fmt.Fprintln(env.errOut, "k3sm update apply: --clear-pin removes the server's release pin and must run as root")
		return exitInternalError
	}
	if env.workDir == "" {
		fmt.Fprintln(env.errOut, "k3sm update apply: no server work dir to remove the release pin from")
		return exitInternalError
	}
	remove := env.clearPin
	if remove == nil {
		remove = updatectl.ClearReleasePin
	}
	cleared, err := remove(env.workDir)
	var contested *updatectl.PinDirContestedError
	if errors.As(err, &contested) {
		fmt.Fprintf(env.errOut, "k3sm update apply: %s was replaced again after each of %d attempts to move it aside.\n", contested.Dir, contested.Attempts)
		for _, a := range contested.Asides {
			fmt.Fprintln(env.errOut, "  moved aside:", a)
		}
		fmt.Fprintf(env.errOut, "Stop the server, clear the pin again, then start the server:\n  %s\n", updatectl.PinClearRecovery)
		return exitInternalError
	}
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update apply:", err)
		return exitInternalError
	}
	switch {
	case cleared.Path == "":
		fmt.Fprintln(env.out, "There is no release pin.")
	case cleared.Untrusted != "":
		fmt.Fprintf(env.out, "Moved %s aside to %s: it could not be trusted (%s). Created a fresh %s; nothing is pinned.\n",
			cleared.Path, strings.Join(cleared.Asides, ", "), cleared.Untrusted, cleared.Path)
		fmt.Fprintln(env.out, "The aside entries stay in the work dir; they belong to the service user, which may remove them.")
	default:
		fmt.Fprintf(env.out, "Removed the release pin %s.\n", cleared.Path)
	}
	return 0
}

// newUpdateObject is the singleton Update with spec, as the dynamic client
// sends it. It carries no status: the controller writes that.
func newUpdateObject(spec updatesv1alpha1.UpdateSpec) (*unstructured.Unstructured, error) {
	u := &updatesv1alpha1.Update{
		TypeMeta:   metav1.TypeMeta{APIVersion: updatesv1alpha1.SchemeGroupVersion.String(), Kind: "Update"},
		ObjectMeta: metav1.ObjectMeta{Name: updatesv1alpha1.UpdateName},
		Spec:       spec,
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(u)
	if err != nil {
		return nil, err
	}
	delete(obj, "status")
	return &unstructured.Unstructured{Object: obj}, nil
}

// updateStatusView is `k3sm update status -o json`. With no Update named
// current it is exactly {"phase":"","version":"","resolved":null,"nodes":[],
// "conditions":[]}: every other key is omitted, and a present Update always
// has a version.
type updateStatusView struct {
	// Present is whether the cluster has an Update named current; it is not
	// encoded (Version says it).
	Present bool `json:"-"`
	// Phase is the controller's display phase; empty before it reconciles.
	Phase   string `json:"phase"`
	Version string `json:"version"`
	// Resolved is the verified release; null until verification passed.
	Resolved   *updatesv1alpha1.UpdateResolved `json:"resolved"`
	Nodes      []updateStatusNode              `json:"nodes"`
	Conditions []metav1.Condition              `json:"conditions"`
	Name       string                          `json:"name,omitempty"`
	// Finished is the controller's end-state predicate over the conditions.
	Finished       bool   `json:"finished,omitempty"`
	Cancel         bool   `json:"cancel,omitempty"`
	Drain          bool   `json:"drain,omitempty"`
	Signature      string `json:"signature,omitempty"`
	AllowDowngrade bool   `json:"allowDowngrade,omitempty"`
	// Generation and ObservedGeneration say whether the status describes the
	// current spec (a cancel not yet seen trails).
	Generation         int64 `json:"generation,omitempty"`
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// updateStatusNode is one node of updateStatusView.
type updateStatusNode struct {
	Name  string `json:"name"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	Phase string `json:"phase,omitempty"`
	// Message is the node's message without its last-progress time, which is
	// LastProgress (RFC 3339; empty when the message carries none).
	Message      string `json:"message,omitempty"`
	LastProgress string `json:"lastProgress,omitempty"`
	// AdminTokenRotated is set when the node's in-place install minted a new
	// admin token: every admin kubeconfig copied from it before is refused.
	AdminTokenRotated bool `json:"adminTokenRotated,omitempty"`
}

// adminTokenRotatedRemedy is the line the text form prints under a node whose
// AdminTokenRotated is set.
const adminTokenRotatedRemedy = "admin credential re-minted: copy the admin kubeconfig (`k3sm kubeconfig` on the server) again to every other Mac and tool that uses it"

// updateProgressMark separates a node message from its last-progress time,
// as the controller writes it ("<message>; last progress <RFC3339>").
const updateProgressMark = "; last progress "

// splitUpdateProgress splits a node message into its text and its
// last-progress time.
func splitUpdateProgress(msg string) (base, at string) {
	if rest, ok := strings.CutPrefix(msg, "last progress "); ok {
		return "", rest
	}
	if i := strings.LastIndex(msg, updateProgressMark); i >= 0 {
		return msg[:i], msg[i+len(updateProgressMark):]
	}
	return msg, ""
}

// newUpdateStatusView is the view of u (nil: no Update). Node names, versions
// and messages carry what nodes say of themselves, so every string is
// control-stripped.
func newUpdateStatusView(u *updatesv1alpha1.Update) updateStatusView {
	v := updateStatusView{Nodes: []updateStatusNode{}, Conditions: []metav1.Condition{}}
	if u == nil {
		return v
	}
	v.Name = updatesv1alpha1.UpdateName
	clip := func(s string) string { return status.ClipText(s, 1024) }
	v.Present = true
	v.Version = clip(u.Spec.Version)
	v.Phase = clip(string(u.Status.Phase))
	v.Finished = updateFinished(u)
	v.Cancel = u.Spec.Cancel
	v.Drain = u.Spec.Strategy.Drain
	v.Signature = clip(string(u.Spec.Verify.Signature))
	v.AllowDowngrade = u.Spec.AllowDowngrade
	if r := u.Status.Resolved; r != nil {
		v.Resolved = &updatesv1alpha1.UpdateResolved{Version: clip(r.Version), Digest: clip(r.Digest)}
	}
	for _, n := range u.Status.Nodes {
		base, at := splitUpdateProgress(n.Message)
		v.Nodes = append(v.Nodes, updateStatusNode{
			Name: clip(n.Name), From: clip(n.From), To: clip(n.To), Phase: clip(string(n.Phase)),
			Message: clip(base), LastProgress: clip(at), AdminTokenRotated: n.AdminTokenRotated,
		})
	}
	for _, c := range u.Status.Conditions {
		c.Type, c.Reason, c.Message = clip(c.Type), clip(c.Reason), clip(c.Message)
		v.Conditions = append(v.Conditions, c)
	}
	v.Generation, v.ObservedGeneration = u.Generation, u.Status.ObservedGeneration
	return v
}

// renderUpdateStatus prints v for a person.
func renderUpdateStatus(w io.Writer, v updateStatusView) {
	if !v.Present {
		fmt.Fprintf(w, "no managed update (the cluster has no Update named %q; start one with `k3sm update apply`)\n", updatesv1alpha1.UpdateName)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	phase := v.Phase
	if phase == "" {
		phase = "not yet reconciled"
	}
	if v.Cancel && !v.Finished {
		phase += " (cancel requested)"
	}
	fmt.Fprintf(tw, "update\t%s to %s\n", v.Name, v.Version)
	fmt.Fprintf(tw, "phase\t%s\n", phase)
	if v.Resolved != nil {
		fmt.Fprintf(tw, "resolved\t%s %s\n", v.Resolved.Version, v.Resolved.Digest)
	}
	fmt.Fprintf(tw, "drain\t%s\n", map[bool]string{true: "yes", false: "no"}[v.Drain])
	if v.Signature != "" {
		fmt.Fprintf(tw, "signature\t%s\n", v.Signature)
	}
	if len(v.Nodes) > 0 {
		fmt.Fprintf(tw, "\nNODE\tFROM\tTO\tPHASE\tLAST PROGRESS\tMESSAGE\n")
		for _, n := range v.Nodes {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", n.Name, n.From, n.To, n.Phase, n.LastProgress, n.Message)
			if n.AdminTokenRotated {
				// Under the node's MESSAGE, so the table's columns stay aligned.
				fmt.Fprintf(tw, "\t\t\t\t\t%s\n", adminTokenRotatedRemedy)
			}
		}
	}
	if len(v.Conditions) > 0 {
		fmt.Fprintf(tw, "\nCONDITION\tSTATUS\tREASON\tMESSAGE\n")
		for _, c := range v.Conditions {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.Type, c.Status, c.Reason, c.Message)
		}
	}
	_ = tw.Flush()
}

// runUpdateStatus is `k3sm update status`.
func runUpdateStatus(ctx context.Context, args []string, env updateEnv) int {
	fsFlags := flag.NewFlagSet("update status", flag.ContinueOnError)
	fsFlags.SetOutput(env.errOut)
	format := fsFlags.String("o", "text", "output format: text or json")
	watch := fsFlags.Bool("watch", false, "re-print on every change until the update finishes")
	if err := fsFlags.Parse(args); err != nil {
		return exitUsage
	}
	if fsFlags.NArg() > 0 || (*format != "text" && *format != "json") {
		fmt.Fprint(env.errOut, updateUsage)
		return exitUsage
	}
	_, dyn, err := updateClients(env)
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update status: cannot reach the cluster:", err)
		return exitInternalError
	}
	every := env.watchEvery
	if every <= 0 {
		every = updateWatchEvery
	}
	var last string
	for first := true; ; first = false {
		u, err := getUpdate(ctx, dyn)
		if err != nil {
			fmt.Fprintln(env.errOut, "k3sm update status:", err)
			return exitInternalError
		}
		v := newUpdateStatusView(u)
		var b strings.Builder
		if *format == "json" {
			enc := json.NewEncoder(&b)
			enc.SetIndent("", "  ")
			if err := enc.Encode(v); err != nil {
				fmt.Fprintln(env.errOut, "k3sm update status:", err)
				return exitInternalError
			}
		} else {
			renderUpdateStatus(&b, v)
		}
		if b.String() != last {
			if !first && *format == "text" {
				fmt.Fprintln(env.out)
			}
			fmt.Fprint(env.out, b.String())
			last = b.String()
		}
		if !*watch || !v.Present || v.Finished {
			return 0
		}
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
			t.Stop()
			return 0
		case <-t.C:
		}
	}
}

// runUpdateCancel is `k3sm update cancel`: set spec.cancel.
func runUpdateCancel(ctx context.Context, args []string, env updateEnv) int {
	if len(args) > 0 {
		fmt.Fprint(env.errOut, updateUsage)
		return exitUsage
	}
	_, dyn, err := updateClients(env)
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update cancel: cannot reach the cluster:", err)
		return exitInternalError
	}
	u, err := getUpdate(ctx, dyn)
	if err == nil && u == nil {
		err = errNoUpdate
	}
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update cancel:", err)
		return exitInternalError
	}
	if updateFinished(u) {
		fmt.Fprintf(env.out, "The Update %s to %s is already %s; there is nothing to cancel.\n", updatesv1alpha1.UpdateName, status.ClipText(u.Spec.Version, 128), updatePhase(u))
		return 0
	}
	patch := []byte(`{"spec":{"cancel":true}}`)
	if _, err := dyn.Resource(updateGVR).Patch(ctx, updatesv1alpha1.UpdateName, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		fmt.Fprintf(env.errOut, "k3sm update cancel: set spec.cancel on the Update %s: %v\n", updatesv1alpha1.UpdateName, err)
		return exitInternalError
	}
	fmt.Fprintf(env.out, "Cancel requested for the Update %s to %s. The node being updated finishes its update; the nodes not yet started are left on the release they run, and the Update ends Cancelled. A cancel is not a rollback: nodes already moved stay on %s.\n",
		updatesv1alpha1.UpdateName, status.ClipText(u.Spec.Version, 128), status.ClipText(u.Spec.Version, 128))
	return 0
}

// runUpdateAbort is `k3sm update abort`, the recovery after a failed step. It
// ends the Update first, so the controller stops acting on it, then releases
// every node: the k3sm.io/update-* annotations go, and a cordon is lifted only
// where the controller's update-cordoned annotation says the controller made
// it.
func runUpdateAbort(ctx context.Context, args []string, env updateEnv) int {
	if len(args) > 0 {
		fmt.Fprint(env.errOut, updateUsage)
		return exitUsage
	}
	cs, dyn, err := updateClients(env)
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update abort: cannot reach the cluster:", err)
		return exitInternalError
	}
	u, err := getUpdate(ctx, dyn)
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update abort:", err)
		return exitInternalError
	}
	// The nodes are read before the Update is ended, so a control plane's
	// admin token rotation is recorded on the aborted Update before its
	// annotation is cleared below.
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update abort: list nodes:", err)
		return exitInternalError
	}
	switch {
	case u == nil:
		fmt.Fprintf(env.out, "No Update named %q; releasing the nodes only.\n", updatesv1alpha1.UpdateName)
	case updateEndedAs(u, updatectl.ReasonSucceeded) || updateEndedAs(u, updatectl.ReasonCancelled):
		fmt.Fprintf(env.out, "The Update %s to %s is already %s; left as it is.\n", updatesv1alpha1.UpdateName, status.ClipText(u.Spec.Version, 128), updatePhase(u))
	default:
		was := updatePhase(u)
		now := time.Now
		if env.inputs.Now != nil {
			now = env.inputs.Now
		}
		updatectl.NoteAdminTokenRotations(u, nodes.Items, slog.New(slog.NewTextHandler(env.errOut, &slog.HandlerOptions{Level: slog.LevelWarn})))
		abortUpdateStatus(u, now().UTC().Truncate(time.Second))
		if err := writeUpdateStatus(ctx, dyn, u); err != nil {
			fmt.Fprintln(env.errOut, "k3sm update abort:", err)
			return exitInternalError
		}
		fmt.Fprintf(env.out, "Marked the Update %s to %s Cancelled (it was %s).\n", updatesv1alpha1.UpdateName, status.ClipText(u.Spec.Version, 128), was)
		for _, e := range u.Status.Nodes {
			if e.AdminTokenRotated {
				fmt.Fprintf(env.out, "Node %s: %s.\n", status.ClipText(e.Name, 253), adminTokenRotatedRemedy)
			}
		}
	}
	failed := false
	released := 0
	for _, n := range nodes.Items {
		drop := map[string]any{}
		for k := range n.Annotations {
			if strings.HasPrefix(k, updateAnnotationPrefix) {
				drop[k] = nil
			}
		}
		if len(drop) == 0 {
			continue
		}
		patch := map[string]any{"metadata": map[string]any{"annotations": drop}}
		uncordon := n.Annotations[updatectl.CordonedAnnotation] == "true" && n.Spec.Unschedulable
		if uncordon {
			patch["spec"] = map[string]any{"unschedulable": false}
		}
		b, err := json.Marshal(patch)
		if err == nil {
			_, err = cs.CoreV1().Nodes().Patch(ctx, n.Name, types.MergePatchType, b, metav1.PatchOptions{})
		}
		name := status.ClipText(n.Name, 253)
		if err != nil {
			fmt.Fprintf(env.errOut, "k3sm update abort: release node %s: %v\n", name, err)
			failed = true
			continue
		}
		released++
		keys := make([]string, 0, len(drop))
		for k := range drop {
			keys = append(keys, status.ClipText(k, 253))
		}
		sort.Strings(keys)
		fmt.Fprintf(env.out, "Node %s: cleared %s.\n", name, strings.Join(keys, ", "))
		switch {
		case uncordon:
			fmt.Fprintf(env.out, "Node %s: uncordoned (the update controller had cordoned it).\n", name)
		case n.Spec.Unschedulable:
			fmt.Fprintf(env.out, "Node %s: left cordoned (the cordon is not the update controller's).\n", name)
		}
	}
	if released == 0 && !failed {
		fmt.Fprintln(env.out, "No node carries an update annotation.")
	}
	if failed {
		return exitInternalError
	}
	return 0
}

// abortUpdateStatus ends u Cancelled the way the controller's own cancel
// does, so the controller treats it as finished: every node not yet finished
// is Cancelled, and the Progressing and Succeeded conditions are False with
// the reason Cancelled. A Failed condition already True stays, so the failure
// that led to the abort is still on record.
func abortUpdateStatus(u *updatesv1alpha1.Update, now time.Time) {
	at := now.Format(time.RFC3339)
	for i := range u.Status.Nodes {
		e := &u.Status.Nodes[i]
		switch e.Phase {
		case updatesv1alpha1.UpdateNodePhaseDone, updatesv1alpha1.UpdateNodePhaseSkipped,
			updatesv1alpha1.UpdateNodePhaseFailed, updatesv1alpha1.UpdateNodePhaseCancelled:
			continue
		}
		e.Phase = updatesv1alpha1.UpdateNodePhaseCancelled
		msg := "aborted by k3sm update abort"
		if e.AdminTokenRotated {
			msg += "; " + updatectl.AdminTokenRotatedMessage
		}
		e.Message = msg + updateProgressMark + at
	}
	msg := "k3sm update abort ended the roll"
	set := func(typ string, st metav1.ConditionStatus) {
		meta.SetStatusCondition(&u.Status.Conditions, metav1.Condition{
			Type: typ, Status: st, Reason: updatectl.ReasonCancelled, Message: msg,
			ObservedGeneration: u.Generation, LastTransitionTime: metav1.NewTime(now),
		})
	}
	u.Status.Phase = updatesv1alpha1.UpdatePhaseCancelled
	u.Status.ObservedGeneration = u.Generation
	set(updatectl.ConditionProgressing, metav1.ConditionFalse)
	set(updatectl.ConditionSucceeded, metav1.ConditionFalse)
	if !meta.IsStatusConditionTrue(u.Status.Conditions, updatectl.ConditionFailed) {
		set(updatectl.ConditionFailed, metav1.ConditionFalse)
	}
}

// writeUpdateStatus writes u's status through the status subresource. The
// resourceVersion u was read at rides along, so a status the controller wrote
// in between is a conflict, not overwritten.
func writeUpdateStatus(ctx context.Context, dyn dynamic.Interface, u *updatesv1alpha1.Update) error {
	u.APIVersion = updatesv1alpha1.SchemeGroupVersion.String()
	u.Kind = "Update"
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(u)
	if err != nil {
		return fmt.Errorf("encode the Update %s: %w", u.Name, err)
	}
	if _, err := dyn.Resource(updateGVR).UpdateStatus(ctx, &unstructured.Unstructured{Object: obj}, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("write the Update %s status: %w", u.Name, err)
	}
	return nil
}
