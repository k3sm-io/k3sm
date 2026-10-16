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
	"io/fs"
	"log/slog"
	"os"
	"syscall"
	"text/tabwriter"
	"time"

	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/update"
	"k3sm.io/k3sm/pkg/version"
)

// updateUsage is `k3sm update --help`.
const updateUsage = `k3sm update — check for a newer k3sm release

Usage: k3sm update check [-o text|json]

  check   resolve the latest release the way install.sh does, and compare this
          Mac's k3sm and every node's with it; the result is also recorded
          for the update row of ` + "`k3sm status`" + ` (as root or the service user)

Flags:
  -o text|json   output format (default text)

Exit codes: 0 the check finished, 1 it could not (the error says why), 2 usage.
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
		inputs:  update.Inputs{BaseURL: update.DefaultBaseURL, Installed: version.Get()},
		workDir: workDir,
	}
	cs, err := statusNodeClient(statusKubeInputsFor(role, statusPaths(workDir)))
	if err != nil {
		env.kubeErr = err
	} else {
		env.inputs.Kube = cs
	}
	return env
}

// statusNodeClient is the clientset of the apiserver client `k3sm status`
// resolves (newStatusKube), so the check lists the Nodes of the cluster the
// report describes, over the same credentials.
func statusNodeClient(in statusKubeInputs) (kubernetes.Interface, error) {
	k, _, err := newStatusKube(in)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(restKube)
	if !ok {
		return nil, fmt.Errorf("the status client is a %T, not a clientset", k)
	}
	return rk.client, nil
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
			fmt.Fprintf(env.errOut, "k3sm update: not recorded for `k3sm status` (%v); run with sudo to record it\n", err)
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
	fmt.Fprintf(tw, "installed\t%s (%s)\n", rep.Installed, rep.InstalledState)
	if len(rep.Nodes) > 0 {
		fmt.Fprintf(tw, "\nNODE\tVERSION\tSTATE\n")
		// Node names and versions are what each node says of itself, so they
		// are control-stripped before they reach a terminal.
		for _, n := range rep.Nodes {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", status.ClipText(n.Name, 253), status.ClipText(n.Version, 128), n.State)
		}
	}
	_ = tw.Flush()
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

// runUpdateRecorder refreshes the update record for `k3sm status` at most once
// an interval until ctx ends. Every failure is logged and survivable: a check
// is a report, never a reason to stop a server, and a failed one is itself
// recorded so the row says why.
func runUpdateRecorder(ctx context.Context, workDir string, cs kubernetes.Interface, interval time.Duration, logger *slog.Logger) {
	wait := updateCheckDue(workDir, time.Now(), interval)
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		rep, err := update.Check(ctx, update.Inputs{BaseURL: update.DefaultBaseURL, Kube: cs, Installed: version.Get()})
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			logger.Info("could not check for a k3sm update", "err", err)
		}
		if err := writeUpdateRecord(workDir, rep.Record(err)); err != nil && !errors.Is(err, errNoStatusDir) {
			logger.Warn("could not record the update check for `k3sm status`", "path", status.UpdatePath(workDir), "err", err)
		}
		wait = interval
	}
}
