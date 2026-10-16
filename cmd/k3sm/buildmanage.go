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
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k3sm.io/k3sm/pkg/builder"
	"k3sm.io/k3sm/pkg/buildledger"
)

const buildCancelUsage = `Usage: k3sm build cancel <id>

Stop a running build. The build's own process interrupts buildx, which cancels
the job in the build engine, and records the build as cancelled. A finished
build is refused. A build whose process is already gone (killed before it could
record its outcome) is marked cancelled.
`

const buildRmUsage = `Usage: k3sm build rm <id>

Remove a build from your build history, with its stored log. A running build is
refused: cancel it first with "k3sm build cancel <id>".
`

const buildLogsUsage = `Usage: k3sm build logs [-f] <id>

Print a build's stored log: what the build printed, its progress included.

  -f, --follow   keep printing while the build runs, and return when it finishes
`

const buildPruneUsage = `Usage: k3sm build prune [--all] [--force] [--work-dir <dir>]

Reclaim the build engine's cache. DRY RUN BY DEFAULT: it prints what a prune
would reclaim; pass --force to prune. The engine must be running ("k3sm builder
up"). Cache a running build holds is never removed.

  --all     also remove the engine's internal and frontend records and the
            cache shared with images it built, so the next build starts colder
  --force   prune, and print the bytes reclaimed
`

// cancelRequestTimeout bounds how long `build cancel` waits for the build to
// stop and record itself: buildx's interrupt grace, plus room for the record.
const cancelRequestTimeout = 45 * time.Second

// cancelRetries and cancelRetryDelay cover the moment between a build writing
// its running record and opening its cancel socket.
const (
	cancelRetries    = 3
	cancelRetryDelay = 300 * time.Millisecond
)

// followInterval is how often `build logs -f` looks for new output.
const followInterval = 250 * time.Millisecond

// runBuildManage dispatches the history verbs: cancel, rm, logs, prune.
func runBuildManage(verb string, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch verb {
	case "prune":
		return runBuildPrune(ctx, args, os.Stdout)
	}
	usage := map[string]string{"cancel": buildCancelUsage, "rm": buildRmUsage, "logs": buildLogsUsage}[verb]
	fs := flag.NewFlagSet("build "+verb, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	var follow bool
	if verb == "logs" {
		fs.BoolVar(&follow, "f", false, "follow the log while the build runs")
		fs.BoolVar(&follow, "follow", false, "follow the log while the build runs")
	}
	id, err := parseOneID(fs, args)
	if err != nil {
		return err
	}
	dir, err := buildledger.DefaultDir()
	if err != nil {
		return err
	}
	l := buildledger.New(dir)
	switch verb {
	case "cancel":
		return cancelBuild(ctx, os.Stdout, l, id, builder.RequestCancel)
	case "rm":
		return removeBuild(os.Stdout, l, id)
	default:
		return showBuildLog(ctx, os.Stdout, os.Stderr, l, id, follow, followInterval, builder.BuildAlive)
	}
}

// parseOneID parses fs over args, accepting flags before or after the id, and
// returns the one id.
func parseOneID(fs *flag.FlagSet, args []string) (string, error) {
	var ids []string
	for {
		if err := fs.Parse(args); err != nil {
			return "", err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		ids = append(ids, args[0])
		args = args[1:]
	}
	if len(ids) != 1 {
		return "", fmt.Errorf("%s takes exactly one build id (see `k3sm build ls`), got %d", fs.Name(), len(ids))
	}
	return ids[0], nil
}

// cancelBuild stops build id through request and reports what happened.
func cancelBuild(ctx context.Context, w io.Writer, l *buildledger.Ledger, id string, request func(context.Context, string) error) error {
	r, err := l.Get(id)
	if err != nil {
		return err
	}
	if r.Status != buildledger.StatusRunning {
		return fmt.Errorf("build %s already finished (%s); there is nothing to cancel", id, r.Status)
	}
	rctx, cancel := context.WithTimeout(ctx, cancelRequestTimeout)
	defer cancel()
	for attempt := 1; ; attempt++ {
		err = request(rctx, l.CancelPath(id))
		if !errors.Is(err, builder.ErrNoBuildProcess) || attempt == cancelRetries {
			break
		}
		select {
		case <-rctx.Done():
			return fmt.Errorf("cancel build %s: %w", id, rctx.Err())
		case <-time.After(cancelRetryDelay):
		}
	}
	switch {
	case errors.Is(err, builder.ErrNoBuildProcess):
		// Nothing holds the build. Either it finished meanwhile, or it was
		// killed and left its record running.
		if now, gerr := l.Get(id); gerr == nil && now.Status != buildledger.StatusRunning {
			return fmt.Errorf("build %s finished (%s) before the cancel reached it", id, now.Status)
		}
		if _, err := l.Cancel(r); err != nil {
			return err
		}
		fmt.Fprintf(w, "build %s had no running process (it exited without recording its outcome); marked cancelled\n", id)
		return nil
	case err != nil:
		return fmt.Errorf("cancel build %s: %w", id, err)
	}
	now, err := l.Get(id)
	if err != nil {
		return err
	}
	if now.Status != buildledger.StatusCancelled {
		return fmt.Errorf("build %s finished (%s) before the cancel took effect", id, now.Status)
	}
	fmt.Fprintf(w, "cancelled build %s\n", id)
	return nil
}

// removeBuild drops build id and its log from the history.
func removeBuild(w io.Writer, l *buildledger.Ledger, id string) error {
	r, err := l.Get(id)
	if err != nil {
		return err
	}
	if r.Status == buildledger.StatusRunning {
		return fmt.Errorf("build %s is running; cancel it first with `k3sm build cancel %s`", id, id)
	}
	if err := l.Remove(id); err != nil {
		return err
	}
	fmt.Fprintf(w, "removed build %s\n", id)
	return nil
}

// showBuildLog prints build id's stored log to w. With follow, it keeps
// printing while the record is running and returns once it finishes, or once
// no build process holds it any more (alive reports that).
func showBuildLog(ctx context.Context, w, errOut io.Writer, l *buildledger.Ledger, id string, follow bool, interval time.Duration, alive func(context.Context, string) bool) error {
	if _, err := l.Get(id); err != nil {
		return err
	}
	f, err := l.OpenLog(id)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(w, f); err != nil {
		return fmt.Errorf("read the log of build %s: %w", id, err)
	}
	if !follow {
		return nil
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		r, err := l.Get(id)
		if err != nil {
			return err
		}
		if r.Status != buildledger.StatusRunning {
			_, err := io.Copy(w, f)
			return err
		}
		if !alive(ctx, l.CancelPath(id)) {
			// The record may have been finished between the two reads.
			if r, err := l.Get(id); err == nil && r.Status != buildledger.StatusRunning {
				_, err := io.Copy(w, f)
				return err
			}
			_, err := io.Copy(w, f)
			fmt.Fprintf(errOut, "build %s has no running process; its record was left running (`k3sm build cancel %s` marks it cancelled)\n", id, id)
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if _, err := io.Copy(w, f); err != nil {
			return fmt.Errorf("read the log of build %s: %w", id, err)
		}
	}
}

// cachePruner is the engine seam `build prune` drives.
type cachePruner interface {
	PlanPrune(ctx context.Context, all bool) (builder.CacheReport, error)
	PruneCache(ctx context.Context, all bool) (builder.CacheReport, error)
}

// runBuildPrune parses the flags and prunes the engine's cache.
func runBuildPrune(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("build prune", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, buildPruneUsage) }
	all := fs.Bool("all", false, "also remove internal, frontend and shared cache records")
	force := fs.Bool("force", false, "prune (without this, only report what would be reclaimed)")
	workDir := fs.String("work-dir", "", "control-plane work dir whose admin kubeconfig is used verbatim (default: K3SM_WORK_DIR, else the posture default with a fallback to your own kubeconfig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("build prune takes no positional arguments (got %q)", fs.Arg(0))
	}
	dir, explicit := builderWorkDir(*workDir)
	mgr, err := newBuilderManager(builderOptions{workDir: dir, workDirExplicit: explicit})
	if err != nil {
		return err
	}
	return pruneBuildCache(ctx, w, mgr, *all, *force)
}

// pruneBuildCache reports, or with force performs, a prune of the engine cache.
func pruneBuildCache(ctx context.Context, w io.Writer, p cachePruner, all, force bool) error {
	if !force {
		rep, err := p.PlanPrune(ctx, all)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "would reclaim %s (%d bytes) from %d cache record(s)\n", humanBytes(uint64(rep.Bytes)), rep.Bytes, rep.Records)
		fmt.Fprintln(w, "(dry run; pass --force to prune)")
		return nil
	}
	rep, err := p.PruneCache(ctx, all)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "reclaimed %s (%d bytes) from %d cache record(s)\n", humanBytes(uint64(rep.Bytes)), rep.Bytes, rep.Records)
	return nil
}
