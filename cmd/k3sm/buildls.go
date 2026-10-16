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
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"

	"k3sm.io/k3sm/pkg/builder"
	"k3sm.io/k3sm/pkg/buildledger"
)

const buildLsUsage = `Usage: k3sm build ls [-o text|json]

List this user's builds, newest first: every "k3sm build" is recorded when it
starts and again when it finishes, and the newest 200 are kept.

  -o text   a table (the default)
  -o json   the records as a JSON array
`

// defaultBuildLedger is the invoking user's ledger, or nil when no home
// directory resolves; a nil ledger records nothing.
func defaultBuildLedger() *buildledger.Ledger {
	dir, err := buildledger.DefaultDir()
	if err != nil {
		slog.Warn("build ledger unavailable; this build is not recorded", "err", err)
		return nil
	}
	return buildledger.New(dir)
}

// buildRecord follows one build into the ledger. Every write failure is a
// warning: the ledger is a history of builds, and a build must not fail
// because its history could not be kept.
type buildRecord struct {
	ledger *buildledger.Ledger
	rec    buildledger.Record
	// started is whether the running record was written; a record that never
	// started is not finished either, so a ledger that failed once stays quiet.
	started bool
	// digest is the digest of the image the store recorded, captured by the
	// recorder wrapper on the path that ran.
	digest string
	// log is the build's stored log (`k3sm build logs`), or nil when it could
	// not be created.
	log *buildledger.LogWriter
}

// startBuildRecord writes the running record for o. The route starts as the
// native packager's, which reads the Dockerfile first, unless the platform
// already decides it; the engine wrapper rewrites it when the build routes there.
func startBuildRecord(l *buildledger.Ledger, o buildOptions) *buildRecord {
	tr := &buildRecord{ledger: l}
	if l == nil {
		return tr
	}
	r := buildledger.Record{
		Dockerfile: absOrSelf(o.dockerfile),
		Context:    absOrSelf(o.contextDir),
		Tag:        o.tag,
		Platform:   strings.Join(o.targets(), ","),
		Engine:     buildledger.EngineNative,
	}
	if enginePlatformRequested(o) {
		tr.routeToEngine(&r, o)
	}
	rec, err := l.Start(r)
	if err != nil {
		slog.Warn("build ledger: record the build's start", "err", err)
		return tr
	}
	tr.rec, tr.started = rec, true
	if tr.log, err = l.CreateLog(rec.ID); err != nil {
		slog.Warn("build ledger: this build's log is not kept", "id", rec.ID, "err", err)
	}
	return tr
}

// teeOutput is a build's output writer that also carries where the build's
// error stream goes, so the engine path can hand buildx's progress (stderr) to
// the same log its stdout reaches without widening the engineBuilder seam.
type teeOutput struct {
	io.Writer
	// stderr is the error stream copied into the log, for a stderr that is not
	// a terminal.
	stderr io.Writer
	// term is the process's stderr when it is a terminal, and log the log's
	// error-stream input: the engine runs buildx on a pseudo-terminal then, so
	// its interactive progress still draws, and copies it to both.
	term *os.File
	log  io.Writer
}

// processStderr is the process's own error stream; a seam for the tests.
var processStderr io.Writer = os.Stderr

// stderrOf is the error stream that belongs with out: the tee's when out is
// one, the process's otherwise.
func stderrOf(out io.Writer) io.Writer {
	if t, ok := out.(*teeOutput); ok {
		return t.stderr
	}
	return processStderr
}

// stderrTerminal is the process's stderr when it is a terminal, else nil. A
// seam so the tee's choice is testable without a terminal.
var stderrTerminal = func() *os.File {
	if builder.IsTerminal(os.Stderr) {
		return os.Stderr
	}
	return nil
}

// tee returns out, and the process's stderr, each copied into the build's
// log. Each stream reaches the log through its own PlainWriter, so the log
// holds text and not terminal control. Without a log, out is returned
// unchanged.
func (tr *buildRecord) tee(out io.Writer) io.Writer {
	if tr.log == nil {
		return out
	}
	errLog := buildledger.NewPlainWriter(tr.log)
	t := &teeOutput{
		Writer: io.MultiWriter(out, buildledger.NewPlainWriter(tr.log)),
		stderr: io.MultiWriter(stderrOf(out), errLog),
		log:    errLog,
	}
	if _, nested := out.(*teeOutput); !nested {
		t.term = stderrTerminal()
	}
	return t
}

// runEngineBuildx runs buildx for an engine build, its output going where out
// says: on a pseudo-terminal when the build's stderr is a terminal and the
// build is logged, so buildx draws its interactive progress, and with a plain
// copy to stderrOf(out) otherwise.
func runEngineBuildx(ctx context.Context, bin string, args, env []string, out io.Writer) error {
	if t, ok := out.(*teeOutput); ok && t.term != nil {
		return builder.RunBuildxPTY(ctx, bin, args, env, out, t.term, t.log)
	}
	return builder.RunBuildxTo(ctx, bin, args, env, out, stderrOf(out))
}

// run runs job, cancellable through `k3sm build cancel` when the build is
// recorded, and records the outcome.
func (tr *buildRecord) run(ctx context.Context, job func(context.Context) error) error {
	if tr.log != nil {
		defer func() {
			if err := tr.log.Close(); err != nil {
				slog.Warn("build ledger: close the build's log", "id", tr.rec.ID, "err", err)
			}
		}()
	}
	if !tr.started {
		return job(ctx)
	}
	return builder.RunCancellable(ctx, tr.ledger.CancelPath(tr.rec.ID), job, tr.finish)
}

// routeToEngine marks r as an engine build, for the platform the engine builds.
func (tr *buildRecord) routeToEngine(r *buildledger.Record, o buildOptions) {
	r.Engine = buildledger.EngineBuildEngine
	if p, err := engineBuildPlatform(o); err == nil {
		r.Platform = p
	}
}

// engine wraps the engine seam so the record names the route the build took.
func (tr *buildRecord) engine(next engineBuilder) engineBuilder {
	return func(ctx context.Context, o buildOptions, out io.Writer) error {
		if tr.started && tr.rec.Engine != buildledger.EngineBuildEngine {
			tr.routeToEngine(&tr.rec, o)
			if err := tr.ledger.Write(tr.rec); err != nil {
				slog.Warn("build ledger: record the build's route", "id", tr.rec.ID, "err", err)
			}
		}
		return next(ctx, o, out)
	}
}

// recorder wraps the store seam to capture the digest of the image it records.
func (tr *buildRecord) recorder(next storeRecorder) storeRecorder {
	return func(ctx context.Context, ref name.Tag, img ggcrv1.Image) error {
		if err := next(ctx, ref, img); err != nil {
			return err
		}
		if d, err := img.Digest(); err == nil {
			tr.digest = d.String()
		}
		return nil
	}
}

// finish rewrites the record with the build's outcome: cancelled when a
// `k3sm build cancel` stopped it.
func (tr *buildRecord) finish(cancelled bool, buildErr error) {
	if !tr.started {
		return
	}
	var err error
	if cancelled {
		_, err = tr.ledger.Cancel(tr.rec)
	} else {
		_, err = tr.ledger.Finish(tr.rec, tr.digest, buildErr)
	}
	if err != nil {
		slog.Warn("build ledger: record the build's outcome", "id", tr.rec.ID, "err", err)
	}
}

// absOrSelf is p made absolute, or p itself when the working directory is gone.
func absOrSelf(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// runBuildLs parses the flags and lists the invoking user's ledger.
func runBuildLs(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("build ls", flag.ContinueOnError)
	format := fs.String("o", "text", "output format: text or json")
	fs.Usage = func() { fmt.Fprint(os.Stderr, buildLsUsage) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("build ls takes no positional arguments (got %q)", fs.Arg(0))
	}
	dir, err := buildledger.DefaultDir()
	if err != nil {
		return err
	}
	return listBuilds(w, buildledger.New(dir), *format, time.Now())
}

// listBuilds prints l's records newest first: a table, or the records verbatim
// as a JSON array. now prices a running build's duration.
func listBuilds(w io.Writer, l *buildledger.Ledger, format string, now time.Time) error {
	if format != "text" && format != "json" {
		return fmt.Errorf("unknown output format %q, want text or json", format)
	}
	recs, err := l.List()
	if err != nil {
		return err
	}
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(recs)
	}
	if len(recs) == 0 {
		fmt.Fprintln(w, "No builds recorded.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATUS\tTAG\tPLATFORM\tENGINE\tSTARTED\tDURATION")
	for _, r := range recs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.ID, sanitizeSnapshotName(string(r.Status)), sanitizeSnapshotName(r.Tag),
			sanitizeSnapshotName(r.Platform), sanitizeSnapshotName(r.Engine),
			r.StartedAt.UTC().Format(time.RFC3339), r.Duration(now).Round(time.Second))
	}
	return tw.Flush()
}
