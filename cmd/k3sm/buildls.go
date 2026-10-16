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
	return tr
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

// finish rewrites the record with the build's outcome.
func (tr *buildRecord) finish(buildErr error) {
	if !tr.started {
		return
	}
	if _, err := tr.ledger.Finish(tr.rec, tr.digest, buildErr); err != nil {
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
