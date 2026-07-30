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
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"k3sm.io/runtimed/pkg/image"
)

// imageUsage is the `k3sm image --help` text. The verb list is deliberately
// honest about what exists: only `prune` is implemented.
const imageUsage = `k3sm image — the local image store

Usage: k3sm image <command> [flags]

  prune   report (dry-run) or reclaim unreferenced blobs in the local image store

Planned, not implemented yet: load, import, ls — see docs/user/images.md.
`

// runImage dispatches the `k3sm image` sub-verbs. It is a router, not a verb:
// `load`/`import`/`ls` land here additively (docs/user/images.md), so a new verb
// is one case and nothing else moves.
func runImage(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, imageUsage)
		return errors.New("k3sm image needs a subcommand (prune)")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "-h", "--help", "help":
		fmt.Print(imageUsage)
		return nil
	case "prune":
		return runImagePrune(rest)
	default:
		fmt.Fprint(os.Stderr, imageUsage)
		return fmt.Errorf("unknown `k3sm image` subcommand %q (want prune)", sub)
	}
}

// defaultPruneGrace is the minimum age a blob must have before prune will even
// consider deleting it. It is a safety window against the pull→materialize race
// this CLI cannot observe: a blob written seconds ago by a pull whose pod has not
// yet been created is not yet named by anything a scan can see.
const defaultPruneGrace = time.Hour

// reclaimHonesty is the LOAD-BEARING qualifier on every size this command
// prints. runtimed materializes pod rootfs trees with APFS clonefile, so a
// blob's bytes are shared extents: unlinking the blob frees only the extents no
// surviving clone still references. Every figure below is therefore a LOGICAL
// size and physical reclaim is knowable only from a free-space delta. Do not
// reword this into a promise of freed bytes — TestImagePruneCLI pins it.
const reclaimHonesty = "Sizes are LOGICAL blob sizes, not proven freed bytes: APFS clonefile shares extents\n" +
	"with materialized pod rootfs trees, so confirm physical reclaim with a free-space delta\n" +
	"(`df -h %s` before and after)."

// pruneUsageNote is appended to `k3sm image prune -h`.
const pruneUsageNote = `k3sm image prune — report or reclaim unreferenced blobs in the local image store

Usage: k3sm image prune [flags]

DRY RUN IS THE DEFAULT: with no flags this plans only and removes nothing.
--execute performs the deletion; it requires root and refuses unless the set of
in-use images can be proven (see the refusal it prints).

Flags:
`

// pruneOptions is the parsed `k3sm image prune` flag surface.
type pruneOptions struct {
	root    string        // runtimed on-disk root (image cache + pod dirs)
	execute bool          // false (default) = plan only, delete nothing
	grace   time.Duration // minimum blob age before deletion is considered
}

// inUseSet is the answer to "which cached images do live pods depend on?".
//
// Derivable is the load-bearing field: false means UNKNOWN, never "nothing is in
// use". An empty-but-underivable set fed to the planner marks every blob
// unreferenced, so `--execute` must refuse on it (deleting the world) while
// dry-run may still print the plan, clearly labelled provisional.
type inUseSet struct {
	Digests   []string // manifest digests of in-use images; meaningful only when Derivable
	Derivable bool     // whether the live-pod→image mapping could be established at all
	Detail    string   // operator-facing explanation of the verdict (used in the refusal)
	Pods      int      // pod dirs observed under <root>/pods (informational)
}

// digests returns the in-use manifest digests, or nil when the set could not be
// derived — an underivable set never leaks a partial list into the planner.
func (s inUseSet) digests() []string {
	if !s.Derivable {
		return nil
	}
	return s.Digests
}

// pruneEnv holds `image prune`'s side-effecting seams: privilege lookup, the
// cache scan, the in-use derivation, the planner, the executor, the clock and
// the output sink. Tests inject fakes (GO-STANDARDS: fake at seams) so the CLI's
// refusal logic is provable without root, a real cache, or a real clock.
type pruneEnv struct {
	euid      func() int
	enumerate func(root string) ([]image.BlobNode, []image.ImageEdge, error)
	inUse     func(root string) (inUseSet, error)
	plan      func(nodes []image.BlobNode, edges []image.ImageEdge, inUse []string, grace time.Duration, now time.Time) (*image.PrunePlan, error)
	execute   func(root string, plan *image.PrunePlan, grace time.Duration, now time.Time) (*image.ExecuteReport, error)
	now       func() time.Time
	out       io.Writer
}

// productionPruneEnv wires the real seams: the process euid, runtimed's cache
// enumerator/planner/executor over the on-disk root, and stdout.
func productionPruneEnv() pruneEnv {
	return pruneEnv{
		euid: os.Geteuid,
		enumerate: func(root string) ([]image.BlobNode, []image.ImageEdge, error) {
			c, err := openCache(root)
			if err != nil {
				return nil, nil, err
			}
			return c.EnumerateBlobs()
		},
		inUse: derivePodInUse,
		plan:  image.PlanPrune,
		// The cache's prune lock is IN-PROCESS only (image.Cache doc); this CLI is
		// a separate process from any running node, so cross-process safety rests
		// entirely on ExecutePrune re-verifying grace + file kind per unlink.
		execute: func(root string, plan *image.PrunePlan, grace time.Duration, now time.Time) (*image.ExecuteReport, error) {
			c, err := openCache(root)
			if err != nil {
				return nil, err
			}
			return c.ExecutePrune(plan, grace, now)
		},
		now: time.Now,
		out: os.Stdout,
	}
}

// openCache opens the image cache at root WITHOUT creating anything:
// image.NewCache MkdirAll's the blobs dir, which would make a dry-run scan
// mutate the filesystem, so an absent cache is an error instead.
func openCache(root string) (*image.Cache, error) {
	blobs := filepath.Join(root, "blobs")
	fi, err := os.Stat(blobs)
	if err != nil {
		return nil, fmt.Errorf("image cache %s: %w", blobs, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("image cache %s is not a directory", blobs)
	}
	return image.NewCache(root)
}

// runImagePrune parses the `k3sm image prune` flags and runs it against the
// production seams.
func runImagePrune(args []string) error {
	return imagePruneCLI(args, productionPruneEnv())
}

// imagePruneCLI is `image prune` with its seams injected: it owns the flag
// surface so tests exercise the real flags (parsing, defaults, pass-through)
// rather than a hand-built options struct.
func imagePruneCLI(args []string, env pruneEnv) error {
	fs := flag.NewFlagSet("image prune", flag.ContinueOnError)
	// Discard flag's own output and return the error instead — main prints it
	// once (GO-STANDARDS: don't log and return the same error).
	fs.SetOutput(io.Discard)
	opts := pruneOptions{}
	// --pod-root is the SAME spelling `k3sm server --pod-root` uses for this root
	// (runtimed's on-disk root: the image cache plus the pod dirs) — deliberately
	// not a new --data-dir dialect.
	fs.StringVar(&opts.root, "pod-root", image.DefaultRoot, "runtimed on-disk root `dir` (image cache + pod dirs) — the same root k3sm server --pod-root runs with")
	fs.BoolVar(&opts.execute, "execute", false, "actually delete the planned blobs (requires root); omitted = DRY RUN, which removes nothing")
	fs.DurationVar(&opts.grace, "grace", defaultPruneGrace, "minimum blob age before deletion is considered; anything modified more recently is always kept")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(env.out, pruneUsageNote)
			fs.SetOutput(env.out)
			fs.PrintDefaults()
			return nil
		}
		return fmt.Errorf("parse flags: %w", err)
	}
	if rest := fs.Args(); len(rest) > 0 {
		return fmt.Errorf("unexpected argument %q (image prune takes flags only)", rest[0])
	}
	return imagePrune(opts, env)
}

// imagePrune plans, and only on an explicit --execute with a PROVEN in-use set
// deletes, unreferenced blobs in the local image store.
//
// The two refusals are the whole point of this verb:
//
//   - --execute without root cannot unlink from the root-owned store, so it
//     fails fast with the sudo instruction rather than half-deleting;
//   - --execute with an UNDERIVABLE in-use set is refused outright. The planner
//     treats an empty in-use set as "no image is in use", which would mark every
//     unreferenced blob deletable — a delete-the-world bug. Dry-run in that state
//     is still useful and still runs, labelled provisional.
func imagePrune(opts pruneOptions, env pruneEnv) error {
	if opts.root == "" {
		return errors.New("--pod-root must not be empty")
	}
	if opts.grace < 0 {
		return fmt.Errorf("--grace %v is negative", opts.grace)
	}
	if opts.execute && env.euid() != 0 {
		return fmt.Errorf("--execute needs root: the image store under %s is root-owned (euid %d here) — re-run as `sudo k3sm image prune --execute`",
			opts.root, env.euid())
	}
	now := env.now()

	nodes, edges, err := env.enumerate(opts.root)
	if err != nil {
		return fmt.Errorf("scan image store: %w", err)
	}
	use, err := env.inUse(opts.root)
	if err != nil {
		return fmt.Errorf("derive in-use images: %w", err)
	}
	if opts.execute && !use.Derivable {
		return fmt.Errorf("refusing to delete: cannot prove which images are in use, so every unreferenced-looking blob might belong to a running pod — %s. Re-run without --execute for a provisional plan", use.Detail)
	}

	plan, err := env.plan(nodes, edges, use.digests(), opts.grace, now)
	if err != nil {
		return fmt.Errorf("plan prune: %w", err)
	}

	if !opts.execute {
		printPrunePlan(env.out, opts, use, plan)
		return nil
	}
	rep, err := env.execute(opts.root, plan, opts.grace, now)
	if err != nil {
		return fmt.Errorf("execute prune: %w", err)
	}
	printPruneReport(env.out, opts, plan, rep)
	return nil
}

// derivePodInUse is the PRODUCTION in-use derivation — and it reports
// UNDERIVABLE unconditionally, by design and not by accident.
//
// Code evidence for why (runtimed, read at authoring time): a pod dir holds only
// the materialized tree (image.Cache.PodRootfs → <root>/pods/<podID>/rootfs,
// created by runtime.createPod) plus volume dirs. Nothing under it records the
// manifest digest the tree was cloned from — Puller.Pull persists the raw
// manifest into the CAS as a prune EDGE record, keyed by its own digest, and
// deliberately keeps no ref/pod index (pull.go: "do not grow this into an
// index"). The manifest digest a caller must supply to protect an image's chain
// (PullResult.ManifestDigest) exists only in the running daemon's memory.
//
// So this scan can report HOW MANY pods have materialized trees, which is worth
// telling the operator, but never WHICH images they use. The live-pod→image
// mapping arrives with the M12.1-d1 ref→digest image index or a running-node
// query; until then Derivable is false and --execute always refuses. Pod count
// deliberately does NOT gate that verdict: zero pod dirs is not proof of zero
// live pods (a pod being created concurrently has no dir yet).
func derivePodInUse(root string) (inUseSet, error) {
	podsDir := filepath.Join(root, "pods")
	ents, err := os.ReadDir(podsDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return inUseSet{}, fmt.Errorf("read pod dirs %s: %w", podsDir, err)
	}
	pods := 0
	for _, e := range ents {
		if e.IsDir() {
			pods++
		}
	}
	return inUseSet{
		Derivable: false,
		Pods:      pods,
		Detail: fmt.Sprintf("no live-pod→image mapping exists on disk (%d pod dir(s) under %s record their materialized rootfs, never the manifest digest it came from), and this CLI cannot see a running node's in-memory pod map; the mapping lands with the M12.1-d1 ref→digest image index",
			pods, podsDir),
	}, nil
}

// Fixed reason orders so the summary is deterministic across runs.
var (
	keepReasons = []image.PruneReason{
		image.ReasonKeptInUse,
		image.ReasonKeptReferenced,
		image.ReasonKeptUnknownProvenance,
		image.ReasonKeptYoung,
	}
	deleteReasons = []image.PruneReason{
		image.ReasonDeleteUnreferenced,
		image.ReasonDeleteStaleTemp,
	}
)

// printPrunePlan renders a dry-run plan: the header (mode, root, grace), the
// in-use verdict, per-verdict counts and logical bytes, and the full delete set.
func printPrunePlan(w io.Writer, opts pruneOptions, use inUseSet, plan *image.PrunePlan) {
	fmt.Fprintf(w, "k3sm image prune — DRY RUN: nothing will be deleted (pass --execute to reclaim)\n")
	fmt.Fprintf(w, "  store: %s\n", filepath.Join(opts.root, "blobs"))
	fmt.Fprintf(w, "  grace: %v (anything modified more recently is kept)\n\n", opts.grace)

	if use.Derivable {
		fmt.Fprintf(w, "in-use set: %d image(s) — %s\n\n", len(use.Digests), use.Detail)
	} else {
		fmt.Fprintf(w, "in-use set: UNDERIVABLE (treated as empty) — every verdict below is PROVISIONAL\n")
		fmt.Fprintf(w, "  %s\n", use.Detail)
		fmt.Fprintf(w, "  --execute is refused in this state; this plan is for inspection only.\n\n")
	}

	keepN, keepBytes := countDecisions(plan.Keep)
	delN, delBytes := countDecisions(plan.Delete)
	fmt.Fprintf(w, "inventory: %d node(s), %s logical\n", keepN+delN, humanBytes(keepBytes+delBytes))
	fmt.Fprintf(w, "  keep   %4d node(s), %10s logical\n", keepN, humanBytes(keepBytes))
	printReasonCounts(w, plan.Keep, keepReasons)
	fmt.Fprintf(w, "  delete %4d node(s), %10s logical\n", delN, humanBytes(delBytes))
	printReasonCounts(w, plan.Delete, deleteReasons)

	if delN > 0 {
		fmt.Fprintf(w, "\ndelete set (--execute would unlink these):\n")
		tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "  REASON\tPATH\tKIND\tLOGICAL\tMODIFIED")
		for _, d := range plan.Delete {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", d.Reason, d.Node.Path, d.Node.Kind,
				humanBytes(d.Node.Size), d.Node.ModTime.UTC().Format(time.RFC3339))
		}
		_ = tw.Flush() // best-effort: the plan is already fully written to w
	}

	fmt.Fprintf(w, "\n"+reclaimHonesty+"\n\n", opts.root)
	fmt.Fprintf(w, "k3sm-image-prune: mode=dry-run root=%s inuse=%s inventory=%d keep=%d delete=%d delete_logical_bytes=%d grace=%v\n",
		opts.root, inUseTag(use), keepN+delN, keepN, delN, delBytes, opts.grace)
}

// printPruneReport renders an executed prune: what was unlinked, and every plan
// entry the executor skipped (re-verification misses are normal, not errors).
func printPruneReport(w io.Writer, opts pruneOptions, plan *image.PrunePlan, rep *image.ExecuteReport) {
	planN, planBytes := countDecisions(plan.Delete)
	fmt.Fprintf(w, "k3sm image prune — EXECUTED\n")
	fmt.Fprintf(w, "  store:   %s\n", filepath.Join(opts.root, "blobs"))
	fmt.Fprintf(w, "  grace:   %v\n", opts.grace)
	fmt.Fprintf(w, "  planned: %d node(s), %s logical\n", planN, humanBytes(planBytes))
	fmt.Fprintf(w, "  deleted: %d node(s), %s logical\n", rep.Deleted, humanBytes(rep.DeletedBytes))
	if len(rep.Skipped) > 0 {
		fmt.Fprintf(w, "  skipped: %d node(s) left in place (re-verification miss; the next run re-plans them)\n", len(rep.Skipped))
		tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "    PATH\tREASON")
		for _, s := range rep.Skipped {
			fmt.Fprintf(tw, "    %s\t%s\n", s.Path, s.Reason)
		}
		_ = tw.Flush() // best-effort: the report is already fully written to w
	}
	fmt.Fprintf(w, "\n"+reclaimHonesty+"\n\n", opts.root)
	fmt.Fprintf(w, "k3sm-image-prune: mode=execute root=%s planned=%d deleted=%d deleted_logical_bytes=%d skipped=%d grace=%v\n",
		opts.root, planN, rep.Deleted, rep.DeletedBytes, len(rep.Skipped), opts.grace)
}

// inUseTag is the machine-line token for the in-use verdict.
func inUseTag(use inUseSet) string {
	if !use.Derivable {
		return "underivable"
	}
	return fmt.Sprintf("%d", len(use.Digests))
}

// countDecisions sums a decision slice's node count and logical bytes.
func countDecisions(ds []image.PruneDecision) (int, int64) {
	var bytes int64
	for _, d := range ds {
		bytes += d.Node.Size
	}
	return len(ds), bytes
}

// printReasonCounts prints one indented line per reason in the given order, plus
// any reason not in that order (so an added PruneReason can never go unreported).
func printReasonCounts(w io.Writer, ds []image.PruneDecision, order []image.PruneReason) {
	counts := map[image.PruneReason]int{}
	for _, d := range ds {
		counts[d.Reason]++
	}
	known := map[image.PruneReason]bool{}
	for _, r := range order {
		known[r] = true
		fmt.Fprintf(w, "    %-24s %d\n", r, counts[r])
	}
	var extra []string
	for r := range counts {
		if !known[r] {
			extra = append(extra, string(r))
		}
	}
	sort.Strings(extra)
	for _, r := range extra {
		fmt.Fprintf(w, "    %-24s %d\n", r, counts[image.PruneReason(r)])
	}
}

// humanBytes formats n as a binary-prefixed size. The caller labels it logical —
// see reclaimHonesty.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	v := float64(n)
	i := -1 // i indexes units only AFTER the first division
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	return strings.TrimSuffix(fmt.Sprintf("%.1f", v), ".0") + " " + units[i]
}
