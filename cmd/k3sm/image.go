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
	"net"
	"os"
	"sort"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"

	"k3sm.io/k3sm/pkg/executor"
)

const imageUsage = `k3sm image — ingest, inspect and reclaim this node's image store

Usage: k3sm image pull <reference> [flags]
       k3sm image tag <digest|reference> <new-reference> [flags]
       k3sm image untag <reference> [flags]
       k3sm image inspect <reference|digest> [flags]
       k3sm image save <reference> -o <file.tar> [flags]
       k3sm image load <docker-save.tar> [flags]
       k3sm image import <oci-layout.tar> [flags]
       k3sm image push <oci-layout-dir|reference> <registry-reference> [flags]
       k3sm image prune [flags]
       k3sm image ls [flags]
       k3sm image df [flags]

pull    fetch a reference into this node's store through the daemon's OWN
        puller — the same code path a pod-driven pull takes, so every blob is
        re-hashed against its digest before it is recorded. Prints the digest
        the reference resolved to. --platform pins which manifest of a
        multi-platform index to fetch; --policy carries the corev1 pull-policy
        semantics (always, if-not-present, never). A pulled image survives
        prune until you untag it.
tag     record an ADDITIONAL name for content this node already holds. The
        target is named by digest — a reference is resolved to one first —
        because a tag that named another tag could be re-aimed by a concurrent
        pull. It never re-points an existing name: that is untag, then tag.
untag   remove ONE (reference x platform) name. UNTAG REMOVES A NAME, NOT
        BYTES: no blob is unlinked here, and content is reclaimed only by
        ` + "`k3sm image prune`" + `, which re-derives reachability first — so untagging
        a name a running pod still pins leaves that pod unharmed. --digest
        refuses the removal unless the name still resolves to that digest.
inspect report what the store knows about one image: digest, resolved platform,
        creation time, entrypoint/cmd, user, working directory, and each
        layer's digest and size. -o json prints the daemon's raw response
        instead of the table. Read-only — it contacts no registry.
save    stream one image out of the store as a tarred OCI image layout (the
        ` + "`docker save`" + ` analog) into the file -o names. The archive is checked
        against the digest and the byte count the daemon reports it sent, and
        a short one is discarded rather than left on disk.
load    stream a ` + "`docker save`" + ` tar into this node's image store.
import  stream a tarred OCI image layout (the ` + "`docker buildx -o type=oci`" + `
        output) into this node's image store.
        Both are streamed to the daemon, which is the store's only writer: it
        re-hashes every byte and records the reference. Loaded content is stored,
        not yet runnable — see docs/user/images.md.
push    upload an image to a registry reference, and print the digest it now has
        there so callers can pin it. The first argument is normally the OCI
        layout directory ` + "`k3sm build --format oci`" + ` writes; a first argument
        that is no path on disk is taken as a reference in THIS NODE's store,
        exported with save and then uploaded. The upload itself does NOT talk to
        the daemon: it reads a directory you own and uploads as you. The
        credential comes from $K3SM_REGISTRY_TOKEN, this node's own
        ingest-registry credential (only when the target IS this node's loopback
        registry), or the docker config chain — never from the command line, and
        k3sm stores none of it.
prune   delete image content no pod references. DRY RUN BY DEFAULT — pass
        --force to actually unlink. The daemon does the deleting: this command
        is a client of the runtimed Images service, it never walks the store
        itself. A pod's content is never deleted, and if the daemon cannot
        enumerate every pod's references it refuses the whole prune.
ls      list the images this node has recorded.
df      show the image store's filesystem usage.

Flags:
`

// imageOptions is the parsed argv for `k3sm image`, kept separate from execution
// so the gate can drive parsing and execution independently.
type imageOptions struct {
	subcommand string
	socket     string
	force      bool
	timeout    time.Duration
	// archive is the positional path load/import ingests; empty for every other
	// subcommand, which take no positional argument at all.
	archive   string
	reference string
	// source is the image the verb NAMES: pull's reference, tag's existing
	// digest-or-reference, and the reference-or-digest untag, inspect and save
	// act on. It is kept apart from --reference because that flag names the
	// entry load/import is about to CREATE, and folding the two would make
	// `image save app:v1 --reference other:v1` mean something.
	source string
	// platform is the parsed --platform selector, nil when unset. Unset is not
	// "every platform": the daemon reads it as its own host platform for a pull
	// and as "the reference's single entry" for the verbs that name one, so the
	// distinction has to survive to the wire.
	platform *runtimev1.Platform
	// policy is the parsed --policy, pull only.
	policy runtimev1.ImagePullPolicy
	// digest is untag's --digest pin: the removal is refused unless the entry
	// still resolves to it.
	digest string
	// output is -o/--output, whose meaning is the subcommand's: the file save
	// writes the archive to, and inspect's rendering (empty for the table,
	// "json" for the daemon's raw response).
	output string
	// layoutDir and target are push's two positional arguments: the OCI layout
	// to read, and the registry reference to write it to. The credential is
	// neither of them, and is not a flag either — see registryAuth.
	layoutDir string
	target    string
	// workDir is the control-plane state root push looks in for THIS node's
	// ingest-registry credential. It is a path, never a secret: the credential
	// itself stays in a 0600 file the invoking user must already be able to read.
	workDir string
}

// Ingest streams a whole archive, so it cannot share the deadline sized for a
// metadata call: a multi-GB tar over a unix socket routinely outlives two
// minutes, and a deadline that fires mid-stream throws away every byte already
// sent. Both are still one flag — an explicit --timeout always wins.
const (
	metadataTimeout  = 2 * time.Minute
	streamingTimeout = 30 * time.Minute
)

// runImage is the `k3sm image` entry point.
func runImage(args []string) error {
	opts, err := parseImageArgs(args, os.Stderr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	return imageCommand(ctx, opts, os.Stdout, dialRuntimed)
}

// parseImageArgs parses argv. ContinueOnError so a bad flag is an error the
// caller reports, never an os.Exit inside a test binary.
func parseImageArgs(args []string, errOut io.Writer) (imageOptions, error) {
	var o imageOptions
	fs := flag.NewFlagSet("image", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		fmt.Fprint(errOut, imageUsage)
		fs.PrintDefaults()
	}
	fs.StringVar(&o.socket, "socket", runtimed.DefaultSocketPath, "runtimed control socket to dial")
	// The control-plane state root, consulted by push ONLY, and only to find this
	// node's ingest-registry credential. A resolve failure is not reported here:
	// every other subcommand is a client of runtimed and has no use for a work
	// dir, so an unresolvable one must not make `k3sm image ls` fail.
	defaultWorkDir, _ := executor.ResolveWorkDir()
	fs.StringVar(&o.workDir, "work-dir", defaultWorkDir, "control-plane state root to read this node's ingest-registry push credential from (push only)")
	// DRY RUN IS THE DEFAULT and deleting takes an explicit flag, because the
	// blast radius is asymmetric: a needless dry run costs a statfs, while an
	// unintended prune on a node that cannot reach its registry costs every image
	// it cannot re-pull.
	fs.BoolVar(&o.force, "force", false, "actually unlink (without this, prune only reports what it would delete)")
	fs.StringVar(&o.reference, "reference", "", "reference to record a loaded image under (load, import; defaults to the one the archive names)")
	// The platform is part of the store's (reference x platform) KEY, never a
	// filter, so it is spelled the way an OCI platform is spelled everywhere
	// else — os/arch[/variant] — rather than as three flags nobody would pair
	// correctly.
	var platformSpec, policySpec string
	fs.StringVar(&platformSpec, "platform", "", "os/arch[/variant] this verb acts on, e.g. darwin/arm64 (pull, tag, untag, inspect, save)")
	fs.StringVar(&policySpec, "policy", "", "pull policy: always, if-not-present or never (pull only; default is the pull-through behaviour)")
	fs.StringVar(&o.digest, "digest", "", "refuse the removal unless the name still resolves to this manifest digest (untag only)")
	// One flag, two meanings, chosen by the subcommand — the spelling `docker`
	// uses for both. It is validated per subcommand at parse time so `inspect -o
	// out.tar` fails before anything is dialled.
	fs.StringVar(&o.output, "o", "", "save: the file to write the archive to; inspect: json, for the daemon's raw response instead of the table")
	fs.StringVar(&o.output, "output", "", "alias for -o")
	fs.DurationVar(&o.timeout, "timeout", metadataTimeout, "overall deadline for the call (load, import, push, pull and save default to 30m — they stream image content)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	// stdlib flag stops at the first non-flag argument, so a single Parse would
	// leave `image prune --force` with --force unparsed and silently dry-run a
	// command the operator asked to execute. Parsing the remainder AFTER lifting
	// the subcommand accepts both orderings, which matters because the
	// subcommand-first spelling is the one every comparable tool teaches.
	rest := fs.Args()
	if len(rest) == 0 {
		return o, fmt.Errorf("exactly one subcommand is required (%s)", imageSubcommands)
	}
	o.subcommand = rest[0]
	// load/import/push take positional paths, so parsing cannot stop at the first
	// non-flag argument: `image load app.tar --reference x` must reach --reference.
	// Alternating parse-then-lift accepts every ordering an operator might type.
	var positional []string
	remaining := rest[1:]
	for {
		if err := fs.Parse(remaining); err != nil {
			return o, err
		}
		remaining = fs.Args()
		if len(remaining) == 0 {
			break
		}
		positional = append(positional, remaining[0])
		remaining = remaining[1:]
	}
	switch o.subcommand {
	case "prune", "ls", "df":
		if len(positional) > 0 {
			return o, fmt.Errorf("unexpected argument %q: exactly one subcommand is required (%s)", positional[0], imageSubcommands)
		}
	case "load", "import":
		if len(positional) == 0 {
			return o, fmt.Errorf("%s requires the path of the archive to ingest", o.subcommand)
		}
		if len(positional) > 1 {
			return o, fmt.Errorf("unexpected argument %q: %s takes exactly one archive path", positional[1], o.subcommand)
		}
		o.archive = positional[0]
	case "push":
		if len(positional) < 2 {
			return o, errors.New("push requires a source (an OCI layout directory, or a reference in this node's store) and the registry reference to push it to")
		}
		if len(positional) > 2 {
			// A third word is most often an operator reaching for a credential
			// argument. Refusing beats ignoring: a token typed here would already
			// be in the shell history by the time it was ignored.
			return o, fmt.Errorf("unexpected argument %q: push takes exactly a layout directory and a reference (the credential is read from $%s or the docker config chain, never from the command line)", positional[2], registryTokenEnv)
		}
		o.layoutDir = positional[0]
		o.target = positional[1]
		if flagWasSet(fs, "reference") {
			return o, errors.New("push takes its reference as the second argument, not --reference")
		}
	case "pull", "untag", "inspect", "save":
		if len(positional) == 0 {
			return o, fmt.Errorf("%s requires the reference%s to act on", o.subcommand, digestAlso(o.subcommand))
		}
		if len(positional) > 1 {
			return o, fmt.Errorf("unexpected argument %q: %s takes exactly one reference%s", positional[1], o.subcommand, digestAlso(o.subcommand))
		}
		o.source = positional[0]
	case "tag":
		if len(positional) < 2 {
			return o, errors.New("tag requires the digest or reference to name, and the new reference to record for it")
		}
		if len(positional) > 2 {
			return o, fmt.Errorf("unexpected argument %q: tag takes exactly a source (digest or reference) and the new reference", positional[2])
		}
		o.source = positional[0]
		o.target = positional[1]
	default:
		return o, fmt.Errorf("unknown subcommand %q (want one of %s)", o.subcommand, imageSubcommands)
	}

	// Every flag below belongs to a subset of the verbs. Refusing a flag the
	// verb cannot honour beats ignoring it: an ignored --platform on a prune
	// reads as "that platform was pruned" until someone re-reads the store.
	platformVerbs := map[string]bool{"pull": true, "tag": true, "untag": true, "inspect": true, "save": true}
	if flagWasSet(fs, "platform") && !platformVerbs[o.subcommand] {
		return o, fmt.Errorf("%s does not take --platform (it selects the (reference x platform) entry pull, tag, untag, inspect and save act on)", o.subcommand)
	}
	var err error
	if o.platform, err = parsePlatform(platformSpec); err != nil {
		return o, err
	}
	if flagWasSet(fs, "policy") && o.subcommand != "pull" {
		return o, fmt.Errorf("%s does not take --policy (only pull performs a registry round trip)", o.subcommand)
	}
	if o.policy, err = parsePullPolicy(policySpec); err != nil {
		return o, err
	}
	if flagWasSet(fs, "digest") && o.subcommand != "untag" {
		return o, fmt.Errorf("%s does not take --digest (it pins the entry untag is allowed to remove)", o.subcommand)
	}
	switch o.subcommand {
	case "save":
		if o.output == "" {
			return o, errors.New("save requires -o <file.tar>: the archive is written to a file you name, never to the terminal")
		}
	case "inspect":
		if o.output != "" && o.output != "json" {
			return o, fmt.Errorf("-o %q: inspect renders a table by default and `json` on request", o.output)
		}
	default:
		if flagWasSet(fs, "o") || flagWasSet(fs, "output") {
			return o, fmt.Errorf("%s does not take -o (save writes an archive to it, inspect chooses a rendering with it)", o.subcommand)
		}
	}
	// The streaming default applies only when the operator did not choose. Visit
	// reports flags actually set across both Parse calls, so it distinguishes
	// "--timeout 2m" from "left alone".
	timeoutSet := false
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "timeout" {
			timeoutSet = true
		}
	})
	if !timeoutSet && streamingSubcommands[o.subcommand] {
		o.timeout = streamingTimeout
	}
	if o.timeout <= 0 {
		return o, fmt.Errorf("--timeout must be positive, got %v", o.timeout)
	}
	return o, nil
}

// imageSubcommands is the verb list an argument error names, kept in one place
// so a new verb cannot be advertised in the usage and forgotten in the errors.
const imageSubcommands = "pull, tag, untag, inspect, save, load, import, push, prune, ls, df"

// streamingSubcommands are the verbs that move image content rather than
// metadata, and so inherit the streaming deadline when the operator did not
// choose one. A deadline sized for a metadata call fires mid-transfer and
// throws away every byte already moved.
var streamingSubcommands = map[string]bool{
	"load": true, "import": true, "push": true, "pull": true, "save": true,
}

// digestAlso names the alternative target spelling in an argument error, for
// the verbs that accept a digest as well as a reference.
func digestAlso(subcommand string) string {
	if subcommand == "pull" || subcommand == "untag" {
		return ""
	}
	return " (or digest)"
}

// flagWasSet reports whether name was given on the command line. flag cannot
// distinguish "not set" from "set to the empty string" by value alone, and a
// verb that cannot honour a flag must refuse it rather than quietly ignore it.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == name {
			set = true
		}
	})
	return set
}

// imagesDialer opens a connection to a runtimed control socket. It is the test
// seam: the command's rendering and its error mapping are exercised against a
// fake service with no daemon, no root and no filesystem.
type imagesDialer func(ctx context.Context, socket string) (grpc.ClientConnInterface, io.Closer, error)

// dialRuntimed is the production imagesDialer: a plain unix-socket gRPC client.
// The socket is 0600 in a 0700 dir owned by the daemon's uid, so an operator who
// is not that uid gets a connection error — which is the correct outcome, since
// PruneImages deletes content.
func dialRuntimed(_ context.Context, socket string) (grpc.ClientConnInterface, io.Closer, error) {
	cc, err := grpc.NewClient("passthrough:///runtimed",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dial runtimed at %s: %w", socket, err)
	}
	return cc, cc, nil
}

// imageCommand executes the parsed command against the daemon.
//
// THE DAEMON DOES THE WORK. This command computes no reachability, opens no
// blob, and unlinks nothing: it sends a request and renders the typed answer.
// That is not a layering preference — a CLI walking a live store cannot be made
// correct by locking, because no lock it holds is also held across the daemon's
// own pull commit, so it would race the very writer it is trying to reason about.
func imageCommand(ctx context.Context, o imageOptions, out io.Writer, dial imagesDialer) error {
	// push is the one subcommand whose ordinary form is not a daemon client: it
	// reads a layout the invoking user owns and uploads it to a registry as that
	// user. Dialing first would fail a perfectly valid push on a node whose
	// daemon is down, so push takes the dialer and uses it only for the store-ref
	// form, which genuinely has to ask the daemon for the bytes.
	if o.subcommand == "push" {
		return imagePush(ctx, o, out, dial)
	}
	cc, closer, err := dial(ctx, o.socket)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer.Close()
	}
	client := runtimev1.NewImagesClient(cc)
	switch o.subcommand {
	case "load":
		return imageLoad(ctx, client, o, out, runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE)
	case "import":
		return imageLoad(ctx, client, o, out, runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT)
	case "pull":
		return imagePull(ctx, client, o, out)
	case "tag":
		return imageTag(ctx, client, o, out)
	case "untag":
		return imageUntag(ctx, client, o, out)
	case "inspect":
		return imageInspect(ctx, client, o, out)
	case "save":
		return imageSave(ctx, client, o, out)
	case "prune":
		return imagePrune(ctx, client, o, out)
	case "ls":
		return imageList(ctx, client, out)
	case "df":
		return imageDF(ctx, client, out)
	}
	return fmt.Errorf("unknown subcommand %q", o.subcommand)
}

// imagePrune asks the daemon to prune and renders the typed outcome.
func imagePrune(ctx context.Context, client runtimev1.ImagesClient, o imageOptions, out io.Writer) error {
	resp, err := client.PruneImages(ctx, &runtimev1.PruneImagesRequest{DryRun: !o.force})
	if err != nil {
		return imageRPCError("prune images", o.socket, err)
	}
	verb := "would delete"
	if o.force {
		verb = "deleted"
	}
	if len(resp.GetRemovedDigests()) == 0 {
		fmt.Fprintln(out, "nothing to reclaim: every blob in the store is referenced.")
	}
	for _, d := range resp.GetRemovedDigests() {
		fmt.Fprintf(out, "%s %s\n", verb, d)
	}
	fmt.Fprintf(out, "%s %d blob(s), %s\n", verb, len(resp.GetRemovedDigests()), humanBytes(resp.GetReclaimedBytes()))
	if !o.force {
		fmt.Fprintln(out, "(dry run — pass --force to unlink)")
	}
	// Kept blobs are summarized by REASON rather than listed one per line: an
	// operator asking "why is my disk still full" needs the shape of the answer,
	// and a store with thousands of layers would otherwise bury it.
	if counts := skipCounts(resp.GetSkipped()); len(counts) > 0 {
		fmt.Fprintln(out, "kept:")
		reasons := make([]string, 0, len(counts))
		for r := range counts {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		for _, r := range reasons {
			fmt.Fprintf(out, "  %-24s %d\n", r, counts[r])
		}
	}
	return nil
}

// skipCounts tallies kept blobs by their typed reason, rendered in the operator's
// vocabulary rather than the enum's.
func skipCounts(skipped []*runtimev1.SkippedBlob) map[string]int {
	counts := make(map[string]int)
	for _, s := range skipped {
		counts[skipReasonText(s.GetReason())]++
	}
	return counts
}

// skipReasonText renders a typed skip reason. The mapping is total: an enum
// value this build does not know renders as its own name rather than being
// silently folded into a neighbour's meaning.
func skipReasonText(r runtimev1.PruneSkipReason) string {
	switch r {
	case runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_IN_USE:
		return "in use by a pod"
	case runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_LEASED:
		return "an ingest is in flight"
	case runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_REACHABLE:
		return "reachable"
	case runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_UNLINK_FAILED:
		return "not deletable"
	case runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_UNSPECIFIED:
		return "no reason reported"
	}
	return r.String()
}

// imageList renders the node's recorded images.
func imageList(ctx context.Context, client runtimev1.ImagesClient, out io.Writer) error {
	resp, err := client.ListImages(ctx, &runtimev1.ListImagesRequest{})
	if err != nil {
		return imageRPCError("list images", "", err)
	}
	if len(resp.GetImages()) == 0 {
		fmt.Fprintln(out, "no images recorded on this node.")
		return nil
	}
	fmt.Fprintf(out, "%-48s %-8s %s\n", "REFERENCE", "LAYERS", "CONFIG")
	for _, img := range resp.GetImages() {
		m := img.GetManifest()
		fmt.Fprintf(out, "%-48s %-8d %s\n", m.GetReference(), len(m.GetLayers()), m.GetConfig().GetDigest())
	}
	return nil
}

// imageDF renders the image store's filesystem usage.
func imageDF(ctx context.Context, client runtimev1.ImagesClient, out io.Writer) error {
	resp, err := client.ImageFsInfo(ctx, &runtimev1.ImageFsInfoRequest{})
	if err != nil {
		return imageRPCError("image filesystem info", "", err)
	}
	fmt.Fprintf(out, "store: %s\n", humanBytes(resp.GetStoreBytes()))
	for _, fsu := range resp.GetFilesystems() {
		fmt.Fprintf(out, "%s: %s used of %s, %s available\n",
			fsu.GetMountpoint(), humanBytes(fsu.GetUsedBytes()),
			humanBytes(fsu.GetCapacityBytes()), humanBytes(fsu.GetAvailableBytes()))
	}
	// The store figure counts every blob at its full logical size, but a blob
	// whose extents are cloned into a live pod's rootfs shares them — so the sum
	// is not what a prune would give back, and saying so is cheaper than an
	// operator inferring a broken prune from the arithmetic.
	fmt.Fprintln(out, "(store bytes are logical sizes; APFS clones share extents, so a prune frees less)")
	return nil
}

// imageRPCError translates a daemon status into an operator-actionable message.
func imageRPCError(what, socket string, err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%s: %w", what, err)
	}
	switch st.Code() {
	case codes.Unimplemented:
		return fmt.Errorf("%s: this runtimed does not serve the image service: %s", what, st.Message())
	case codes.FailedPrecondition:
		// The fail-closed refusal. It is not a daemon fault and the operator can
		// act on it, so it must not read like an internal error.
		return fmt.Errorf("%s: the daemon refused: %s", what, st.Message())
	case codes.Unavailable:
		if socket != "" {
			return fmt.Errorf("%s: cannot reach runtimed at %s (is the daemon running, and are you its uid?): %s",
				what, socket, st.Message())
		}
		return fmt.Errorf("%s: runtimed unavailable: %s", what, st.Message())
	}
	return fmt.Errorf("%s: %s", what, st.Message())
}

// humanBytes renders a byte count in binary units.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
