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
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"

	"k3sm.io/k3sm/pkg/executor"
)

const imageUsage = `k3sm image — record, name and inspect images in the cluster registry, list where each is cached, and manage this node's cache

Usage: k3sm image pull <reference> [flags]
       k3sm image tag <reference|digest> <new-tag> [flags]
       k3sm image untag <tag> [flags]
       k3sm image inspect <tag|repository@digest> [flags]
       k3sm image save <reference> -o <file.tar> [flags]
       k3sm image load <docker-save.tar> [flags]
       k3sm image import <oci-layout.tar> [flags]
       k3sm image push <oci-layout-dir|reference> <registry-reference> [flags]
       k3sm image prune [flags]
       k3sm image ls [-o json|ndjson] [flags]
       k3sm image df [-o json] [flags]
       k3sm image migrate [--report] [-o json]   (copy this node's images into the cluster registry once; sudo on a worker)

pull    fetch a reference into this node's store through the daemon's OWN
        puller — the same code path a pod-driven pull takes, so every blob is
        re-hashed against its digest before it is recorded. Prints the digest
        the reference resolved to. --platform pins which manifest of a
        multi-platform index to fetch; --policy carries the corev1 pull-policy
        semantics (always, if-not-present, never). Pull fills this node's
        cache. A pulled image is ordinary cache content, so prune
        can reclaim it once no pod uses it. A public reference is then also copied into the cluster
        registry as registry-k3sm:6450/<registry>/<repository>:<tag>
        (docker.io for Docker Hub), which a node pulls from only when the
        public registry cannot be reached at all. The copy uploads as you
        through your kubeconfig, like push; a failed copy is a warning, not a
        failed pull. A cluster-registry reference, or a registry with a port,
        gets no copy; --no-mirror skips it.
tag     add a tag in the cluster registry to a manifest it already holds:
        an OCI manifest PUT of the same bytes, so the new tag names the same
        digest. The source is a tag, a <repository>@<digest>, or a bare digest
        in the new tag's repository; --platform tags that platform's child of
        an index. It refuses to re-point a tag that already names another
        manifest unless --force is given.
untag   delete one tag from the cluster registry. It REMOVES A NAME, NOT BYTES:
        a manifest another tag names stays, the registry's own garbage
        collection reclaims what nothing names, and a node that already
        pulled the image keeps its cached copy. --digest refuses the removal
        unless the tag still names that manifest.
inspect report what the cluster registry holds under a tag or a
        <repository>@<digest>: digest, platform, creation time,
        entrypoint/cmd, user, working directory, and each layer's digest and
        size. An index lists its platforms; --platform inspects one. -o json
        prints the registry's manifest and config documents instead.
save    export one image from the cluster registry as a tarred OCI image
        layout (the ` + "`docker save`" + ` analog, and what import reads back) into
        the file -o names. An index is saved whole unless --platform picks
        one. A failed save leaves no file behind.
        tag, untag, inspect and save never contact the daemon, and a name
        naming another registry is refused. tag writes through the push gate
        with a token minted through your kubeconfig; inspect and save read
        this server's registry anonymously; untag deletes, which the gate
        never forwards, so it needs the server's push credential: run it as
        root with --work-dir /var/lib/k3sm/server. An account that can read
        that credential (see --work-dir) uses it for all four.
load    record a ` + "`docker save`" + ` tar in the cluster registry, the cluster's one
        image store, under registry-k3sm:6450/<repository>:<tag>, overwriting
        that tag; then pull it into this node's cache.
import  the same for a tarred OCI image layout (the ` + "`docker buildx -o type=oci`" + `
        output); a layout holding a multi-platform index records the index.
        Both upload as you with this node's push credential (see --work-dir),
        and the cache pull goes through the daemon's own puller.
push    upload an image to a registry reference, and print the digest it now has
        there so callers can pin it. The first argument is normally the OCI
        layout directory ` + "`k3sm build --format oci`" + ` writes; a first argument
        that is no path on disk is taken as a reference in THIS NODE's store,
        exported with save and then uploaded. A reference this node's store does
        not hold may name an image the cluster registry holds, as image ls and
        inspect show it (the one ` + "`k3sm build`" + ` recorded): it is copied from
        there through the push gate, blobs the destination has are skipped and,
        within the cluster registry, mounted rather than sent again; a
        destination naming the same repository and tag copies nothing. The
        layout upload itself does NOT talk to the daemon: it reads a directory
        you own and uploads as you. The
        credential comes from $K3SM_REGISTRY_TOKEN (with $K3SM_REGISTRY_USER
        as its user, "token" by default), this node's own
        ingest-registry credential (only when the target IS this node's loopback
        registry), or the docker config chain — never from the command line, and
        k3sm stores none of it.
prune   delete the cluster registry's untagged manifests and evict what no
        pod uses from this node's cache. DRY RUN BY DEFAULT — pass --force to
        delete. The registry half runs on the server that holds the registry:
        a manifest a tag, a tagged index or a kept referrer still needs stays,
        and so does one younger than an hour (a push may be in flight); the
        registry's garbage collection then reclaims the layers. The cache half
        is the runtimed Images service's own prune: a pod's content is never
        deleted, and if the daemon cannot enumerate every pod's references it
        refuses the whole prune. -o json prints both halves as one document.
ls      list the images in the cluster's one registry (the server's), each
        under its canonical reference ` + "`" + canonicalRegistry + "/<repo>:<tag>`" + `, with
        its digest, platforms and size, how many Pods use it, and the nodes
        whose status.images report it cached. A node at the 50-image
        status.images cap may cache an image it does not list; -o json names
        such nodes under cachedOnIncomplete. Read-only and anonymous: it needs
        no root and no daemon socket, only a kubeconfig that can read Nodes,
        Pods and the local-registry-hosting ConfigMap. An unreachable registry
        is reported (reachable: false, with the error) and still exits 0.
        -o ndjson streams the listing as it runs, one JSON object per line,
        each with a "type": first {"type":"start","schemaVersion":1,
        "registry":{"name","reachable"[,"error"]}}; then
        {"type":"progress","repositories","repositoriesRead","tags",
        "tagsRead"} after each repository's tag list (tags is the running
        total, growing until every list is read) and at most every 250ms
        while tags are read; {"type":"image",...} per tag as it is read,
        with the fields of an element of -o json's images, in completion
        order; and last {"type":"end","images","cachedOnIncomplete",
        "migration"}. An unreachable registry is a start line saying so,
        then end, exit 0; a failure after the registry answered is
        {"type":"error","error"} and a non-zero exit, with no end line.
df      show the registry's size (its distinct blobs) and each node's image
        cache as its status.images reports it. Same reads as ls.

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
	// cacheOnly marks a pull as a cache warm-up rather than an operator pull:
	// the daemon records no operator root for it, so prune may reclaim the
	// image once no pod uses it. No flag sets it; only the warm-up after a
	// build, load or import into the cluster registry does.
	cacheOnly bool
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
	// noMirror is pull's --no-mirror: skip the copy into the cluster registry.
	noMirror bool
	// warn is where a verb writes a warning that does not fail it: the
	// writer parseImageArgs was given. Nil discards.
	warn io.Writer
	// workDir is the control-plane state root push looks in for THIS node's
	// ingest-registry credential. It is a path, never a secret: the credential
	// itself stays in a 0600 file the invoking user must already be able to read.
	workDir string
}

// Moving image content (load, import, push, pull, save) cannot share the
// deadline sized for a metadata call: a multi-GB upload to or download from the
// registry routinely outlives two minutes, and a deadline that fires mid-stream
// throws away every byte already sent. Both are still one flag — an explicit
// --timeout always wins.
const (
	metadataTimeout  = 2 * time.Minute
	streamingTimeout = 30 * time.Minute
)

// runImage is the `k3sm image` entry point.
func runImage(args []string) error {
	// migrate has its own flags and touches the registry as well as runtimed,
	// so it parses on its own (imagemigrateverb.go).
	if len(args) > 0 && args[0] == "migrate" {
		return runImageMigrate(args[1:])
	}
	opts, err := parseImageArgs(args, os.Stderr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	// ls and df read the cluster's registry, not this node's daemon, so they
	// dial no socket and need no root.
	if opts.subcommand == "ls" || opts.subcommand == "df" {
		env, err := newImageRegistryEnv()
		if err != nil {
			return err
		}
		return imageRegistryCommand(ctx, opts, os.Stdout, env)
	}
	return imageCommand(ctx, opts, os.Stdout, dialRuntimed)
}

// parseImageArgs parses argv. ContinueOnError so a bad flag is an error the
// caller reports, never an os.Exit inside a test binary.
func parseImageArgs(args []string, errOut io.Writer) (imageOptions, error) {
	o := imageOptions{warn: errOut}
	fs := flag.NewFlagSet("image", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		fmt.Fprint(errOut, imageUsage)
		fs.PrintDefaults()
	}
	fs.StringVar(&o.socket, "socket", runtimed.DefaultSocketPath, "runtimed control socket to dial")
	// The control-plane state root, consulted by the verbs that talk to the
	// cluster registry (push, load, import, tag, untag, inspect, save, prune, and
	// pull's copy into the cluster registry) to find this node's registry
	// credential and, for prune, its store. A resolve failure is not reported
	// here: ls and df find the registry through the cluster API and have no use
	// for a work dir, so an unresolvable one must not make `k3sm image ls` fail.
	defaultWorkDir, _ := executor.ResolveWorkDir()
	fs.StringVar(&o.workDir, "work-dir", defaultWorkDir, "control-plane state root to read this node's registry push credential and store from (push, pull, load, import, tag, untag, inspect, save, prune)")
	// DRY RUN IS THE DEFAULT and deleting takes an explicit flag, because the
	// blast radius is asymmetric: a needless dry run costs a statfs, while an
	// unintended prune on a node that cannot reach its registry costs every image
	// it cannot re-pull.
	fs.BoolVar(&o.force, "force", false, "prune: actually delete (without this, prune only reports what it would delete); tag: re-point a tag that names another manifest")
	fs.StringVar(&o.reference, "reference", "", "reference to record a loaded image under (load, import; defaults to the one the archive names)")
	// The platform is part of the store's (reference x platform) KEY, never a
	// filter, so it is spelled the way an OCI platform is spelled everywhere
	// else — os/arch[/variant] — rather than as three flags nobody would pair
	// correctly.
	var platformSpec, policySpec string
	fs.StringVar(&platformSpec, "platform", "", "os/arch[/variant] this verb acts on, e.g. darwin/arm64 (pull; tag, inspect, save: one platform of an index)")
	fs.StringVar(&policySpec, "policy", "", "pull policy: always, if-not-present or never (pull only; default is the pull-through behaviour)")
	fs.BoolVar(&o.noMirror, "no-mirror", false, "pull: do not copy a public image into the cluster registry")
	fs.StringVar(&o.digest, "digest", "", "refuse the removal unless the name still resolves to this manifest digest (untag only)")
	// One flag, several meanings, chosen by the subcommand — the spelling `docker`
	// uses for both. It is validated per subcommand at parse time so `inspect -o
	// out.tar` fails before anything is dialled.
	fs.StringVar(&o.output, "o", "", "save: the file to write the archive to; inspect: json, for the registry's documents instead of the table; prune: json, for one document with both halves; ls, df: json")
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
			return o, errors.New("push requires a source (an OCI layout directory, or a reference in this node's store or the cluster registry) and the registry reference to push it to")
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
	platformVerbs := map[string]bool{"pull": true, "tag": true, "inspect": true, "save": true}
	if flagWasSet(fs, "platform") && !platformVerbs[o.subcommand] {
		return o, fmt.Errorf("%s does not take --platform (it selects the platform pull fetches, or the child of an index tag, inspect and save act on; a tag names the whole index, so untag takes none)", o.subcommand)
	}
	if o.force && o.subcommand != "prune" && o.subcommand != "tag" {
		return o, fmt.Errorf("%s does not take --force (it unlinks for prune and re-points a tag for tag)", o.subcommand)
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
	if flagWasSet(fs, "socket") && (o.subcommand == "ls" || o.subcommand == "df") {
		return o, fmt.Errorf("%s does not take --socket (it reads the cluster's registry, not this node's daemon)", o.subcommand)
	}
	if o.noMirror && o.subcommand != "pull" {
		return o, fmt.Errorf("%s does not take --no-mirror (it skips the cluster-registry copy pull writes of a public image)", o.subcommand)
	}
	if flagWasSet(fs, "digest") && o.subcommand != "untag" {
		return o, fmt.Errorf("%s does not take --digest (it pins the entry untag is allowed to remove)", o.subcommand)
	}
	switch o.subcommand {
	case "save":
		if o.output == "" {
			return o, errors.New("save requires -o <file.tar>: the archive is written to a file you name, never to the terminal")
		}
	case "ls":
		if o.output != "" && o.output != "json" && o.output != "ndjson" {
			return o, fmt.Errorf("-o %q: ls renders a table by default, `json` or `ndjson` (one JSON line per image as it is read) on request", o.output)
		}
	case "inspect", "prune", "df":
		if o.output != "" && o.output != "json" {
			return o, fmt.Errorf("-o %q: %s renders a table by default and `json` on request", o.output, o.subcommand)
		}
	default:
		if flagWasSet(fs, "o") || flagWasSet(fs, "output") {
			return o, fmt.Errorf("%s does not take -o (save writes an archive to it; inspect, prune, ls and df choose a rendering with it)", o.subcommand)
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
	return imageCommandWith(ctx, o, out, dial, deleteManifest)
}

// imageCommandWith is imageCommand with the registry's manifest deleter as a
// seam, which only prune uses.
func imageCommandWith(ctx context.Context, o imageOptions, out io.Writer, dial imagesDialer, del manifestDeleter) error {
	// push is the one subcommand whose ordinary form is not a daemon client: it
	// reads a layout the invoking user owns and uploads it to a registry as that
	// user. Dialing first would fail a perfectly valid push on a node whose
	// daemon is down, so push takes the dialer and uses it only for the store-ref
	// form, which genuinely has to ask the daemon for the bytes.
	if o.subcommand == "push" {
		return imagePush(ctx, o, out, dial)
	}
	// load and import upload to the cluster registry as the invoking user, and
	// dial the daemon only for the warm pull that follows.
	switch o.subcommand {
	case "load":
		return imageIngest(ctx, o, out, ingestPusher, warmNodeCache(dial, o.socket), runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE)
	case "import":
		return imageIngest(ctx, o, out, ingestPusher, warmNodeCache(dial, o.socket), runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT)
	}
	// tag, untag, inspect and save act on the cluster registry and never dial
	// the daemon: the node's store is a pull cache no user verb names.
	switch o.subcommand {
	case "tag":
		return imageTag(ctx, o, out)
	case "untag":
		return imageUntag(ctx, o, out)
	case "inspect":
		return imageInspect(ctx, o, out)
	case "save":
		return imageSave(ctx, o, out)
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
	case "pull":
		img, err := imagePull(ctx, client, o, out)
		if err != nil {
			return err
		}
		if !o.noMirror {
			warn := o.warn
			if warn == nil {
				warn = io.Discard
			}
			mirrorPulled(ctx, o, img, out, warn, pullMirrorer)
		}
		return nil
	case "prune":
		return imagePrune(ctx, client, o, out, del, time.Now())
	}
	return fmt.Errorf("unknown subcommand %q", o.subcommand)
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

// imageRPCError translates a daemon status into an operator-actionable message.
func imageRPCError(what, socket string, err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%s: %w", what, err)
	}
	switch st.Code() {
	case codes.NotFound:
		return notInNodeStore{fmt.Errorf("%s: %s", what, st.Message())}
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

// errNotInNodeStore matches a daemon answer that this node's store holds no
// image under the name asked for (gRPC NOT_FOUND). push reads it as the cue to
// look in the cluster registry.
var errNotInNodeStore = errors.New("not in this node's store")

// notInNodeStore carries the daemon's own not-found text and matches
// errNotInNodeStore, so the message an operator reads is unchanged.
type notInNodeStore struct{ error }

// Is matches errNotInNodeStore.
func (notInNodeStore) Is(target error) bool { return target == errNotInNodeStore }

// Unwrap returns the daemon's error.
func (e notInNodeStore) Unwrap() error { return e.error }

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
