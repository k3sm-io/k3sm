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
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/k3sm/pkg/buildledger"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/oci"
)

const buildUsage = `k3sm build — build an image from a Dockerfile

Usage: k3sm build --tag <ref> [--output <path>] [flags] <context-dir>
       k3sm build ls [-o text|json]
       k3sm build cancel <id>
       k3sm build rm <id>
       k3sm build logs [-f] <id>
       k3sm build prune [--all] [--force]

ONE command, two engines, chosen from the Dockerfile:

  COPY-only (FROM, COPY, ADD, ENV, ENTRYPOINT, CMD, WORKDIR, LABEL, EXPOSE)
  packages NATIVELY — no daemon, no cluster, a darwin/arm64 image. FROM takes
  "scratch" or a registry reference; a named base is fetched for darwin/arm64
  and refused if it declares another platform.

  Anything the native builder cannot express — RUN above all, and multi-stage
  builds, ARG, USER and the rest of the full Dockerfile — routes to the k3sm
  build engine (BuildKit in a Linux micro-VM) and produces a linux image. The
  engine is started on first use; "k3sm builder status" shows it and
  "k3sm builder down" stops it.

Either way the image is RECORDED IN THE CLUSTER REGISTRY, the cluster's one
image store, as registry-k3sm:6450/<repository>:<tag>, ready for a Pod on any
node to name, and this node's cache is warmed with it, so imagePullPolicy Never
works here too. What you do next does not depend on which engine built it.
--output additionally writes a portable artifact you can carry elsewhere
("docker" tarball, or "oci" for a layout directory). A tag that names the
cluster registry (bare, registry-k3sm:6450, or localhost:<port>) is recorded
there. A tag that names any other registry is refused unless --push sends it
to that registry, and then it goes there only: the cluster registry keeps no
copy under another registry's name.

  k3sm build -t myapp:v1 .                       # registry-k3sm:6450/myapp:v1
  k3sm build -t myapp:v1 --output myapp.tar .    # and a file to carry
  k3sm build -t ghcr.io/org/myapp:v1 --push .    # to that registry only

--no-record skips the recording: the build writes --output and/or uploads
--push and never talks to this node's runtime daemon, the way "buildctl
--output type=oci" builds without a containerd. It needs no root, so it is the
mode for a build run as an ordinary user. At least one of --output and --push
is required with it. Recording the result is then a separate root step:

  k3sm build -t myapp:v1 --no-record --output myapp.tar .
  sudo k3sm image load myapp.tar                 # the registry, when you want it

--platform names the target. Unset builds darwin/arm64 natively, or a Linux
image when the Dockerfile needs the engine. An EXPLICIT Linux target always
builds on the engine, so a COPY-only Dockerfile can produce a Linux image too:

  k3sm build -t myapp:v1 --platform linux/arm64 .
  k3sm build -t myapp:v1 --platform linux/arm64,linux/amd64 --format oci --output out .

Several platforms at once produce an index. The cluster registry, --output (as
"oci") and --push carry every one of them; this node's cache holds the platform
this node's Linux guests run, and the summary says so. The
engine's guest is arm64 and registers no emulator, so RUN steps for another
architecture are refused by name — COPY a cross-compiled binary in instead.

The built image RUNS. Name it in a Pod — from a manifest, not "kubectl run",
which cannot declare the darwin nodeSelector and provider toleration every
k3sm Pod requires (a ValidatingAdmissionPolicy refuses a Pod without them):

  k3sm build --tag myapp:v1 .
  kubectl apply -f pod.yaml                      # already in the cluster registry

See docs/user/what-runs.md for a copy-pasteable manifest.

Every build is kept in your build history, the newest 200 of them:

  k3sm build ls                                  # a table, newest first
  k3sm build ls -o json                          # the records as JSON
  k3sm build logs -f <id>                        # a build's output, followed
  k3sm build cancel <id>                         # stop a running build
  k3sm build rm <id>                             # drop a record and its log
  k3sm build prune [--all] --force               # reclaim the engine's cache

Pin FROM to a digest (name@sha256:…) if you want a reproducible build: a tag can
move under you. See docs/user/what-runs.md for the whole path, and
docs/user/images.md for the reference.

Flags:
`

// buildOptions is the parsed argv, kept separate from execution so the gate can
// drive parsing and execution independently.
type buildOptions struct {
	dockerfile string
	tag        string
	output     string
	// push uploads the built image to the registry a foreign tag names, the
	// only delivery such a tag gets. On a tag naming the cluster registry the
	// recording is already that upload, so push adds nothing.
	push bool
	// noRecord skips the store recording: the build delivers only to --output
	// and/or --push and never dials the runtime daemon, so an unprivileged user
	// who cannot reach its socket can still build. parseBuildArgs refuses it
	// without one of those sinks, because the build would then go nowhere.
	noRecord bool
	format   string
	// platforms is the parsed --platform list: one target, or several for a
	// multi-platform build. It is never empty — an argv that named no platform
	// carries the native path's default.
	platforms  []string
	contextDir string
	// platformSet records whether --platform was given. The engine path builds
	// Linux images, so it must tell "the operator asked for darwin/arm64" (a
	// native-only target, and an error) from "nobody asked" (the default, which
	// the engine reads as its own guest platform).
	platformSet bool
}

// runBuild is the `k3sm build` entry point.
func runBuild(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "ls":
			return runBuildLs(args[1:], os.Stdout)
		case "cancel", "rm", "logs", "prune":
			return runBuildManage(args[0], args[1:])
		}
	}
	opts, err := parseBuildArgs(args, os.Stderr)
	if err != nil {
		return err
	}
	return build(context.Background(), opts, os.Stdout)
}

// parseBuildArgs parses argv. It uses ContinueOnError so a bad flag is an error
// the caller reports, never an os.Exit inside a test binary.
func parseBuildArgs(args []string, errOut io.Writer) (buildOptions, error) {
	var o buildOptions
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		fmt.Fprint(errOut, buildUsage)
		fs.PrintDefaults()
	}
	fs.StringVar(&o.dockerfile, "file", "", "path to the Dockerfile (default <context>/Dockerfile)")
	fs.StringVar(&o.dockerfile, "f", "", "short form of --file")
	fs.StringVar(&o.tag, "tag", "", "image reference to assign, e.g. myapp:v1 (required)")
	fs.StringVar(&o.tag, "t", "", "short form of --tag")
	fs.StringVar(&o.output, "output", "", "additionally write the image to this path (the cluster registry recording still happens unless --no-record is set)")
	fs.BoolVar(&o.push, "push", false, "upload the image to the registry the tag names; required for a tag naming a registry other than the cluster registry, which is then not recorded")
	fs.BoolVar(&o.noRecord, "no-record", false, "do not record the image in the cluster registry (never dials the runtime daemon, needs no root); requires --output or --push")
	fs.StringVar(&o.format, "format", "docker", "output format: docker (a `docker load` tarball) or oci (an OCI layout dir)")
	var platformSpec string
	fs.StringVar(&platformSpec, "platform", oci.DefaultPlatform, "target platform, or several separated by commas: "+oci.DefaultPlatform+" (native) or "+enginePlatform+" and friends (the build engine)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	o.platformSet = flagWasSet(fs, "platform")
	var err error
	if o.platforms, err = parsePlatforms(platformSpec); err != nil {
		return o, err
	}

	// stdlib flag stops at the first non-flag argument, so "k3sm build . --tag x"
	// would silently leave --tag unparsed and build an untagged image. That
	// ordering is half of Docker's own documentation, so refuse it explicitly
	// rather than succeeding with the wrong result.
	rest := fs.Args()
	for _, a := range rest[min(1, len(rest)):] {
		if strings.HasPrefix(a, "-") {
			return o, fmt.Errorf("flag %q must come before the context directory", a)
		}
	}
	if len(rest) != 1 {
		return o, errors.New("exactly one build-context directory is required")
	}
	o.contextDir = rest[0]

	// --tag is required with or without --output: it names the image the build
	// delivers (the cluster-registry entry, unless --no-record, and the --output
	// and --push targets), and an unnamed image is one nothing can select.
	if o.tag == "" {
		return o, errors.New("--tag is required")
	}
	// --no-record removes the one sink every other build has, so a build with
	// neither --output nor --push would produce an image and then discard it.
	// That is refused before any work starts rather than reported as a success.
	if o.noRecord && o.output == "" && !o.push {
		return o, errors.New("--no-record needs --output or --push: without the cluster registry the build has nowhere to deliver the image")
	}
	// A tag naming another registry is never recorded in the cluster registry,
	// so without --push (or --no-record) the build would have nowhere to put
	// it. That is refused before any work starts.
	if workDir := workDirFromEnv(); !o.push && !o.noRecord && tagIsForeign(o.tag, workDir) {
		_, err := registryReference(o.tag, workDir)
		return o, err
	}
	if o.format != "docker" && o.format != "oci" {
		return o, fmt.Errorf("--format %q: want \"docker\" or \"oci\"", o.format)
	}
	// A docker-save tarball holds ONE image. A multi-platform build produces an
	// index, so the combination is refused here rather than at the end of a build
	// that would then have to drop every platform but one.
	if len(o.platforms) > 1 && o.output != "" && o.format == "docker" {
		return o, fmt.Errorf("--format docker holds one image and --platform names %d; use --format oci, which carries them all", len(o.platforms))
	}
	if o.dockerfile == "" {
		o.dockerfile = filepath.Join(o.contextDir, "Dockerfile")
	}
	return o, nil
}

// engineBuilder builds a Dockerfile the native packager cannot express, through
// the in-cluster build engine. It is a seam so the ROUTING decision — which
// Dockerfiles go where — is provable without a cluster, a VM or a network.
type engineBuilder func(ctx context.Context, o buildOptions, out io.Writer) error

// build parses, assembles and writes, routing to the build engine when the
// Dockerfile needs one.
//
// Every build is entered in the user's build ledger (`k3sm build ls`): a
// running record before the build starts and the outcome when it returns. The
// ledger observes the build and never steers it, so a ledger that cannot be
// written costs a warning, not the build.
func build(ctx context.Context, o buildOptions, out io.Writer) error {
	return buildRecorded(ctx, defaultBuildLedger(), o, out, engineBuildWith, recordInRegistry(pushBuilt, defaultCacheWarmer(), os.Stderr), pushBuilt)
}

// buildRecorded is buildWith entered in the ledger l (nil records nothing).
// engineFor builds the engine seam over the recorder, so both routes deliver
// through the one recorder whose digest the ledger keeps.
func buildRecorded(ctx context.Context, l *buildledger.Ledger, o buildOptions, out io.Writer, engineFor func(storeRecorder) engineBuilder, record storeRecorder, push imagePusher) error {
	tr := startBuildRecord(l, o)
	if o.noRecord {
		// deliver already skips the recording under --no-record. This replaces
		// the seam as well, so a path that reached it anyway fails loudly instead
		// of contacting the registry the operator asked this build to leave alone.
		record = refuseRecord
	}
	record = tr.recorder(record)
	out = tr.tee(out)
	return tr.run(ctx, func(ctx context.Context) error {
		return buildWith(ctx, o, out, tr.engine(engineFor(record)), record, push)
	})
}

// buildWith is build with the engine seam injected.
//
// Parsing completes before the output is opened, so a Dockerfile rejected on its
// last line leaves no artifact behind — and the routing decision is taken from
// that same parse, so no Dockerfile is read twice or classified by a second,
// drifting reader.
func buildWith(ctx context.Context, o buildOptions, out io.Writer, engine engineBuilder, record storeRecorder, push imagePusher) error {
	ref, err := name.NewTag(o.tag)
	if err != nil {
		return fmt.Errorf("--tag %q: %w", o.tag, err)
	}

	f, err := os.Open(o.dockerfile)
	if err != nil {
		return fmt.Errorf("open Dockerfile: %w", err)
	}
	defer f.Close()
	df, err := oci.Parse(f)
	if err != nil {
		if !needsBuildEngine(err) {
			return err
		}
		// The one combination the engine provably cannot serve is refused here,
		// before it is started: minutes of boot and layer work ending in runc's
		// "exec format error" names neither the architecture nor the reason.
		if refusal := emulationRefusal(o, err); refusal != nil {
			return refusal
		}
		// The Dockerfile is valid Docker that this builder cannot express. That
		// is not a user error, so it is not reported as one: the engine builds
		// it. `k3sm build` is the one build command either way.
		return engine(ctx, o, out)
	}
	// The Dockerfile is within the native subset, but the native packager copies
	// host files into a DARWIN image and cannot produce a Linux one — so an
	// explicit Linux target is an engine build by definition, COPY-only or not.
	// The parse still happened first, so a malformed Dockerfile is still refused
	// natively rather than after an engine boot.
	if enginePlatformRequested(o) {
		return engine(ctx, o, out)
	}

	bc, err := oci.NewContext(o.contextDir)
	if err != nil {
		return err
	}

	tmp, err := os.MkdirTemp("", "k3sm-build-")
	if err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	baseRef, named := df.Base()
	img, err := oci.Build(oci.Request{
		Dockerfile: df, Context: bc, Platform: o.targets()[0], TmpDir: tmp,
		BaseResolver: remoteBase(ctx, localRegistryWorkDir()),
	})
	if err != nil {
		return err
	}

	if err := deliver(ctx, o, ref, built{image: img, platforms: o.targets(), storePlatform: o.targets()[0]}, out, record, push, "", ""); err != nil {
		return err
	}
	if named {
		// The base is reported because it decides whether this build is
		// reproducible. A DIGEST-pinned FROM is: the same context yields the same
		// image forever. A TAG-pinned one is not -- the tag can move under you,
		// and the only way to notice is to have been told what you actually got.
		fmt.Fprintf(out, "  base:   %s\n", baseRef)
		if !strings.Contains(baseRef, "@sha256:") {
			repo := strings.SplitN(baseRef, ":", 2)[0]
			fmt.Fprintf(out, "  note:   FROM names a tag, so this build is not reproducible; pin FROM %s@<digest> to make it so\n", repo)
		}
	}
	return nil
}

// localRegistryWorkDir resolves the control-plane state root the build's FROM
// resolution looks in for this node's ingest-registry credential. An
// unresolvable one yields "", which registryAuth reads as "there is no local
// registry credential" and falls through to the docker chain — `k3sm build` must
// not fail because a control plane it never talks to could not be located.
func localRegistryWorkDir() string {
	wd, err := executor.ResolveWorkDir()
	if err != nil {
		return ""
	}
	return wd
}

// remoteBase is the production BaseResolver: it fetches a named FROM base from a
// registry, for the platform this builder targets, using the same credential
// chain "k3sm image push" uses — including this node's own ingest registry, so
// `FROM localhost:<port>/…` resolves against an image pushed there. It is passed
// IN rather than reached for inside pkg/oci so the library keeps its "no I/O
// outside the build context" contract and its tests stay offline.
func remoteBase(ctx context.Context, workDir string) oci.BaseResolver {
	return func(ref string) (ggcrv1.Image, error) {
		r, err := name.ParseReference(ref)
		if err != nil {
			return nil, err
		}
		auth, err := registryAuth(r, workDir)
		if err != nil {
			return nil, err
		}
		return remote.Image(r,
			remote.WithContext(ctx),
			remote.WithAuth(auth),
			// Ask for this builder's platform. A single-manifest image ignores the
			// hint, which is why oci.Build re-checks the resolved config rather
			// than trusting the request.
			remote.WithPlatform(ggcrv1.Platform{OS: oci.PlatformOS, Architecture: oci.PlatformArch}),
		)
	}
}
