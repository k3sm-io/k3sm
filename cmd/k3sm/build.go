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

	"k3sm.io/k3sm/pkg/oci"
)

const buildUsage = `k3sm build — package a native darwin/arm64 image from a COPY-only Dockerfile

Usage: k3sm build --tag <ref> --output <path> [flags] <context-dir>

Accepted Dockerfile subset: FROM scratch, COPY, ADD, ENV, ENTRYPOINT, CMD,
WORKDIR, LABEL, EXPOSE. RUN is rejected — this builder packages files, it does
not execute them.

The output is a portable image artifact. k3sm cannot yet RUN an image it built:
the ingest and materialize path is still on the roadmap, so an "image: <ref>"
Pod spec will not resolve to it. See docs/user/images.md.

Flags:
`

// buildOptions is the parsed argv, kept separate from execution so the gate can
// drive parsing and execution independently.
type buildOptions struct {
	dockerfile string
	tag        string
	output     string
	format     string
	platform   string
	contextDir string
}

// runBuild is the `k3sm build` entry point.
func runBuild(args []string) error {
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
	fs.StringVar(&o.tag, "tag", "", "image reference to assign, e.g. myapp:v1 (required)")
	fs.StringVar(&o.output, "output", "", "path to write the image to (required)")
	fs.StringVar(&o.format, "format", "docker", "output format: docker (a `docker load` tarball) or oci (an OCI layout dir)")
	fs.StringVar(&o.platform, "platform", oci.DefaultPlatform, "target platform (only "+oci.DefaultPlatform+" is supported)")
	if err := fs.Parse(args); err != nil {
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

	if o.tag == "" {
		return o, errors.New("--tag is required")
	}
	// There is no default output: with the shared local store deliberately out of
	// scope there is no safe implicit sink, and a build that assembles an image
	// and then discards it while exiting 0 is indistinguishable from success.
	if o.output == "" {
		return o, errors.New("--output is required (this builder has no default sink)")
	}
	if o.format != "docker" && o.format != "oci" {
		return o, fmt.Errorf("--format %q: want \"docker\" or \"oci\"", o.format)
	}
	if o.dockerfile == "" {
		o.dockerfile = filepath.Join(o.contextDir, "Dockerfile")
	}
	return o, nil
}

// build parses, assembles and writes. Parsing completes before the output is
// opened, so a Dockerfile rejected on its last line leaves no artifact behind.
func build(ctx context.Context, o buildOptions, out io.Writer) error {
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
		return err
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

	img, err := oci.Build(oci.Request{Dockerfile: df, Context: bc, Platform: o.platform, TmpDir: tmp})
	if err != nil {
		return err
	}

	var sink oci.Sink = oci.TarballSink{Path: o.output}
	if o.format == "oci" {
		sink = oci.LayoutSink{Path: o.output}
	}
	if err := sink.Write(ctx, ref, img); err != nil {
		return err
	}

	digest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("compute digest: %w", err)
	}
	fmt.Fprintf(out, "built %s\n  digest: %s\n  output: %s (%s)\n", ref, digest, o.output, o.format)
	return nil
}
