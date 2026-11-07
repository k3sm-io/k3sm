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
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/modelpack"
	"k3sm.io/k3sm/pkg/registryclient"
)

// modelRepositoryPrefix is where every model lives in the cluster registry.
const modelRepositoryPrefix = "models/"

// modelUsage is `k3sm model`'s help.
const modelUsage = `Usage: k3sm model <push|ls|rm> [flags] <args>

Store models in the cluster registry as ModelPack OCI artifacts, under
registry-k3sm:6450/models/<name>.

  push <dir> <name>[:tag]
        build a ModelPack artifact from the files in <dir> (one raw layer per
        file; split safetensors and split GGUF sets as one layer per split)
        and push it as models/<name>:<tag> (tag defaults to latest), then
        print its manifest digest. Code and pickle files (.py, .pyc, .bin,
        .pt, .pth, .pkl, .pickle, .ckpt, .so, .dylib), symbolic links, and
        paths outside [A-Za-z0-9._-/] or that collide by case are refused by
        name before any file is read. The same files always make the same
        digest, and a blob the registry already holds is not uploaded again.
        Writes as 'k3sm image push' does: the server's push credential when
        this account can read it, else a builder token through your
        kubeconfig.
  ls [-o json]
        list the models in the cluster registry: every tag under models/
        whose manifest is a ModelPack artifact, with its weight format,
        quantization and parameter size (copied from the model's
        config.json at push, when it records them), total size, file count
        and weight shard count. Reads each model's manifest and config,
        never its files, over your own credentials. -o json writes a
        versioned document instead of the table.
  rm <name>[:tag]
        remove the tag models/<name>:<tag> (tag defaults to latest). It
        removes a name, not bytes: the registry reclaims content no tag names
        at its next garbage collection. Needs the server's push credential
        (run on the server as root), because the push gate never forwards a
        delete.

Flags (before the arguments):
`

// modelOptions is one parsed `k3sm model` invocation.
type modelOptions struct {
	verb    string
	dir     string
	name    string
	workDir string
	timeout time.Duration
	// output is ls's -o: "" for the table, or json.
	output string
}

// runModel runs `k3sm model`.
func runModel(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(os.Stdout, modelUsage)
		return nil
	}
	o, err := parseModelArgs(args, os.Stderr)
	if err != nil {
		return err
	}
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := sigCtx, context.CancelFunc(func() {})
	if o.timeout > 0 {
		ctx, cancel = context.WithTimeout(sigCtx, o.timeout)
	}
	defer cancel()
	return modelCommand(ctx, o, os.Stdout)
}

// parseModelArgs parses `k3sm model <verb> [flags] <args>`. ContinueOnError so
// a bad flag is an error the caller reports, never an os.Exit in a test.
func parseModelArgs(args []string, errOut io.Writer) (modelOptions, error) {
	if len(args) == 0 {
		return modelOptions{}, errors.New("model: name a verb (push, ls or rm)")
	}
	o := modelOptions{verb: args[0]}
	var want int
	switch o.verb {
	case "push":
		want = 2
	case "rm":
		want = 1
	case "ls":
		want = 0
	default:
		return modelOptions{}, fmt.Errorf("unknown model verb %q (want push, ls or rm)", o.verb)
	}
	fs := flag.NewFlagSet("model "+o.verb, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		fmt.Fprint(errOut, modelUsage)
		fs.PrintDefaults()
	}
	defaultWorkDir, _ := executor.ResolveWorkDir()
	fs.StringVar(&o.workDir, "work-dir", defaultWorkDir, "control-plane state root to read this node's registry push credential from")
	defaultTimeout := time.Duration(0)
	if o.verb == "rm" || o.verb == "ls" {
		defaultTimeout = metadataTimeout
	}
	if o.verb == "ls" {
		fs.StringVar(&o.output, "o", "", "json, for a versioned document instead of the table")
		fs.StringVar(&o.output, "output", "", "alias for -o")
	}
	fs.DurationVar(&o.timeout, "timeout", defaultTimeout, "overall deadline; push has none by default, and abandons a request only when it moves no byte for "+requestIdleTimeout.String())
	if err := fs.Parse(args[1:]); err != nil {
		return modelOptions{}, err
	}
	if fs.NArg() != want {
		return modelOptions{}, fmt.Errorf("model %s takes %d argument(s), got %q", o.verb, want, fs.Args())
	}
	if o.output != "" && o.output != "json" {
		return modelOptions{}, fmt.Errorf("-o %q: ls renders a table by default and `json` on request", o.output)
	}
	switch o.verb {
	case "push":
		o.dir, o.name = fs.Arg(0), fs.Arg(1)
	case "rm":
		o.name = fs.Arg(0)
	}
	return o, nil
}

// modelCommand runs one parsed invocation.
func modelCommand(ctx context.Context, o modelOptions, out io.Writer) error {
	switch o.verb {
	case "push":
		return modelPush(withRequestIdle(ctx, requestIdleTimeout), o, out)
	case "rm":
		return modelRm(ctx, o, out)
	case "ls":
		env, err := newImageRegistryEnv()
		if err != nil {
			return err
		}
		return modelLs(ctx, o, out, env)
	}
	return fmt.Errorf("unknown model verb %q", o.verb)
}

// modelReference is the cluster-registry name of model name[:tag]: the
// repository under models/ (a leading models/ is accepted and not doubled),
// tag latest when none is given. A registry host or a digest is refused: a
// model is pushed and removed by tag, in the cluster registry alone.
func modelReference(s string) (clusterImage, error) {
	if strings.Contains(s, "@") {
		return clusterImage{}, fmt.Errorf("model %q: name a tag, not a digest", s)
	}
	if first, rest, ok := strings.Cut(s, "/"); ok && rest != "" && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return clusterImage{}, fmt.Errorf("model %q: %q names a registry; a model lives in the cluster registry, so name it as <name>[:tag]", s, first)
	}
	repo, tag := s, "latest"
	if i := strings.LastIndex(s, ":"); i >= 0 {
		repo, tag = s[:i], s[i+1:]
	}
	repo = modelRepositoryPrefix + strings.TrimPrefix(repo, modelRepositoryPrefix)
	if repo == modelRepositoryPrefix || !registryclient.ValidRepository(repo) {
		return clusterImage{}, fmt.Errorf("model %q: %q is not a repository name (lowercase [a-z0-9] parts joined by . _ - and /)", s, repo)
	}
	if !registryclient.ValidTag(tag) {
		return clusterImage{}, fmt.Errorf("model %q: %q is not a tag", s, tag)
	}
	return clusterImageAt(repo, tag)
}

// modelPush builds the artifact for o.dir and pushes it as o.name.
//
// The directory is read, validated and hashed BEFORE the registry is
// contacted, so a refused file costs no token and no request. Each blob is
// uploaded only when the repository lacks it (go-containerregistry HEADs it
// first), and each is re-verified as it is read, so the bytes sent are the
// bytes the manifest names. The manifest goes last, so a tag never names a
// manifest whose blobs are not all there.
func modelPush(ctx context.Context, o modelOptions, out io.Writer) error {
	ref, err := modelReference(o.name)
	if err != nil {
		return err
	}
	a, err := modelpack.Build(ctx, o.dir)
	if err != nil {
		return err
	}
	acc, err := registryWriteAccess(ctx, o.workDir)
	if err != nil {
		return fmt.Errorf("push %s: %w", ref.flat, err)
	}
	if ref, err = acc.locate(ref); err != nil {
		return err
	}
	repo := ref.remote.Context()
	blobs := []modelBlob{{desc: a.ConfigDescriptor, open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(a.Config)), nil
	}}}
	for _, l := range a.Layers {
		blobs = append(blobs, modelBlob{desc: l.Descriptor, open: func() (io.ReadCloser, error) { return a.Open(l) }})
	}
	for _, b := range blobs {
		if err := remote.WriteLayer(repo, b, acc.opts...); err != nil {
			return registryError("push "+ref.flat.String()+": upload "+b.desc.Digest.String(), err)
		}
	}
	if err := remote.Put(ref.remote, rawManifest{body: a.Manifest, mediaType: ispec.MediaTypeImageManifest}, acc.opts...); err != nil {
		return registryError("push "+ref.flat.String(), err)
	}
	fmt.Fprintf(out, "pushed %s (%d files)\n  digest: %s\n  pin:    %s@%s\n", ref.flat, len(a.Layers), a.Digest, ref.flat.Context().Name(), a.Digest)
	return nil
}

// modelRm removes the tag o.name names, as `k3sm image untag` does: a name,
// not bytes, and only with the server's push credential.
func modelRm(ctx context.Context, o modelOptions, out io.Writer) error {
	ref, err := modelReference(o.name)
	if err != nil {
		return err
	}
	acc, err := registryDeleteAccess(ctx, o.workDir)
	if err != nil {
		return fmt.Errorf("rm %s: %w", ref.flat, err)
	}
	if ref, err = acc.locate(ref); err != nil {
		return err
	}
	desc, err := remote.Head(ref.remote, acc.opts...)
	if err != nil {
		return registryError("rm "+ref.flat.String(), err)
	}
	if err := remote.Delete(ref.remote, acc.opts...); err != nil {
		return registryError("rm "+ref.flat.String(), err)
	}
	fmt.Fprintf(out, "removed %s\n  digest: %s\n", ref.flat, desc.Digest)
	fmt.Fprintln(out, "(the registry reclaims content no tag names at its next garbage collection)")
	return nil
}

// modelBlob is one blob of a model artifact as go-containerregistry uploads
// it: raw, so its compressed and uncompressed forms are the same bytes.
type modelBlob struct {
	desc ispec.Descriptor
	open func() (io.ReadCloser, error)
}

func (b modelBlob) Digest() (ggcrv1.Hash, error)         { return ggcrv1.NewHash(b.desc.Digest.String()) }
func (b modelBlob) DiffID() (ggcrv1.Hash, error)         { return b.Digest() }
func (b modelBlob) Compressed() (io.ReadCloser, error)   { return b.open() }
func (b modelBlob) Uncompressed() (io.ReadCloser, error) { return b.open() }
func (b modelBlob) Size() (int64, error)                 { return b.desc.Size, nil }
func (b modelBlob) MediaType() (types.MediaType, error) {
	return types.MediaType(b.desc.MediaType), nil
}

// rawManifest is manifest bytes remote.Put sends verbatim under mediaType.
type rawManifest struct {
	body      []byte
	mediaType string
}

func (m rawManifest) RawManifest() ([]byte, error)        { return m.body, nil }
func (m rawManifest) MediaType() (types.MediaType, error) { return types.MediaType(m.mediaType), nil }
