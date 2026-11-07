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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/modelpack"
	"k3sm.io/k3sm/pkg/modelpack/hf"
	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/version"
)

// modelRepositoryPrefix is where every model lives in the cluster registry.
const modelRepositoryPrefix = "models/"

// modelUsage is `k3sm model`'s help.
const modelUsage = `Usage: k3sm model <push|import|ls|rm> [flags] <args>

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
  import hf://<org>/<repo>[@<revision>] [<name>[:tag]]
        import a Hugging Face model repository at a pinned commit and push
        it as models/<name>:<tag> (name defaults to <org>/<repo> lowercased,
        tag to latest). A branch or tag revision (default main) is resolved
        to its 40-hex commit first, and every file is fetched at that commit.
        Every name is checked as push checks it before any byte is fetched,
        then each file is downloaded to a scratch directory (resumed with a
        Range request if a transfer breaks) and verified before anything is
        pushed: an LFS file by the sha256 the Hub lists, which becomes its
        layer digest, a small file by its git blob id. The manifest records
        the source (hf://<org>/<repo>) and the commit, so importing the same
        commit again uploads nothing and prints the same digest. Access is
        anonymous: a gated repository is refused. The Hub's hashes catch
        corruption in transit, not a compromised Hub; pass --sha256 for a
        file whose hash you know from elsewhere (each fetched line prints
        the --sha256 that pins that file next time). Files are downloaded into
        a k3sm-hf-import-* directory under --scratch-dir, removed when the
        import ends or is interrupted; a later import sweeps one a killed
        process left behind after 24 hours without change.
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

	// import only
	source     hf.Ref
	sha256     map[string]string
	scratchDir string
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
		return modelOptions{}, errors.New("model: name a verb (push, import, ls or rm)")
	}
	o := modelOptions{verb: args[0]}
	var want, most int
	switch o.verb {
	case "push":
		want, most = 2, 2
	case "import":
		want, most = 1, 2
	case "rm":
		want, most = 1, 1
	case "ls":
		want, most = 0, 0
	default:
		return modelOptions{}, fmt.Errorf("unknown model verb %q (want push, import, ls or rm)", o.verb)
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
	if o.verb == "import" {
		fs.StringVar(&o.scratchDir, "scratch-dir", "", "directory to download into before the push (a fresh subdirectory, removed afterwards); default the system temporary directory")
		fs.Func("sha256", "<path>=<sha256 hex>: a file's sha256 known from elsewhere, checked as well as the Hub's hash (repeatable)", func(v string) error {
			p, sum, ok := strings.Cut(v, "=")
			if !ok || p == "" || sum == "" {
				return fmt.Errorf("want <path>=<sha256 hex>, got %q", v)
			}
			if o.sha256 == nil {
				o.sha256 = map[string]string{}
			}
			if _, dup := o.sha256[p]; dup {
				return fmt.Errorf("%s named twice", p)
			}
			o.sha256[p] = strings.ToLower(sum)
			return nil
		})
	}
	if err := fs.Parse(args[1:]); err != nil {
		return modelOptions{}, err
	}
	if fs.NArg() < want || fs.NArg() > most {
		n := strconv.Itoa(want)
		if most != want {
			n += " or " + strconv.Itoa(most)
		}
		return modelOptions{}, fmt.Errorf("model %s takes %s argument(s), got %q", o.verb, n, fs.Args())
	}
	if o.output != "" && o.output != "json" {
		return modelOptions{}, fmt.Errorf("-o %q: ls renders a table by default and `json` on request", o.output)
	}
	switch o.verb {
	case "push":
		o.dir, o.name = fs.Arg(0), fs.Arg(1)
	case "import":
		src, err := hf.ParseRef(fs.Arg(0))
		if err != nil {
			return modelOptions{}, err
		}
		o.source, o.name = src, strings.ToLower(src.Repo)
		if fs.NArg() == 2 {
			o.name = fs.Arg(1)
		}
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
	case "import":
		return modelImport(withRequestIdle(ctx, requestIdleTimeout), o, out)
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
	return pushModel(ctx, o.workDir, ref, a, out)
}

// pushModel pushes the built artifact a as ref, through the push gate with
// the credential `k3sm image push` uses, and prints its digest. The caller
// has built and verified a before the registry is contacted.
func pushModel(ctx context.Context, workDir string, ref clusterImage, a *modelpack.Artifact, out io.Writer) error {
	acc, err := registryWriteAccess(ctx, workDir)
	if err != nil {
		return fmt.Errorf("push %s: %w", ref.flat, err)
	}
	if ref, err = acc.locate(ref); err != nil {
		return err
	}
	if err := modelpack.Push(ctx, ref.remote, a, acc.opts...); err != nil {
		if be, ok := errors.AsType[*modelpack.BlobError](err); ok {
			return registryError("push "+ref.flat.String()+": upload "+be.Digest, be.Err)
		}
		return registryError("push "+ref.flat.String(), errors.Unwrap(err))
	}
	fmt.Fprintf(out, "pushed %s (%d files)\n  digest: %s\n  pin:    %s@%s\n", ref.flat, len(a.Layers), a.Digest, ref.flat.Context().Name(), a.Digest)
	return nil
}

// hubOptions configures the Hub client `model import` uses; a test points
// it at an in-process Hub. Every request is abandoned when it moves no byte
// for the context's idle window, on top of the client's own connect, TLS
// and header timeouts.
var hubOptions = func() hf.Options {
	return hf.Options{Transport: boundRequests(hf.DefaultTransport()), UserAgent: "k3sm/" + version.Version}
}

// modelImport imports o.source at a pinned commit and pushes it as o.name.
//
// The name is checked first, so a bad one costs no download. The Hub
// client verifies every file before it calls the push, which is
// `model push`'s own: the push gate, the same credential, a blob uploaded
// only when the registry lacks it, and the manifest last.
func modelImport(ctx context.Context, o modelOptions, out io.Writer) error {
	ref, err := modelReference(o.name)
	if err != nil {
		return fmt.Errorf("%w (name the model: k3sm model import %s <name>[:tag])", err, o.source)
	}
	c, err := hf.NewClient(hubOptions())
	if err != nil {
		return err
	}
	res, err := c.Import(ctx, o.source, hf.ImportOptions{
		ScratchDir: o.scratchDir,
		SHA256:     o.sha256,
		Note:       func(msg string) { fmt.Fprintln(out, msg) },
		Fetched: func(p string, size int64, sum string) {
			fmt.Fprintf(out, "fetched %s (%d bytes, verified)\n  pin: --sha256 %s=%s\n", p, size, p, sum)
		},
		Push: func(ctx context.Context, a *modelpack.Artifact) error {
			return pushModel(ctx, o.workDir, ref, a, out)
		},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "imported %s%s@%s (%d bytes fetched)\n", hf.Scheme, o.source.Repo, res.Commit, res.Bytes)
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
