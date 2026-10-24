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
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// upstreamProbeTimeout bounds one "does the registry this reference names
// serve it" question. A registry that does not answer in time is treated as
// not serving it, and the image is migrated.
const upstreamProbeTimeout = 15 * time.Second

// runtimedMigrationSource is the production migrationSource: this node's
// runtimed, through ListImages and SaveImage only.
type runtimedMigrationSource struct {
	client runtimev1.ImagesClient
	socket string
}

// List returns every entry of the node store.
func (s runtimedMigrationSource) List(ctx context.Context) ([]storeEntry, error) {
	resp, err := s.client.ListImages(ctx, &runtimev1.ListImagesRequest{})
	if err != nil {
		return nil, imageRPCError("list images", s.socket, err)
	}
	if st := resp.GetError(); st != nil && st.GetCode() != 0 {
		return nil, fmt.Errorf("list images: %s", st.GetMessage())
	}
	out := make([]storeEntry, 0, len(resp.GetImages()))
	for _, img := range resp.GetImages() {
		m := img.GetManifest()
		out = append(out, storeEntry{
			Reference:   m.GetReference(),
			Platform:    platformText(m.GetPlatform()),
			Digest:      img.GetManifestDescriptor().GetDigest(),
			IndexDigest: m.GetIndexDigest(),
		})
	}
	return out, nil
}

// Export reads one entry back through SaveImage, by its digest, into a
// staging layout that cleanup removes. saveImageArchive verifies the export
// against the daemon's digest and byte count, and the migration re-checks the
// image's own digest before anything is uploaded.
func (s runtimedMigrationSource) Export(ctx context.Context, img storeEntry) (ggcrv1.Image, func(), error) {
	if img.Digest == "" {
		return nil, nil, errors.New("the store records no manifest digest for it (it predates manifest retention)")
	}
	tmp, err := os.MkdirTemp("", "k3sm-migrate")
	if err != nil {
		return nil, nil, fmt.Errorf("create a staging directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	archive := filepath.Join(tmp, "image.tar")
	if _, err := saveImageArchive(ctx, s.client, &runtimev1.SaveImageRequest{
		Digest: img.Digest,
		Format: runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
	}, archive, s.socket); err != nil {
		cleanup()
		return nil, nil, err
	}
	dir := filepath.Join(tmp, "layout")
	if err := extractOCILayout(archive, dir); err != nil {
		cleanup()
		return nil, nil, err
	}
	if err := os.Remove(archive); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("remove the staged archive: %w", err)
	}
	out, err := layoutImage(dir)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return out, cleanup, nil
}

// registryDigestAt is the production registryDigester: a manifest HEAD
// against this node's registry with its push credential.
func registryDigestAt(workDir string) registryDigester {
	return func(ctx context.Context, ref name.Tag) (string, bool, error) {
		auth, err := registryAuth(ref, workDir)
		if err != nil {
			return "", false, err
		}
		desc, err := remote.Head(ref, remote.WithContext(ctx), remote.WithAuth(auth))
		if err != nil {
			var terr *transport.Error
			if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
				return "", false, nil
			}
			return "", false, err
		}
		return desc.Digest.String(), true, nil
	}
}

// upstreamServesDigest is the production upstreamServes: an anonymous
// manifest HEAD against the registry the reference names. Anonymous on
// purpose: a public cache entry is what this recognises, and an image that
// needs a credential to re-pull is safer migrated.
func upstreamServesDigest(ctx context.Context, reference, digest string) bool {
	ref, err := name.ParseReference(reference)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, upstreamProbeTimeout)
	defer cancel()
	desc, err := remote.Head(ref, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))
	if err != nil {
		return false
	}
	return desc.Digest.String() == digest
}

// namesClusterRegistry reports whether a node-store reference already names
// the cluster registry: the flat registry-k3sm:6450 name or this node's
// registry by its loopback spelling. Such an entry is not a cache of another
// registry's image, so the migration never asks an upstream about it. A
// reference that is not a tag (a digest-only one) names no registry of ours.
func namesClusterRegistry(reference, workDir string) bool {
	probe, err := name.NewTag(reference, name.WithDefaultRegistry(""))
	return err == nil && isClusterRegistryHost(probe.RegistryStr(), workDir)
}

// newImageMigrator wires the production migrator for a work dir and a
// runtimed client.
func newImageMigrator(workDir string, client runtimev1.ImagesClient, socket string) imageMigrator {
	return imageMigrator{
		workDir:  workDir,
		source:   runtimedMigrationSource{client: client, socket: socket},
		digestAt: registryDigestAt(workDir),
		push:     pushBuilt,
		upstream: upstreamServesDigest,
		isLocal:  func(ref string) bool { return namesClusterRegistry(ref, workDir) },
		now:      time.Now,
	}
}

// imageMigrateOptions are the `k3sm image migrate` flags.
type imageMigrateOptions struct {
	socket  string
	workDir string
	report  bool
	output  string
	timeout time.Duration
}

// imageMigrateUsage is the verb's help text.
const imageMigrateUsage = `Usage: k3sm image migrate [--report] [-o json] [--work-dir DIR] [--socket PATH]

Copies every user image in this node's image store into the cluster registry,
once. The node store is never changed, so a rollback finds every image where
it was. A re-run skips what the registry already holds. A tag the registry
holds at another digest keeps the registry's image, and this node's copy is
pushed as <tag>-k3sm-migrated-<12hex>. An image the store cannot export stays
in the node store and runnable until it is loaded again. The server runs this
on its first start after an upgrade; run it by hand on an agent or to retry.

  --report  print the last run's report without running

`

// parseImageMigrateArgs parses `k3sm image migrate` argv.
func parseImageMigrateArgs(args []string, errOut io.Writer) (imageMigrateOptions, error) {
	var o imageMigrateOptions
	fs := flag.NewFlagSet("image migrate", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		fmt.Fprint(errOut, imageMigrateUsage)
		fs.PrintDefaults()
	}
	fs.StringVar(&o.socket, "socket", runtimed.DefaultSocketPath, "runtimed control socket to dial")
	fs.StringVar(&o.workDir, "work-dir", workDirFromEnv(), "control-plane state root: the registry push credential and the migration journal")
	fs.BoolVar(&o.report, "report", false, "print the last run's report without running")
	fs.StringVar(&o.output, "o", "", "json, for the journal itself instead of the report")
	fs.DurationVar(&o.timeout, "timeout", 6*time.Hour, "overall deadline")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() != 0 {
		return o, fmt.Errorf("migrate takes no arguments, got %q", fs.Args())
	}
	if o.output != "" && o.output != "json" {
		return o, fmt.Errorf("-o %q: migrate renders a report by default and `json` on request", o.output)
	}
	if o.timeout <= 0 {
		return o, fmt.Errorf("--timeout must be positive, got %v", o.timeout)
	}
	return o, nil
}

// runImageMigrate is the `k3sm image migrate` entry point.
func runImageMigrate(args []string) error {
	o, err := parseImageMigrateArgs(args, os.Stderr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	return imageMigrateCommand(ctx, o, os.Stdout, dialRuntimed)
}

// imageMigrateCommand runs the verb against a dialer.
func imageMigrateCommand(ctx context.Context, o imageMigrateOptions, out io.Writer, dial imagesDialer) error {
	var (
		j   migrationJournal
		err error
	)
	if o.report {
		j, err = readMigrationJournal(o.workDir)
	} else {
		var unlock func()
		if unlock, err = lockImageMigration(o.workDir); err != nil {
			return err
		}
		defer unlock()
		cc, closer, derr := dial(ctx, o.socket)
		if derr != nil {
			return derr
		}
		if closer != nil {
			defer closer.Close()
		}
		j, err = newImageMigrator(o.workDir, runtimev1.NewImagesClient(cc), o.socket).run(ctx)
	}
	if o.output == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if eerr := enc.Encode(j); eerr != nil {
			return errors.Join(err, eerr)
		}
	} else {
		renderMigrationReport(out, j)
	}
	return err
}

// migrationLock serialises migrations within this process: the on-upgrade
// run and a verb run in the same binary share the journal.
var migrationLock sync.Mutex

// lockImageMigration takes the migration lock, so the server's on-upgrade run
// and an operator's `k3sm image migrate` never write the journal at once.
// Across processes it is an exclusive lock file; a lock left by a crashed run
// is older than any run can be and is taken over.
func lockImageMigration(workDir string) (func(), error) {
	migrationLock.Lock()
	if err := os.MkdirAll(migrationDir(workDir), 0o700); err != nil {
		migrationLock.Unlock()
		return nil, fmt.Errorf("create %s: %w", migrationDir(workDir), err)
	}
	path := filepath.Join(migrationDir(workDir), "lock")
	for attempt := 0; ; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path); migrationLock.Unlock() }, nil
		}
		info, serr := os.Stat(path)
		if attempt == 0 && serr == nil && time.Since(info.ModTime()) > 7*time.Hour {
			_ = os.Remove(path)
			continue
		}
		migrationLock.Unlock()
		return nil, fmt.Errorf("another image migration holds %s; wait for it, or remove the file if no k3sm is migrating", path)
	}
}

// migrationRetry is how often the on-upgrade run retries while this node's
// runtimed or registry is not yet up.
const migrationRetry = 30 * time.Second

// startImageMigration runs the one-time migration in the background on a
// server start, once this node's registry is up. A journal that says a run
// completed makes it a no-op, so only the first start after an upgrade does
// any work. It retries until it completes or ctx ends, and the returned stop
// waits for it. A server that runs no registry (--registry-port 0) has
// nowhere to migrate to and starts nothing.
func startImageMigration(ctx context.Context, opts serverOptions, logger *slog.Logger) func() {
	if opts.registryPort == 0 {
		return noStop
	}
	workDir := opts.workDir
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			finished, err := migrateOnce(ctx, workDir, logger)
			if finished {
				return
			}
			logger.Info("image migration not finished; will retry", "err", err, "in", migrationRetry)
			select {
			case <-ctx.Done():
				return
			case <-time.After(migrationRetry):
			}
		}
	}()
	return func() { cancel(); <-done }
}

// migrateOnce is one attempt of the on-upgrade run. finished is true when
// there is nothing more for the trigger to do.
func migrateOnce(ctx context.Context, workDir string, logger *slog.Logger) (finished bool, err error) {
	j, err := readMigrationJournal(workDir)
	if err != nil {
		logger.Error("image migration: the journal is unreadable; run k3sm image migrate by hand", "err", err)
		return true, err
	}
	if j.Complete {
		return true, nil
	}
	if _, err := registrysvc.ReadCredential(workDir); err != nil {
		return false, fmt.Errorf("this node's registry is not up yet: %w", err)
	}
	unlock, err := lockImageMigration(workDir)
	if err != nil {
		return false, err
	}
	defer unlock()
	cc, closer, err := dialRuntimed(ctx, runtimed.DefaultSocketPath)
	if err != nil {
		if rerr := recordMigrationFailure(workDir, fmt.Errorf("this node's runtime is not reachable: %w", err)); rerr != nil {
			logger.Warn("image migration: could not record the pending reason", "err", rerr)
		}
		return false, err
	}
	if closer != nil {
		defer closer.Close()
	}
	j, err = newImageMigrator(workDir, runtimev1.NewImagesClient(cc), runtimed.DefaultSocketPath).run(ctx)
	if err != nil {
		return false, err
	}
	logger.Info(migrationSummaryLine(j), "journal", migrationJournalPath(workDir))
	return true, nil
}
