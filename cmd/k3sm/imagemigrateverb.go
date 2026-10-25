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

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/registrysvc"
	"k3sm.io/k3sm/pkg/status"
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

// registryDigestAt is the production registryDigester: a manifest HEAD sent
// the way the run's uploads are, so it asks the same registry with the same
// credential.
func registryDigestAt(ctx context.Context, ref name.Tag, dest pushDest) (string, bool, error) {
	opts, err := dest.options(ctx, ref)
	if err != nil {
		return "", false, err
	}
	desc, err := remote.Head(ref, opts...)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return "", false, nil
		}
		return "", false, err
	}
	return desc.Digest.String(), true, nil
}

// userMigrationRoute is the route of `k3sm image migrate`: the path `k3sm
// build --push` takes, through the push gate with a builder token minted from
// the invoking user's kubeconfig. On a server that is its loopback gate, on a
// worker the server's cluster address. A node never pushes as itself; a user
// does.
func userMigrationRoute(workDir string) migrationRoute {
	return func(ctx context.Context) (migrationWriter, error) {
		cr, err := resolveClusterRegistry(ctx, workDir)
		if err != nil {
			return migrationWriter{}, err
		}
		return migrationWriter{authority: cr.authority, dest: pushDest{workDir: workDir, cluster: &cr}}, nil
	}
}

// serverMigrationRoute is the route of the run the server's daemon starts
// after an upgrade. The daemon is not a user and holds no kubeconfig of one,
// so it writes the way the server writes to its own registry: straight to the
// registry's loopback listener with the per-boot push credential the server
// minted under its work dir (registrysvc.CredentialPath, 0600, readable by
// the daemon's own account only), which registryAuth presents only to that
// exact loopback address.
func serverMigrationRoute(workDir string) migrationRoute {
	return func(context.Context) (migrationWriter, error) {
		cred, err := registrysvc.ReadCredential(workDir)
		if err != nil {
			return migrationWriter{}, fmt.Errorf("read this server's registry push credential: %w", err)
		}
		return migrationWriter{authority: cred.Address, dest: pushDest{workDir: workDir}}, nil
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

// newImageMigrator wires the production migrator for a work dir, a runtimed
// client and the route its uploads take.
func newImageMigrator(workDir string, client runtimev1.ImagesClient, socket string, route migrationRoute) imageMigrator {
	return imageMigrator{
		workDir:  workDir,
		source:   runtimedMigrationSource{client: client, socket: socket},
		route:    route,
		digestAt: registryDigestAt,
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
in the node store and runnable until it is loaded again.

The server runs this by itself on its first start after an upgrade. A worker
never pushes on its own: run it there by hand, with sudo, because the node
store is read through the runtime's socket, which only root and the k3sm
service user may open (as for image prune). On a worker --report needs sudo
too, because the journal is root's there. The copy goes through the push
gate with a builder token minted from your kubeconfig, the way
k3sm build --push does: on a server to its loopback gate, on a worker to the
server's cluster address. Progress is journalled on this node.

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
	fs.StringVar(&o.workDir, "work-dir", workDirFromEnv(), "state root of this node's migration journal (and, on a server, of its registry record)")
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
	if err := migrateAgentAccess(); err != nil {
		return err
	}
	var (
		j   migrationJournal
		err error
	)
	if o.report {
		j, err = readMigrationJournal(o.workDir)
	} else {
		if err := migrateRuntimeAccess(o.socket); err != nil {
			return err
		}
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
		j, err = newImageMigrator(o.workDir, runtimev1.NewImagesClient(cc), o.socket, userMigrationRoute(o.workDir)).run(ctx)
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

// migrateGeteuid and migrateServiceUID are the identity the runtime-socket
// rule is decided for, and migrateRole the node this Mac is installed as;
// seams so the refusals are testable.
var (
	migrateGeteuid    = os.Geteuid
	migrateServiceUID = lookupServiceUID
	migrateRole       = installedRole
)

// migrateRuntimeAccess refuses, before anything is dialled, a run that cannot
// open the installed runtime's socket: it is mode 0600 inside a 0700
// directory of the service user, so only root and that user may read the node
// store through it (status.RuntimedReachable, the one home of that rule). A
// --socket naming any other path is the caller's own, and is dialled.
func migrateRuntimeAccess(socket string) error {
	if socket != runtimed.DefaultSocketPath || status.RuntimedReachable(migrateGeteuid(), migrateServiceUID()) {
		return nil
	}
	return fmt.Errorf("k3sm image migrate reads this node's image store through the runtime's socket %s, which only root and the k3sm service user may open (the same rule as k3sm image prune); run it with sudo: sudo k3sm image migrate", socket)
}

// migrateAgentAccess refuses, before any journal is read, a run on a worker
// by an account that is neither root nor the k3sm service user. A worker's
// migration reads its node store through the runtime's socket and journals
// under the root-owned installed work dir, so an ordinary account can neither
// run it nor read its report: without this it would resolve a work dir of
// its own and report a migration that never ran there. The server keeps the
// runtime-socket rule alone (migrateRuntimeAccess).
func migrateAgentAccess() error {
	if role, _ := migrateRole(); role != install.RoleAgent || status.RuntimedReachable(migrateGeteuid(), migrateServiceUID()) {
		return nil
	}
	return errors.New("on a worker, k3sm image migrate (--report included) reads this node's image store and its migration journal, which only root and the k3sm service user may open; run it with sudo: sudo k3sm image migrate")
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
	if err := adoptMigrationPaths(workDir, migrationDir(workDir)); err != nil {
		migrationLock.Unlock()
		return nil, err
	}
	path := filepath.Join(migrationDir(workDir), "lock")
	for attempt := 0; ; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			if aerr := adoptMigrationPaths(workDir, path); aerr != nil {
				_ = os.Remove(path)
				migrationLock.Unlock()
				return nil, aerr
			}
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
			finished, err := migrateOnce(ctx, workDir, dialRuntimed, runtimed.DefaultSocketPath, logger)
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

// migrateOnce is one attempt of the on-upgrade run, reading the node store
// through dial and socket. finished is true when there is nothing more for
// the trigger to do. It writes through serverMigrationRoute: the daemon is not
// a user, so it holds no builder token.
func migrateOnce(ctx context.Context, workDir string, dial imagesDialer, socket string, logger *slog.Logger) (finished bool, err error) {
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
	cc, closer, err := dial(ctx, socket)
	if err != nil {
		if rerr := recordMigrationFailure(workDir, fmt.Errorf("this node's runtime is not reachable: %w", err)); rerr != nil {
			logger.Warn("image migration: could not record the pending reason", "err", rerr)
		}
		return false, err
	}
	if closer != nil {
		defer closer.Close()
	}
	j, err = newImageMigrator(workDir, runtimev1.NewImagesClient(cc), socket, serverMigrationRoute(workDir)).run(ctx)
	if err != nil {
		return false, err
	}
	logger.Info(migrationSummaryLine(j), "journal", migrationJournalPath(workDir))
	return true, nil
}
