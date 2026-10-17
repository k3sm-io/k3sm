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
	"log/slog"
	"net/url"
	"path/filepath"
	"time"

	"k8s.io/client-go/kubernetes"

	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/update"
	"k3sm.io/k3sm/pkg/version"
)

// releaseBaseUsage is the --update-release-base help, shared by `k3sm
// install`, `k3sm server` and `k3sm agent`.
const releaseBaseUsage = "the release index the managed update reads instead of GitHub's, for a mirror or a lab rig: an https URL, or http only on a loopback address (the server signs the checksum it reads from the index, so plain http on a network would let any host on the path choose it). Recorded with the other install arguments and kept by later installs"

// releaseBase validates a --update-release-base value; empty is nil (GitHub's
// index).
func releaseBase(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	return update.ParseReleaseBase(raw)
}

// releaseBaseURL is the base the resolver and the check read: the validated
// --update-release-base, or "" for their GitHub default.
func releaseBaseURL(raw string) string {
	u, err := releaseBase(raw)
	if err != nil || u == nil {
		return ""
	}
	return u.String()
}

// updateSubdir is the directory of the data root the managed update downloads
// and unpacks a release in (<data root>/updates).
const updateSubdir = "updates"

// updateRootFor is the managed update's directory for a daemon whose work dir
// is workDir: <data root>/updates, beside the server and agent work dirs, and
// owned by the service user like the rest of the data root.
func updateRootFor(workDir string) string {
	return filepath.Join(executor.RuntimeRoot(workDir), updateSubdir)
}

// nodeUpdateDeps are the seams of the node-side managed update: the archive
// fetcher, the root helper's ApplyUpdate client and the running build.
type nodeUpdateDeps struct {
	fetcher update.Fetcher
	netd    update.Netd
	running version.Info
	// releaseBase is the node's recorded --update-release-base, or nil.
	releaseBase *url.URL
	// ready reports whether the node's pod runtime answers; nil is always.
	ready func(context.Context) bool
}

// productionUpdateDeps fetches over HTTPS, installs through the node's own
// k3sm-netd socket, and holds Done until ready (the provider's runtime-health
// probe) says the pod runtime answers.
func productionUpdateDeps(opts nodeOptions, ready func(context.Context) bool) nodeUpdateDeps {
	base, _ := releaseBase(opts.updateReleaseBase) // validated when the daemon's flags parsed
	return nodeUpdateDeps{
		releaseBase: base,
		fetcher:     update.HTTPFetcher{Pin: update.HostPin{Base: base}},
		netd:        wire.NewClient(opts.netMode.Socket),
		running:     version.Get(),
		ready:       ready,
	}
}

// newNodeUpdater builds the node's update watcher, or nil when this node
// cannot apply a managed update: no apiserver client, no k3sm-netd root helper
// (the install step is the helper's), or no update root (the standalone
// `k3sm node`, which no install manages).
func newNodeUpdater(opts nodeOptions, cs kubernetes.Interface, deps nodeUpdateDeps, logger *slog.Logger) (*update.Watcher, error) {
	if cs == nil || !opts.netMode.UsesHelper() || opts.updateRoot == "" || len(opts.updateClusterCAPEM) == 0 {
		return nil, nil
	}
	roots := update.CAPool(opts.updateClusterCAPEM)
	if roots == nil {
		return nil, errors.New("the cluster CA this node pins does not parse")
	}
	return update.New(update.Config{
		Node:        opts.nodeName,
		Client:      cs,
		Running:     deps.running,
		Root:        opts.updateRoot,
		Fetcher:     deps.fetcher,
		Netd:        deps.netd,
		Ready:       deps.ready,
		ClusterCA:   roots,
		ReleaseBase: deps.releaseBase,
		Log:         logger,
	})
}

// startNodeUpdate starts the managed-update watcher on this node's own Node and
// returns its stop. It runs once the node is ready (the provider registered),
// like the interconnect handlers, because it acts on this node's own
// annotations; ready is the runtime-health probe Done also waits for.
func startNodeUpdate(ctx context.Context, opts nodeOptions, cs kubernetes.Interface, ready func(context.Context) bool, logger *slog.Logger) (stop func()) {
	w, err := newNodeUpdater(opts, cs, productionUpdateDeps(opts, ready), logger)
	if err != nil {
		logger.Error("managed update disabled on this node", "err", err)
		return noStop
	}
	if w == nil {
		logger.Info("managed update disabled on this node: it needs the k3sm-netd root helper and an installed data root", "node", opts.nodeName)
		return noStop
	}
	return superviseUpdateWatcher(ctx, w.Run, nodeUpdateStopGrace, logger)
}

// nodeUpdateStopGrace bounds how long the node's teardown waits for the update
// watcher to return once its context is cancelled. pkg/install budgets it as one
// step of the launchd ExitTimeOut.
//
// The wait is bounded because the watcher cannot always return on cancellation.
// Mid-install it is inside the root helper's ApplyUpdate stream, and that stream's
// read honours only the connection deadline (the install timeout, tens of
// minutes), never the context. The stream ends when the staged installer stops
// k3sm-netd, and the installer does that only after this daemon has exited: an
// unbounded wait here held the daemon until launchd's SIGKILL, with every
// teardown step after it (the server's ingest registry among them) never run.
// Returning after the grace leaves that one goroutine blocked on the stream;
// it ends with the process, which is what the installer is waiting for.
const nodeUpdateStopGrace = 2 * time.Second

// superviseUpdateWatcher runs run on its own goroutine under a context of its
// own and returns the stop: cancel, then wait for run at most grace. A watcher
// still running after the grace is reported and left; see nodeUpdateStopGrace.
func superviseUpdateWatcher(ctx context.Context, run func(context.Context), grace time.Duration, logger *slog.Logger) (stop func()) {
	uctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		run(uctx)
	}()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(grace):
			logger.Warn("update watcher did not return in time; continuing shutdown (an install in progress continues in the root helper)",
				"stage", "node-update-stop", "wait", grace)
		}
	}
}
