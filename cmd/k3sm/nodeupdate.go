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
	"log/slog"
	"path/filepath"
	"sync"

	"k8s.io/client-go/kubernetes"

	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/update"
	"k3sm.io/k3sm/pkg/version"
)

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
	// ready reports whether the node's pod runtime answers; nil is always.
	ready func(context.Context) bool
}

// productionUpdateDeps fetches over HTTPS, installs through the node's own
// k3sm-netd socket, and holds Done until ready (the provider's runtime-health
// probe) says the pod runtime answers.
func productionUpdateDeps(opts nodeOptions, ready func(context.Context) bool) nodeUpdateDeps {
	return nodeUpdateDeps{
		fetcher: update.HTTPFetcher{},
		netd:    wire.NewClient(opts.netMode.Socket),
		running: version.Get(),
		ready:   ready,
	}
}

// newNodeUpdater builds the node's update watcher, or nil when this node
// cannot apply a managed update: no apiserver client, no k3sm-netd root helper
// (the install step is the helper's), or no update root (the standalone
// `k3sm node`, which no install manages).
func newNodeUpdater(opts nodeOptions, cs kubernetes.Interface, deps nodeUpdateDeps, logger *slog.Logger) (*update.Watcher, error) {
	if cs == nil || !opts.netMode.UsesHelper() || opts.updateRoot == "" {
		return nil, nil
	}
	return update.New(update.Config{
		Node:    opts.nodeName,
		Client:  cs,
		Running: deps.running,
		Root:    opts.updateRoot,
		Fetcher: deps.fetcher,
		Netd:    deps.netd,
		Ready:   deps.ready,
		Log:     logger,
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
	uctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.Run(uctx)
	}()
	return func() {
		cancel()
		wg.Wait()
	}
}
