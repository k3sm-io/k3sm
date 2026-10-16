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
	"io/fs"
	"log/slog"
	"os"
	"time"

	"k3sm.io/darwin-net/pkg/proxy"

	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/svcstatus"
)

// servicesSource is what the services recorder reads from the datapath
// (netserve.Server in production).
type servicesSource interface {
	VIPStates() []proxy.VIPState
	PinnedBackends() map[string][]string
	UnproxiedClusterIPs() []string
	// Synced reports whether the proxy's table has been built from synced
	// informers; a table recorded before that would read as every Service
	// missing its backends.
	Synced() bool
}

// servicesSyncPoll is how often the recorder checks Synced before its first
// record.
const servicesSyncPoll = time.Second

// removeServicesRecord removes the record an earlier server process left, and
// its user-readable copy. It describes a proxy that is gone, and runs whether or
// not this server has a datapath, so a server restarted without one leaves no
// record behind.
func removeServicesRecord(workDir string, logger *slog.Logger) {
	path := status.ServicesPath(workDir)
	for _, p := range []string{path, status.UserReadablePath(workDir, path)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Warn("could not remove the previous Service proxy record", "path", p, "err", err)
		}
	}
}

// runServicesRecorder publishes src's routing table for `k3sm status` (the
// services row): first as soon as src reports Synced, then every interval, until
// ctx ends. Every failure is logged and survivable; the record is a report, never
// a reason to stop a server.
func runServicesRecorder(ctx context.Context, src servicesSource, workDir string, interval, syncPoll time.Duration, logger *slog.Logger) {
	path := status.ServicesPath(workDir)
	poll := time.NewTicker(syncPoll)
	for !src.Synced() {
		select {
		case <-ctx.Done():
			poll.Stop()
			return
		case <-poll.C:
		}
	}
	poll.Stop()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := recordServices(src, workDir, path, time.Now()); err != nil && ctx.Err() == nil {
			logger.Warn("could not record the Service proxy for `k3sm status`", "path", path, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// recordServices writes src's routing table to path through writeRecord: 0600
// like the other records beside it, and 0644 in the status directory.
func recordServices(src servicesSource, workDir, path string, now time.Time) error {
	rec := svcstatus.Record(src.VIPStates(), src.PinnedBackends(), src.UnproxiedClusterIPs(), now)
	return writeRecord(workDir, path, rec)
}
