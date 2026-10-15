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

	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/svcstatus"
)

// runServicesRecorder publishes the Service proxy's routing table for `k3sm
// status` (the services row) every status.ServicesRecordInterval until ctx ends.
//
// A record left by an earlier server process describes a proxy that is gone, so
// it is removed first. The first record is written one interval after start, not
// at once: the proxy's informers sync and install the table in the meantime, and
// a table recorded before that would read as every Service missing its backends.
// Every failure is logged and survivable; the record is a report, never a reason
// to stop a server.
func runServicesRecorder(ctx context.Context, srv *netserve.Server, workDir string, logger *slog.Logger) {
	path := status.ServicesPath(workDir)
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		logger.Warn("could not remove the previous Service proxy record", "path", path, "err", err)
	}
	t := time.NewTicker(status.ServicesRecordInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := recordServices(srv, path, time.Now()); err != nil && ctx.Err() == nil {
			logger.Warn("could not record the Service proxy for `k3sm status`", "path", path, "err", err)
		}
	}
}

// recordServices writes srv's routing table to path through writeFileAtomic,
// which creates the file 0600 like the other records beside it.
func recordServices(srv *netserve.Server, path string, now time.Time) error {
	rec := svcstatus.Record(srv.VIPStates(), srv.StaticServices(), srv.UnproxiedClusterIPs(), now)
	return writeFileAtomic(path, rec)
}
