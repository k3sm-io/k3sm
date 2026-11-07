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
	"path/filepath"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"

	"k3sm.io/k3sm/pkg/interconnect"
	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/status"
)

// budgetSource is what the budget recorder reads (provider.NodeStatusProvider
// in production): the latest budget observation, ok false until the first
// sample.
type budgetSource interface {
	Budget() (budgetv1alpha1.NodeBudgetObservation, bool)
}

// startBudgetPublisher runs this node's budget annotation publisher on the node's
// own client, with a single-object view of its own Node, until the returned stop
// is called. Cancelling ends both goroutines promptly: a write in flight is
// cancelled with the context.
func startBudgetPublisher(ctx context.Context, opts nodeOptions, cs kubernetes.Interface, src budgetSource, logger *slog.Logger) (stop func()) {
	own := interconnect.NewOwnNode(cs, opts.nodeName)
	pub := provider.NewBudgetPublisher(provider.BudgetPublisherConfig{
		Client:   cs,
		NodeName: opts.nodeName,
		Own:      own,
		Source:   src,
		StateDir: opts.budgetDir,
		Log:      logger,
	})
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var loops sync.WaitGroup
		loops.Add(1)
		go func() { defer loops.Done(); own.Run(ctx) }()
		pub.Run(ctx)
		loops.Wait()
	}()
	return func() { cancel(); <-done }
}

// runBudgetRecorder publishes src's budget for `k3sm status` (the report's
// budget block) into statusDir every interval until ctx ends, starting at
// once. Every failure is logged and survivable: the record is a report, never
// a reason to stop a node. A record that stops being rewritten ages out of the
// report on its own (status.BudgetRecordMaxAge), so nothing removes it here.
func runBudgetRecorder(ctx context.Context, src budgetSource, statusDir string, interval time.Duration, logger *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := recordBudget(src, statusDir); err != nil && ctx.Err() == nil {
			logger.Warn("could not record the node budget for `k3sm status`", "path", status.BudgetPath(statusDir), "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// recordBudget writes src's latest observation into statusDir, 0644, through
// a temporary file and a rename. Before the first sample, or with no status
// directory (a work dir outside an install), it writes nothing.
func recordBudget(src budgetSource, statusDir string) error {
	obs, ok := src.Budget()
	if !ok {
		return nil
	}
	if _, err := os.Stat(statusDir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	raw, err := status.EncodeBudgetRecord(obs)
	if err != nil {
		return err
	}
	return writeBytesAtomic(status.BudgetPath(statusDir), raw, 0o644)
}

// writeBytesAtomic writes b to path through a temporary file and a rename, so
// a reader never sees a half-written file. The file gets mode before it takes
// its name.
func writeBytesAtomic(path string, b []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
