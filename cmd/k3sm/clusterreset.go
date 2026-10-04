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
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// clusterResetFunc is the reset runClusterReset performs; a var so a test can
// assert the Config it is handed without starting an etcd member.
var clusterResetFunc = executor.ClusterReset

// runClusterReset is `k3sm server --cluster-reset`: it turns this server's existing
// etcd member into a one-member cluster that keeps its data, with the same work dir
// and ports the daemon uses, and returns. It never starts the daemon. The executor
// refuses while the daemon holds the work-dir lock, and without a member to reset; a
// reset that does not end with this server as the only member says to restore the
// etcd data dir from a snapshot.
func runClusterReset(opts serverOptions, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The member's binary is already staged in the work dir (it has run), so the
	// reset needs no payload directory.
	if err := clusterResetFunc(ctx, opts.executorConfig(logger)); err != nil {
		return fmt.Errorf("cluster reset: %w", err)
	}
	logger.Info("cluster reset complete: restart the daemon normally", "work-dir", opts.workDir,
		"restart-with", "sudo launchctl kickstart -k system/"+install.ServerLabel)
	return nil
}
