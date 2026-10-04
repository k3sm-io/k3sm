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
	"net/url"
	"strconv"

	"k3sm.io/k3sm/pkg/executor"
)

// Leaving the etcd cluster on `sudo k3sm uninstall` of an HA server.
//
// The member removes ITSELF, through its own loopback client with this server's
// etcd client identity: that needs only the cluster's quorum, exactly what any
// membership change needs, and no credential this host does not already hold (an
// uninstalling server carries no server-class token to present to a peer).
// pkg/install decides WHEN — on an etcd-posture server only, before the daemon is
// booted out — and that a failure never blocks the teardown.

// selfMemberRemover is what the uninstall needs from executor.LocalEtcdAdmin.
type selfMemberRemover interface {
	LocalMemberID(ctx context.Context) (uint64, error)
	MemberList(ctx context.Context) ([]executor.EtcdMember, error)
	MemberRemove(ctx context.Context, id uint64) error
	Close() error
}

// dialLocalEtcd connects to this server's own member; a seam for the test.
type dialLocalEtcd func(ctx context.Context, workDir string, clientPort int) (selfMemberRemover, error)

// dialLocalEtcdAdmin is the shipped dialLocalEtcd.
func dialLocalEtcdAdmin(ctx context.Context, workDir string, clientPort int) (selfMemberRemover, error) {
	return executor.NewLocalEtcdAdmin(ctx, workDir, clientPort)
}

// serverMemberDeregister builds install.Config.DeregisterServer for the server work
// dir: it finds the local member's loopback client port in the status record the
// running server keeps, asks the member for its own ID, and removes that member.
//
// The one member it does not remove is the cluster's ONLY voting member: etcd refuses
// that removal (there would be no cluster left to commit it), so asking would only
// turn the uninstall of a healthy single-member cluster into a WARN. It is said at
// INFO and skipped; nothing is left behind, because the cluster goes with the data
// dir.
func serverMemberDeregister(workDir string, dial dialLocalEtcd, logger *slog.Logger) func(context.Context) error {
	return func(ctx context.Context) error {
		port, err := localEtcdClientPort(workDir)
		if err != nil {
			return err
		}
		admin, err := dial(ctx, workDir, port)
		if err != nil {
			return fmt.Errorf("connect to this server's etcd member: %w", err)
		}
		defer func() { _ = admin.Close() }()
		id, err := admin.LocalMemberID(ctx)
		if err != nil {
			return fmt.Errorf("ask this server's etcd member for its ID: %w", err)
		}
		// A member list that cannot be read leaves the removal to answer for itself.
		if ms, err := admin.MemberList(ctx); err == nil && onlyVoter(ms, id) {
			logger.Info("this server is the etcd cluster's only voting member; not removing it (the cluster is removed with its data dir)",
				"member-id", strconv.FormatUint(id, 16))
			return nil
		}
		if err := admin.MemberRemove(ctx, id); err != nil {
			return fmt.Errorf("remove etcd member %s: %w", strconv.FormatUint(id, 16), err)
		}
		return nil
	}
}

// onlyVoter reports whether id is the one voting member in ms (learners do not vote).
func onlyVoter(ms []executor.EtcdMember, id uint64) bool {
	voters := 0
	self := false
	for _, m := range ms {
		if m.IsLearner {
			continue
		}
		voters++
		self = self || m.ID == id
	}
	return voters == 1 && self
}

// localEtcdClientPort reads the member's loopback client port from the status
// record, accepting only the https://127.0.0.1:<port> URL the executor records.
func localEtcdClientPort(workDir string) (int, error) {
	st, err := executor.ReadEtcdStatus(workDir)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", executor.ErrNoEtcdClient, err)
	}
	u, err := url.Parse(st.ClientURL)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" {
		return 0, fmt.Errorf("%w: recorded client URL %q is not a loopback https URL", executor.ErrNoEtcdClient, st.ClientURL)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%w: recorded client URL %q has no usable port", executor.ErrNoEtcdClient, st.ClientURL)
	}
	return port, nil
}
