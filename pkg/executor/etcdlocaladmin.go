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

package executor

import (
	"context"
	"time"
)

// localAdminCallTimeout bounds one LocalEtcdAdmin call. A membership change commits
// through raft, so a cluster without quorum would otherwise hold the caller (a
// bootstrap request, an uninstall) forever.
const localAdminCallTimeout = 10 * time.Second

// EtcdMember is one etcd cluster member as LocalEtcdAdmin reports it. An unstarted
// member (added, never run) has an empty Name and no ClientURLs.
type EtcdMember struct {
	ID         uint64
	Name       string
	PeerURLs   []string
	ClientURLs []string
	IsLearner  bool
}

// LocalEtcdAdmin is the membership admin API of THIS server's etcd member, reached
// over its loopback client listener with this server's etcd client identity
// (client.crt). It is what a server's member routes and its own uninstall drive;
// there is no remote client listener for anything else to use.
type LocalEtcdAdmin struct {
	admin etcdAdmin
}

// NewLocalEtcdAdmin connects to the local member listening on 127.0.0.1:clientPort
// (the server's --kine-port) with the work dir's etcd PKI. The client dials lazily,
// so this succeeds before the member has a leader; every call is bounded.
func NewLocalEtcdAdmin(ctx context.Context, workDir string, clientPort int) (*LocalEtcdAdmin, error) {
	a, err := dialEtcdAdmin(ctx, workDir, etcdClientURL(clientPort))
	if err != nil {
		return nil, err
	}
	return &LocalEtcdAdmin{admin: a}, nil
}

// Close releases the client connection.
func (a *LocalEtcdAdmin) Close() error { return a.admin.Close() }

// LocalMemberID returns the ID of the member answering on the loopback listener.
func (a *LocalEtcdAdmin) LocalMemberID(ctx context.Context) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, localAdminCallTimeout)
	defer cancel()
	st, err := a.admin.Status(ctx)
	if err != nil {
		return 0, err
	}
	return st.MemberID, nil
}

// MemberList lists the members as the local member knows them.
func (a *LocalEtcdAdmin) MemberList(ctx context.Context) ([]EtcdMember, error) {
	ctx, cancel := context.WithTimeout(ctx, localAdminCallTimeout)
	defer cancel()
	ms, err := a.admin.MemberList(ctx)
	if err != nil {
		return nil, err
	}
	return exportEtcdMembers(ms), nil
}

// MemberAddAsLearner adds a non-voting member at peerURL and returns it with the
// member list that resulted.
func (a *LocalEtcdAdmin) MemberAddAsLearner(ctx context.Context, peerURL string) (EtcdMember, []EtcdMember, error) {
	ctx, cancel := context.WithTimeout(ctx, localAdminCallTimeout)
	defer cancel()
	added, ms, err := a.admin.MemberAddAsLearner(ctx, peerURL)
	if err != nil {
		return EtcdMember{}, nil, err
	}
	return EtcdMember(added), exportEtcdMembers(ms), nil
}

// MemberPromote makes a caught-up learner a voting member.
func (a *LocalEtcdAdmin) MemberPromote(ctx context.Context, id uint64) error {
	ctx, cancel := context.WithTimeout(ctx, localAdminCallTimeout)
	defer cancel()
	return a.admin.MemberPromote(ctx, id)
}

// MemberRemove removes a member.
func (a *LocalEtcdAdmin) MemberRemove(ctx context.Context, id uint64) error {
	ctx, cancel := context.WithTimeout(ctx, localAdminCallTimeout)
	defer cancel()
	return a.admin.MemberRemove(ctx, id)
}

func exportEtcdMembers(ms []etcdMember) []EtcdMember {
	out := make([]EtcdMember, 0, len(ms))
	for _, m := range ms {
		out = append(out, EtcdMember(m))
	}
	return out
}
