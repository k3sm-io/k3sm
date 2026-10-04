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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"

	"k3sm.io/k3sm/pkg/certs"
)

// etcdMember is one cluster member as the executor needs to see it.
type etcdMember struct {
	ID         uint64
	Name       string
	PeerURLs   []string
	ClientURLs []string
	IsLearner  bool
}

// etcdMemberStatus is the LOCAL member's Status answer.
type etcdMemberStatus struct {
	// MemberID is the answering member; Leader the member it believes leads (0: none).
	MemberID, Leader uint64
	// DBSize is the backend file's allocated size, DBSizeInUse the part in use,
	// DBSizeQuota the configured backend quota.
	DBSize, DBSizeInUse, DBSizeQuota int64
	IsLearner                        bool
}

// etcdAlarm is one active alarm (Alarm is "NOSPACE", "CORRUPT", ...).
type etcdAlarm struct {
	MemberID uint64
	Alarm    string
}

// etcdMembers is the executor's view of the etcd admin API, defined here at its
// consumer so the quorum wait, the post-quorum checks, the reset and the snapshot are
// unit-tested against a fake. Every call goes to the LOCAL member over its loopback
// client listener; there is no remote client listener to call.
type etcdMembers interface {
	// Status reports the local member.
	Status(ctx context.Context) (etcdMemberStatus, error)
	// AlarmList lists the cluster's active alarms. It goes through raft, so it
	// blocks without quorum: call it only once Status reports a leader.
	AlarmList(ctx context.Context) ([]etcdAlarm, error)
	// MemberList lists the members as the local member knows them (serializable: it
	// answers without quorum, which is what the quorum wait's log line needs).
	MemberList(ctx context.Context) ([]etcdMember, error)
	// MemberAddAsLearner adds a non-voting member at peerURL and returns it with the
	// resulting member list.
	MemberAddAsLearner(ctx context.Context, peerURL string) (etcdMember, []etcdMember, error)
	// MemberPromote makes a caught-up learner a voting member.
	MemberPromote(ctx context.Context, id uint64) error
	// MemberRemove removes a member.
	MemberRemove(ctx context.Context, id uint64) error
	// Defragment defragments the member at endpoint (always the local one).
	Defragment(ctx context.Context, endpoint string) error
	// Snapshot streams a point-in-time copy of the member's backend.
	Snapshot(ctx context.Context) (io.ReadCloser, error)
}

// etcdAdmin is an etcdMembers that holds a connection to release.
type etcdAdmin interface {
	etcdMembers
	Close() error
}

// etcdDialTimeout bounds the client's connection setup.
const etcdDialTimeout = 5 * time.Second

// clientv3Admin implements etcdAdmin over clientv3 against the local member.
type clientv3Admin struct {
	cli      *clientv3.Client
	endpoint string
}

// dialEtcdAdmin connects to the local member at endpoint with this server's etcd
// client identity (client.crt, clientAuth only, from the etcd server CA), verifying
// the member's server-client.crt against the etcd server CA. clientv3 dials lazily, so
// this returns without the member having a leader.
func dialEtcdAdmin(_ context.Context, workDir, endpoint string) (etcdAdmin, error) {
	tlsCfg, err := etcdClientTLS(workDir)
	if err != nil {
		return nil, err
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{endpoint},
		TLS:         tlsCfg,
		DialTimeout: etcdDialTimeout,
		// The client's own logging would go to the daemon's stderr unstructured;
		// every failure it could report comes back as an error to a caller that logs.
		Logger: zap.NewNop(),
	})
	if err != nil {
		return nil, fmt.Errorf("connect to the local etcd member %s: %w", endpoint, err)
	}
	return &clientv3Admin{cli: cli, endpoint: endpoint}, nil
}

// etcdClientTLS builds the client TLS config from the work dir's etcd PKI.
func etcdClientTLS(workDir string) (*tls.Config, error) {
	p := certs.EtcdCertPaths(workDir)
	pair, err := tls.LoadX509KeyPair(p.ClientCert, p.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load the etcd client identity: %w", err)
	}
	caPEM, err := os.ReadFile(p.ServerCACert)
	if err != nil {
		return nil, fmt.Errorf("read the etcd server CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the etcd server CA file holds no certificate")
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

func (a *clientv3Admin) Close() error { return a.cli.Close() }

func (a *clientv3Admin) Status(ctx context.Context) (etcdMemberStatus, error) {
	r, err := a.cli.Status(ctx, a.endpoint)
	if err != nil {
		return etcdMemberStatus{}, err
	}
	st := etcdMemberStatus{Leader: r.Leader, DBSize: r.DbSize, DBSizeInUse: r.DbSizeInUse,
		DBSizeQuota: r.DbSizeQuota, IsLearner: r.IsLearner}
	if r.Header != nil {
		st.MemberID = r.Header.MemberId
	}
	return st, nil
}

func (a *clientv3Admin) AlarmList(ctx context.Context) ([]etcdAlarm, error) {
	r, err := a.cli.AlarmList(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]etcdAlarm, 0, len(r.Alarms))
	for _, al := range r.Alarms {
		out = append(out, etcdAlarm{MemberID: al.MemberID, Alarm: al.Alarm.String()})
	}
	return out, nil
}

func (a *clientv3Admin) MemberList(ctx context.Context) ([]etcdMember, error) {
	r, err := a.cli.MemberList(ctx, clientv3.WithSerializable())
	if err != nil {
		return nil, err
	}
	return toEtcdMembers(r.Members), nil
}

func (a *clientv3Admin) MemberAddAsLearner(ctx context.Context, peerURL string) (etcdMember, []etcdMember, error) {
	r, err := a.cli.MemberAddAsLearner(ctx, []string{peerURL})
	if err != nil {
		return etcdMember{}, nil, err
	}
	var added etcdMember
	if r.Member != nil {
		added = toEtcdMembers([]*pb.Member{r.Member})[0]
	}
	return added, toEtcdMembers(r.Members), nil
}

func (a *clientv3Admin) MemberPromote(ctx context.Context, id uint64) error {
	_, err := a.cli.MemberPromote(ctx, id)
	return err
}

func (a *clientv3Admin) MemberRemove(ctx context.Context, id uint64) error {
	_, err := a.cli.MemberRemove(ctx, id)
	return err
}

func (a *clientv3Admin) Defragment(ctx context.Context, endpoint string) error {
	_, err := a.cli.Defragment(ctx, endpoint)
	return err
}

func (a *clientv3Admin) Snapshot(ctx context.Context) (io.ReadCloser, error) {
	return a.cli.Snapshot(ctx)
}

// toEtcdMembers converts clientv3 members.
func toEtcdMembers(ms []*pb.Member) []etcdMember {
	out := make([]etcdMember, 0, len(ms))
	for _, m := range ms {
		if m == nil {
			continue
		}
		out = append(out, etcdMember{ID: m.ID, Name: m.Name, PeerURLs: m.PeerURLs,
			ClientURLs: m.ClientURLs, IsLearner: m.IsLearner})
	}
	return out
}
