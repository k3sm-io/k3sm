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
	"reflect"
	"slices"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/executor"
)

// TestServerJoinMemberRouteBeforeExecutor pins the joining server's order: the CA
// bundle, then (first boot only) the etcd member route, then the executor, which
// starts with the route's --initial-cluster and a Promote bound to the same server;
// the mesh enroll comes only after the executor reports the apiserver healthy.
//
// The two halves are proved the two ways this package proves bring-up order. The
// member step is a unit (joinEtcdMember over fake seams). Where it sits in
// runServer — after the bundle import, with the executor's Start inside it, and
// before the mesh enroll — is read structurally from server.go, as
// servermeshwiring_test.go does, because runServer boots a real control plane.
func TestServerJoinMemberRouteBeforeExecutor(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	base := executor.Config{WorkDir: t.TempDir(), Etcd: &executor.EtcdConfig{
		Role: executor.EtcdJoin, Name: "server-b", PeerIP: "192.0.2.11", PeerPort: 2380}}

	t.Run("first boot: member route, then the executor with its answer", func(t *testing.T) {
		var order []string
		var promoted []string
		j := &serverEtcdJoin{
			memberExists: func() bool { return false },
			member: func(_ context.Context, name, peerURL string) (bootstrap.EtcdMemberResponse, error) {
				order = append(order, "member "+name+" "+peerURL)
				return bootstrap.EtcdMemberResponse{MemberID: 0xb, InitialCluster: "server-a=https://192.0.2.10:2380,server-b=https://192.0.2.11:2380"}, nil
			},
			promote: func(_ context.Context, name string) error {
				promoted = append(promoted, name)
				return nil
			},
		}
		started, err := joinEtcdMember(context.Background(), j, "192.0.2.10", base, logger)
		if err != nil {
			t.Fatalf("joinEtcdMember: %v", err)
		}
		if want := []string{"member server-b https://192.0.2.11:2380"}; !slices.Equal(order, want) {
			t.Fatalf("calls = %v, want %v", order, want)
		}
		if started.Etcd.InitialCluster != "server-a=https://192.0.2.10:2380,server-b=https://192.0.2.11:2380" {
			t.Errorf("the executor started without the route's initial cluster: %q", started.Etcd.InitialCluster)
		}
		if started.Etcd.Promote == nil {
			t.Fatal("the executor started with no Promote")
		}
		if err := started.Etcd.Promote(context.Background()); err != nil || !slices.Equal(promoted, []string{"server-b"}) {
			t.Errorf("Promote = %v, promoted %v; want the promote route called for server-b", err, promoted)
		}
		if base.Etcd.InitialCluster != "" || base.Etcd.Promote != nil {
			t.Error("the caller's EtcdConfig was mutated")
		}
	})

	t.Run("restart: the member exists, no route call", func(t *testing.T) {
		j := &serverEtcdJoin{
			memberExists: func() bool { return true },
			member: func(context.Context, string, string) (bootstrap.EtcdMemberResponse, error) {
				t.Fatal("the member route was called on a restart")
				return bootstrap.EtcdMemberResponse{}, nil
			},
		}
		cfg, err := joinEtcdMember(context.Background(), j, "192.0.2.10", base, logger)
		if err != nil {
			t.Fatalf("restart: %v", err)
		}
		if cfg.Etcd.InitialCluster != "" || cfg.Etcd.Promote != nil {
			t.Errorf("a restart starts with join-only settings: %+v", cfg.Etcd)
		}
	})

	t.Run("a route failure stops before the executor and is not a control-plane crash", func(t *testing.T) {
		j := &serverEtcdJoin{
			memberExists: func() bool { return false },
			member: func(context.Context, string, string) (bootstrap.EtcdMemberResponse, error) {
				return bootstrap.EtcdMemberResponse{}, errors.New("connection refused")
			},
		}
		for _, server := range []string{"192.0.2.10", ""} {
			if _, err := joinEtcdMember(context.Background(), j, server, base, logger); !errors.Is(err, errEtcdMemberRoute) {
				t.Errorf("--server %q: err = %v, want errEtcdMemberRoute", server, err)
			}
		}
	})

	t.Run("not a joiner: the Config is unchanged", func(t *testing.T) {
		cfg, err := joinEtcdMember(context.Background(), nil, "", base, logger)
		if err != nil || cfg.Etcd != base.Etcd {
			t.Fatalf("err=%v, Etcd changed: %v", err, cfg.Etcd != base.Etcd)
		}
	})

	t.Run("runServer: bundle, member step, executor, then the mesh enroll", func(t *testing.T) {
		_, body := runServerBody(t)
		first := firstCallPositions(body)
		order := []string{"importServerCABundle", "joinEtcdMember", "executor.NewSupervised", "exec.Start", "enrollSelfAndBringUpMesh"}
		for i, name := range order {
			if _, ok := first[name]; !ok {
				t.Fatalf("runServer no longer calls %s", name)
			}
			if i > 0 && first[order[i-1]] >= first[name] {
				t.Errorf("runServer calls %s before %s; the order must be %v", name, order[i-1], order)
			}
		}
	})
}

// TestLocalMemberJoinerAdapts pins the existing server's adapter: the executor's
// member list and learner add reach the bootstrap package's MemberJoiner field for
// field, and promote/remove pass the ID through.
func TestLocalMemberJoinerAdapts(t *testing.T) {
	fake := &fakeLocalMembers{members: []executor.EtcdMember{{ID: 1, Name: "a", PeerURLs: []string{"https://192.0.2.10:2380"}, ClientURLs: []string{"https://127.0.0.1:2379"}}}}
	var j bootstrap.MemberJoiner = localMemberJoiner{admin: fake}
	ctx := context.Background()

	got, err := j.MemberList(ctx)
	if err != nil || !reflect.DeepEqual(got, []bootstrap.EtcdMember{{ID: 1, Name: "a", PeerURLs: []string{"https://192.0.2.10:2380"}, ClientURLs: []string{"https://127.0.0.1:2379"}}}) {
		t.Errorf("MemberList = %+v, %v", got, err)
	}
	added, after, err := j.MemberAddAsLearner(ctx, "https://192.0.2.11:2380")
	if err != nil || added.ID != 2 || !added.IsLearner || len(after) != 2 {
		t.Errorf("MemberAddAsLearner = %+v, %d members, %v", added, len(after), err)
	}
	_ = j.MemberPromote(ctx, 2)
	_ = j.MemberRemove(ctx, 2)
	if !slices.Equal(fake.calls, []string{"promote 2", "remove 2"}) {
		t.Errorf("calls = %v", fake.calls)
	}
}

type fakeLocalMembers struct {
	members []executor.EtcdMember
	calls   []string
}

func (f *fakeLocalMembers) MemberList(context.Context) ([]executor.EtcdMember, error) {
	return f.members, nil
}

func (f *fakeLocalMembers) MemberAddAsLearner(_ context.Context, peerURL string) (executor.EtcdMember, []executor.EtcdMember, error) {
	m := executor.EtcdMember{ID: 2, PeerURLs: []string{peerURL}, IsLearner: true}
	f.members = append(f.members, m)
	return m, f.members, nil
}

func (f *fakeLocalMembers) MemberPromote(_ context.Context, id uint64) error {
	f.calls = append(f.calls, "promote "+string(rune('0'+id)))
	return nil
}

func (f *fakeLocalMembers) MemberRemove(_ context.Context, id uint64) error {
	f.calls = append(f.calls, "remove "+string(rune('0'+id)))
	return nil
}
