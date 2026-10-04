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
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

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

	t.Run("restart: the member exists, no route call, Promote still wired", func(t *testing.T) {
		var promoted []string
		j := &serverEtcdJoin{
			memberExists: func() bool { return true },
			member: func(context.Context, string, string) (bootstrap.EtcdMemberResponse, error) {
				t.Fatal("the member route was called on a restart")
				return bootstrap.EtcdMemberResponse{}, nil
			},
			promote: func(_ context.Context, name string) error {
				promoted = append(promoted, name)
				return nil
			},
		}
		cfg, err := joinEtcdMember(context.Background(), j, "192.0.2.10", base, logger)
		if err != nil {
			t.Fatalf("restart: %v", err)
		}
		if cfg.Etcd.InitialCluster != "" {
			t.Errorf("a restart starts with the join-only initial cluster: %+v", cfg.Etcd)
		}
		// The executor calls it only if the member still reports itself a learner
		// (a joiner restarted before its promotion landed).
		if cfg.Etcd.Promote == nil {
			t.Fatal("a restart with --server/--token starts with no Promote; a learner stranded by an earlier crash could never be promoted")
		}
		if err := cfg.Etcd.Promote(context.Background()); err != nil || !slices.Equal(promoted, []string{"server-b"}) {
			t.Errorf("Promote = %v, promoted %v; want the promote route called for server-b", err, promoted)
		}
		if base.Etcd.Promote != nil {
			t.Error("the caller's EtcdConfig was mutated")
		}
	})

	t.Run("restart without --server or --token: no Promote", func(t *testing.T) {
		for _, o := range []serverOptions{
			{serverJoin: true, token: "K10abc::server:secret", workDir: t.TempDir()},
			{serverJoin: true, joinServer: "192.0.2.10", workDir: t.TempDir()},
		} {
			j := newServerEtcdJoin(o)
			if j.promote != nil {
				t.Errorf("--server %q, token set %v: a promote route was wired with nothing to call", o.joinServer, o.token != "")
			}
			j.memberExists = func() bool { return true }
			cfg, err := joinEtcdMember(context.Background(), j, o.joinServer, base, logger)
			if err != nil || cfg.Etcd.Promote != nil {
				t.Errorf("restart: err=%v Promote set=%v; want nil, nil", err, cfg.Etcd.Promote != nil)
			}
		}
		if j := newServerEtcdJoin(serverOptions{serverJoin: true, joinServer: "192.0.2.10", token: "K10abc::server:secret"}); j.promote == nil {
			t.Error("--server and --token set: no promote route")
		}
	})

	t.Run("a route failure stops before the executor and is not a control-plane crash", func(t *testing.T) {
		// A refusal of the request ends the step; a transient answer is retried
		// in-process (TestEtcdMemberRouteRetryAndPermanence).
		j := &serverEtcdJoin{
			memberExists: func() bool { return false },
			member: func(context.Context, string, string) (bootstrap.EtcdMemberResponse, error) {
				return bootstrap.EtcdMemberResponse{}, &bootstrap.ServerRouteError{Path: bootstrap.EtcdMemberPath,
					StatusCode: http.StatusForbidden, Status: "403 Forbidden", Message: "server bootstrap token rejected"}
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
		first := runServerTrace(t).firstCalls()
		order := []string{"importServerCABundle", "joinEtcdMember", "executor.NewSupervised", "exec.Start", "enrollSelfAndBringUpMesh"}
		for i, name := range order {
			if _, ok := first[name]; !ok {
				t.Fatalf("runServer no longer calls %s", name)
			}
			if i > 0 && first[order[i-1]].pos >= first[name].pos {
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

// TestEtcdMemberRouteRetryAndPermanence: a joining server's member route retries a
// TRANSIENT answer in-process (a network error, a 503, a 404) every
// etcdMemberRouteRetry with no expiry and records nothing on the crash-loop breaker,
// while a PERMANENT refusal (a 400/401/403/409, a token that does not parse) ends the
// step at once and is recorded as a permanent bring-up failure, so the breaker parks
// on the first one.
func TestEtcdMemberRouteRetryAndPermanence(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	base := executor.Config{WorkDir: t.TempDir(), Etcd: &executor.EtcdConfig{
		Role: executor.EtcdJoin, Name: "server-b", PeerIP: "192.0.2.11", PeerPort: 2380}}
	routeErr := func(code int) error {
		return &bootstrap.ServerRouteError{Path: bootstrap.EtcdMemberPath, StatusCode: code, Status: http.StatusText(code), Message: "refused"}
	}

	t.Run("transient answers are retried and never recorded", func(t *testing.T) {
		answers := []error{errors.New("dial tcp 192.0.2.10:9345: connect: connection refused"),
			routeErr(http.StatusServiceUnavailable), routeErr(http.StatusNotFound), routeErr(http.StatusTooManyRequests), nil}
		calls := 0
		var waits []time.Duration
		j := &serverEtcdJoin{
			memberExists: func() bool { return false },
			member: func(context.Context, string, string) (bootstrap.EtcdMemberResponse, error) {
				err := answers[calls]
				calls++
				if err != nil {
					return bootstrap.EtcdMemberResponse{}, err
				}
				return bootstrap.EtcdMemberResponse{MemberID: 0xb, InitialCluster: "server-a=https://192.0.2.10:2380,server-b=https://192.0.2.11:2380"}, nil
			},
			wait: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil },
		}
		cfg, err := joinEtcdMember(context.Background(), j, "192.0.2.10", base, logger)
		if err != nil {
			t.Fatalf("joinEtcdMember = %v, want the route answered after the transient refusals", err)
		}
		if calls != len(answers) || len(waits) != len(answers)-1 {
			t.Errorf("calls=%d waits=%d, want %d calls and one wait between each", calls, len(waits), len(answers))
		}
		for _, d := range waits {
			if d != etcdMemberRouteRetry {
				t.Errorf("waited %s between attempts, want %s", d, etcdMemberRouteRetry)
			}
		}
		if cfg.Etcd.InitialCluster == "" {
			t.Error("the executor would start without the route's initial cluster")
		}
	})

	t.Run("a shutdown during the retry is returned uncounted", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		j := &serverEtcdJoin{
			memberExists: func() bool { return false },
			member: func(context.Context, string, string) (bootstrap.EtcdMemberResponse, error) {
				return bootstrap.EtcdMemberResponse{}, routeErr(http.StatusServiceUnavailable)
			},
			wait: func(context.Context, time.Duration) error { cancel(); return context.Canceled },
		}
		_, err := joinEtcdMember(ctx, j, "192.0.2.10", base, logger)
		if !errors.Is(err, errEtcdMemberRoute) || errors.Is(err, errEtcdMemberRoutePermanent) {
			t.Fatalf("err = %v, want a non-permanent member-route error", err)
		}
		dir := t.TempDir()
		noteEtcdMemberRouteFailure(newCrashBreaker(dir, quietLogger()), quietLogger(), err)
		if _, serr := os.Stat(executor.CrashLoopPath(dir)); !errors.Is(serr, os.ErrNotExist) {
			t.Errorf("a shutdown during the member route wrote a crash record (%v)", serr)
		}
	})

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"400", routeErr(http.StatusBadRequest)},
		{"401", routeErr(http.StatusUnauthorized)},
		{"403 (bad token)", routeErr(http.StatusForbidden)},
		{"409 (own name)", routeErr(http.StatusConflict)},
		{"a token that does not parse", fmt.Errorf("%w: missing prefix", bootstrap.ErrMalformedToken)},
	} {
		t.Run("permanent "+tc.name+": one call, parked on the first record", func(t *testing.T) {
			calls := 0
			j := &serverEtcdJoin{
				memberExists: func() bool { return false },
				member: func(context.Context, string, string) (bootstrap.EtcdMemberResponse, error) {
					calls++
					return bootstrap.EtcdMemberResponse{}, tc.err
				},
				wait: func(context.Context, time.Duration) error {
					t.Fatal("a permanent refusal was retried")
					return nil
				},
			}
			_, err := joinEtcdMember(context.Background(), j, "192.0.2.10", base, logger)
			if calls != 1 || !errors.Is(err, errEtcdMemberRoute) || !errors.Is(err, errEtcdMemberRoutePermanent) {
				t.Fatalf("calls=%d err=%v, want one call and a permanent member-route error", calls, err)
			}
			dir := t.TempDir()
			noteEtcdMemberRouteFailure(newCrashBreaker(dir, quietLogger()), quietLogger(), err)
			rec, rerr := executor.ReadCrashRecord(executor.CrashLoopPath(dir))
			if rerr != nil {
				t.Fatal(rerr)
			}
			last, _ := rec.Last()
			if !rec.Tripped() || len(rec.Crashes) != 1 || !last.Permanent || last.Component != etcdMemberRouteComponent ||
				last.Remedy != etcdMemberRouteRemedy || last.Origin != executor.CrashOriginBringUp {
				t.Errorf("record = %+v (tripped %v), want one permanent %s bring-up failure that trips the breaker",
					rec.Crashes, rec.Tripped(), etcdMemberRouteComponent)
			}
		})
	}

	t.Run("a configuration that cannot form the request is permanent", func(t *testing.T) {
		j := &serverEtcdJoin{memberExists: func() bool { return false }}
		if _, err := joinEtcdMember(context.Background(), j, "", base, logger); !errors.Is(err, errEtcdMemberRoutePermanent) {
			t.Errorf("no --server on a first boot: err = %v, want permanent", err)
		}
	})
}
