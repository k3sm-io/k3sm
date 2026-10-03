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
	"flag"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// TestServerEtcdFlagSurface pins the HA flag surface: the etcd posture's flags are
// registered with the executor's defaults, and the retired external-datastore flags
// are not (an old argv must fail as an unknown flag, never fall back to SQLite).
func TestServerEtcdFlagSurface(t *testing.T) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	opts := serverOptions{}
	_ = registerServerFlags(fs, &opts)
	for _, name := range []string{"cluster-init", "server-join", "cluster-reset", "etcd-peer-port", "etcd-metrics-port"} {
		if fs.Lookup(name) == nil {
			t.Errorf("--%s is not registered", name)
		}
	}
	for _, name := range []string{"datastore-endpoint", "datastore-endpoint-file"} {
		if fs.Lookup(name) != nil {
			t.Errorf("--%s is registered; the external-datastore posture is retired", name)
		}
	}
	if opts.etcdPeerPort != executor.DefaultEtcdPeerPort || opts.etcdMetricsPort != executor.DefaultEtcdMetricsPort {
		t.Errorf("etcd port defaults = %d/%d, want %d/%d", opts.etcdPeerPort, opts.etcdMetricsPort, executor.DefaultEtcdPeerPort, executor.DefaultEtcdMetricsPort)
	}
	if err := fs.Parse([]string{"--datastore-endpoint", "x"}); err == nil {
		t.Error("parsing --datastore-endpoint succeeded; it must be an unknown flag")
	}
}

// TestServerEtcdFlagValidation pins the refusals that run before any state is
// touched: init and join together, and the etcd posture (or a reset) without a
// non-loopback --node-ip.
func TestServerEtcdFlagValidation(t *testing.T) {
	cases := []struct {
		name string
		opts serverOptions
		want error // nil = accepted; errAny = any error
	}{
		{"single-node on the loopback default", serverOptions{nodeIP: "127.0.0.1"}, nil},
		{"init on a LAN address", serverOptions{clusterInit: true, nodeIP: "192.168.0.50"}, nil},
		{"join on a LAN address", serverOptions{serverJoin: true, nodeIP: "192.168.0.111"}, nil},
		{"init and join together", serverOptions{clusterInit: true, serverJoin: true, nodeIP: "192.168.0.50"}, errAny},
		{"init on the loopback default", serverOptions{clusterInit: true, nodeIP: "127.0.0.1"}, executor.ErrEtcdNeedsNodeIP},
		{"join with no node IP", serverOptions{serverJoin: true}, executor.ErrEtcdNeedsNodeIP},
		{"init on the unspecified address", serverOptions{clusterInit: true, nodeIP: "0.0.0.0"}, executor.ErrEtcdNeedsNodeIP},
		{"reset on the loopback default", serverOptions{clusterReset: true, nodeIP: "127.0.0.1"}, executor.ErrEtcdNeedsNodeIP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.validateEtcdFlags()
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("validateEtcdFlags = %v, want nil", err)
			case tc.want == errAny && err == nil:
				t.Fatal("validateEtcdFlags = nil, want a refusal")
			case tc.want != nil && tc.want != errAny && !errors.Is(err, tc.want):
				t.Fatalf("validateEtcdFlags = %v, want %v", err, tc.want)
			}
		})
	}
}

// errAny marks a case that must be refused without naming a sentinel.
var errAny = errors.New("any error")

// TestServerEtcdConfigFromFlags pins that the role flags reach the executor as one
// etcd block — the canonical node name, the --node-ip as the peer address, the two
// etcd ports — and that neither flag leaves the kine posture (a nil block).
func TestServerEtcdConfigFromFlags(t *testing.T) {
	base := serverOptions{nodeName: "studio", nodeIP: "192.168.0.50", etcdPeerPort: 12380, etcdMetricsPort: 12381}
	if cfg := base.executorConfig(nil); cfg.Etcd != nil {
		t.Fatalf("no role flag: Etcd = %+v, want nil (the kine posture)", cfg.Etcd)
	}
	for _, tc := range []struct {
		name string
		set  func(*serverOptions)
		want executor.EtcdRole
	}{
		{"cluster-init", func(o *serverOptions) { o.clusterInit = true }, executor.EtcdInit},
		{"server-join", func(o *serverOptions) { o.serverJoin = true }, executor.EtcdJoin},
		{"cluster-reset alone", func(o *serverOptions) { o.clusterReset = true }, executor.EtcdInit},
		{"cluster-reset beside server-join", func(o *serverOptions) { o.clusterReset, o.serverJoin = true, true }, executor.EtcdJoin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			tc.set(&opts)
			e := opts.executorConfig(nil).Etcd
			if e == nil {
				t.Fatal("Etcd = nil, want the etcd posture")
			}
			if e.Role != tc.want || e.Name != "studio" || e.PeerIP != "192.168.0.50" || e.PeerPort != 12380 || e.MetricsPort != 12381 {
				t.Errorf("Etcd = %+v, want role %v, name studio, peer 192.168.0.50:12380, metrics 12381", e, tc.want)
			}
		})
	}
}

// TestServerClusterResetRunsTheResetOnly pins `k3sm server --cluster-reset`: it hands
// the executor the daemon's own work dir and ports in the etcd posture, returns its
// refusal unchanged in the chain, and does nothing else.
func TestServerClusterResetRunsTheResetOnly(t *testing.T) {
	opts := serverOptions{clusterReset: true, workDir: t.TempDir(), nodeName: "studio", nodeIP: "192.168.0.50", kinePort: 12379, etcdPeerPort: 12380, etcdMetricsPort: 12381}
	var got executor.Config
	calls := 0
	clusterResetFunc = func(_ context.Context, cfg executor.Config) error {
		calls++
		got = cfg
		return executor.ErrClusterResetFailed
	}
	t.Cleanup(func() { clusterResetFunc = executor.ClusterReset })
	err := runClusterReset(opts, nil)
	if !errors.Is(err, executor.ErrClusterResetFailed) {
		t.Fatalf("runClusterReset = %v, want ErrClusterResetFailed in the chain", err)
	}
	if calls != 1 {
		t.Fatalf("reset ran %d times, want 1", calls)
	}
	if got.WorkDir != opts.workDir || got.KinePort != 12379 || got.Etcd == nil || got.Etcd.PeerPort != 12380 || got.Etcd.Name != "studio" {
		t.Errorf("reset Config = %+v (etcd %+v), want the daemon's work dir and ports in the etcd posture", got, got.Etcd)
	}
}
