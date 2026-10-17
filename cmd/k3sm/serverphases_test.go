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
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

// TestServerPhaseStopsAreNeverNil pins the contract runServer's unconditional
// `defer stop()` depends on: a phase that started nothing — disabled by its flag,
// or failed to build — still returns a callable stop. A nil one would panic on
// the way out of every bring-up that took that path, masking the real exit.
//
// Only the disabled and failed paths are driven: each enabled path starts a real
// goroutine (a registry child, the worker-join listener, the MLX reconcile).
// startJoinSupervisor's HA path with an unreachable etcd member also starts the
// join listener, so it is not driven here; it shares the same `stop = noStop`
// default as the disabled path below.
func TestServerPhaseStopsAreNeverNil(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A REST config whose client cannot be built: the CA file does not exist.
	badREST := &rest.Config{Host: "https://127.0.0.1:1", TLSClientConfig: rest.TLSClientConfig{
		CAFile: filepath.Join(t.TempDir(), "absent-ca.crt"),
	}}

	for _, tc := range []struct {
		name  string
		start func() func()
	}{
		{"registry disabled (--registry-port 0)", func() func() {
			stop, _ := startServerRegistry(ctx, serverPlan{opts: serverOptions{registryPort: 0}}, nil, false, nil, logger)
			return stop
		}},
		{"registry failed to build (no work dir)", func() func() {
			stop, _ := startServerRegistry(ctx, serverPlan{opts: serverOptions{registryPort: 5000}}, nil, false, nil, logger)
			return stop
		}},
		{"join supervisor disabled (no mesh enroller)", func() func() {
			return startJoinSupervisor(ctx, serverPlan{}, nil, serverMesh{}, logger)
		}},
		{"embedded add-on reconciler failed to build its clients", func() func() {
			return startEmbeddedAddons(ctx, serverPlan{}, badREST, fake.NewSimpleClientset(), logger)
		}},
		{"interconnect resolver failed to build its clients", func() func() {
			return startInterconnectResolver(ctx, serverPlan{}, badREST, nil, logger)
		}},
		{"mlx operator failed to build its clients", func() func() {
			gpu, stop := startMLXOperator(ctx, serverPlan{}, badREST, nil, logger)
			if gpu == nil {
				t.Error("startMLXOperator returned a nil GPU source; the node's attachRuntimeInfo would panic")
			}
			return stop
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stop := tc.start()
			if stop == nil {
				t.Fatal("stop is nil; runServer's `defer stop()` would panic on this path")
			}
			stop()
		})
	}
}

// TestAddonPosture pins the facts the gated embedded add-ons key on. The kubelet
// CA fact is read off what the server minted: its own node's kubelet serving pair
// from the cluster CA (recorded by serverNodeOptions) AND the apiserver's
// cluster-CA serving pair that makes kube-root-ca.crt that CA, on every topology,
// the mesh IP playing no part. No node capability is read, because the add-on is a
// native pod; and a pair not minted yet, a failed node read, or a read showing no
// Node at all is Undecided: only positive evidence may lead to a withdrawal.
func TestAddonPosture(t *testing.T) {
	fact := func(minted bool) *kubeletServingFact {
		f := newKubeletServingFact()
		if minted {
			f.markMinted()
		}
		return f
	}
	withPair := func(p serverPlan) serverPlan {
		p.cfg.ServingCertFile, p.cfg.ServingKeyFile = "/w/tls/apiserver.crt", "/w/tls/apiserver.key"
		return p
	}
	mesh := withPair(serverPlan{opts: serverOptions{meshIP: "100.64.0.1"}, kubeletServing: fact(true)})
	noPair := serverPlan{opts: serverOptions{meshIP: "100.64.0.1"}, kubeletServing: fact(true)}
	// A single-node server mints its node's kubelet serving pair from the cluster
	// CA too, so the verified scrape works there: true.
	singleNode := withPair(serverPlan{kubeletServing: fact(true)})
	kubeletPairPending := withPair(serverPlan{kubeletServing: fact(false)})
	noFact := withPair(serverPlan{})
	node := func(name string, labels map[string]string) *corev1.Node {
		return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
	}
	plainServer := node("k3sm-server", map[string]string{"kubernetes.io/os": "darwin"})
	worker := node("k3sm-worker", map[string]string{"kubernetes.io/os": "darwin"})
	for _, tc := range []struct {
		name      string
		plan      serverPlan
		nodes     []runtime.Object
		listErr   error
		wantCA    bool
		undecided bool
	}{
		{"mesh, a server and a worker", mesh, []runtime.Object{plainServer, worker}, nil, true, false},
		{"mesh, a single server node still decides", mesh, []runtime.Object{plainServer}, nil, true, false},
		{"single-node with the minted kubelet pair", singleNode, []runtime.Object{plainServer}, nil, true, false},
		{"no kubelet serving fact at all", noFact, []runtime.Object{plainServer}, nil, false, false},
		{"the kubelet pair not minted yet is undecided", kubeletPairPending, []runtime.Object{plainServer}, nil, false, true},
		{"mesh ip but no cluster-CA apiserver serving pair", noPair, []runtime.Object{worker}, nil, false, false},
		{"node read fails", mesh, nil, errors.New("connection refused"), true, true},
		{"no Node registered yet is undecided", mesh, nil, nil, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.nodes...)
			if tc.listErr != nil {
				cs.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, tc.listErr })
			}
			got := addonPosture(context.Background(), tc.plan, cs.CoreV1().Nodes())
			if got.ClusterCAKubeletServing != tc.wantCA || (got.Undecided != "") != tc.undecided {
				t.Errorf("addonPosture = %+v, want ClusterCAKubeletServing=%v undecided=%v", got, tc.wantCA, tc.undecided)
			}
			lists := 0
			for _, a := range cs.Actions() {
				if a.GetVerb() == "list" {
					lists++
				}
			}
			if lists != 1 {
				t.Errorf("%d node reads, want exactly one", lists)
			}
		})
	}
}

// TestMintKicksOneImmediateRegatePass pins that the kubelet serving mint runs one
// add-on re-evaluation pass at once rather than on the next RegateInterval tick:
// the ticker here never fires, the first markMinted yields exactly one tick, a
// second mark yields none, and the ticker still flows through afterwards.
func TestMintKicksOneImmediateRegatePass(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	tick := make(chan time.Time)
	fact := newKubeletServingFact()
	ticks, done := regateTicks(ctx, tick, fact.kicked())

	select {
	case <-ticks:
		t.Fatal("a pass ran before the pair was minted")
	case <-time.After(50 * time.Millisecond):
	}
	fact.markMinted()
	select {
	case <-ticks:
	case <-time.After(5 * time.Second):
		t.Fatal("the mint did not kick a pass; the add-ons would wait for the RegateInterval tick")
	}
	fact.markMinted()
	select {
	case <-ticks:
		t.Fatal("a second mark kicked another pass; the kick is once")
	case <-time.After(50 * time.Millisecond):
	}
	want := time.Unix(42, 0)
	go func() { tick <- want }()
	if got := <-ticks; !got.Equal(want) {
		t.Errorf("forwarded tick = %v, want %v", got, want)
	}
	if minted, decided := fact.read(); !minted || !decided {
		t.Errorf("read() = %v, %v after the mint; want true, true", minted, decided)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("regateTicks did not stop when its context ended")
	}
	if _, ok := <-ticks; ok {
		t.Error("the tick channel is not closed after stop")
	}
}
