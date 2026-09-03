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
	"sync"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestStartServiceInformerStopsItsInformerOnFailure is the regression for netd's
// endless `Unauthorized` log. activateServiceAuthorizer retries startServiceInformer
// on a timer, and the informer used to be started against the DAEMON context — so
// every attempt that failed to sync left its reflector running for the process's
// life, re-listing with the credential it had read, while the next attempt started
// another one. netd boots before the server rewrites its kubeconfig, so this fired
// on every install.
//
// A failed attempt must leave nothing behind: after the error returns, the reflector
// must make no further List calls.
func TestStartServiceInformerStopsItsInformerOnFailure(t *testing.T) {
	cs := fake.NewClientset()
	var mu sync.Mutex
	lists := 0
	// The apiserver rejects the credential — exactly what netd sees when it holds a
	// kubeconfig whose token the server has since re-minted.
	cs.PrependReactor("list", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		lists++
		mu.Unlock()
		return true, nil, apierrors.NewUnauthorized("the token in this kubeconfig is no longer the server's")
	})
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return lists
	}

	if _, err := runServiceInformer(context.Background(), cs, 50*time.Millisecond); err == nil {
		t.Fatal("runServiceInformer must fail when the cache cannot sync")
	}
	// Non-vacuity: an informer that never listed would pass the assertion below for
	// the wrong reason.
	settled := count()
	if settled == 0 {
		t.Fatal("the informer never listed; this test would prove nothing")
	}
	// The reflector's own retry backoff starts at ~800ms, so a second List would
	// land inside this window if the failed attempt were still running. It cannot
	// be flaky in the passing direction: runServiceInformer's teardown calls
	// Shutdown, which does not return until the goroutines are gone.
	time.Sleep(1500 * time.Millisecond)
	if got := count(); got != settled {
		t.Errorf("the failed attempt kept listing after it returned (%d -> %d); its reflector outlived the attempt", settled, got)
	}
}

// TestStartServiceInformerKeepsTheInformerItReturns is the other half of the
// contract: the attempt that SUCCEEDS must leave its informer running, because the
// lister it hands back is only useful while something keeps feeding it.
func TestStartServiceInformerKeepsTheInformerItReturns(t *testing.T) {
	cs := fake.NewClientset()
	var mu sync.Mutex
	lists := 0
	cs.PrependReactor("list", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		lists++
		mu.Unlock()
		return false, nil, nil // fall through to the tracker: an empty, syncable list
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lister, err := runServiceInformer(ctx, cs, 10*time.Second)
	if err != nil {
		t.Fatalf("runServiceInformer against a healthy apiserver: %v", err)
	}
	if lister == nil {
		t.Fatal("a successful sync must return a lister")
	}
	mu.Lock()
	got := lists
	mu.Unlock()
	if got == 0 {
		t.Error("the returned lister is backed by an informer that never listed")
	}
}
