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
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/ingresshost"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestBuildServiceSetDenyAllUntilReady proves that when the kubeconfig does not yet
// exist (netd is bootstrapped by launchd BEFORE the _k3sm server writes it), the
// authorizer returns NON-nil predicates that DENY (fail-safe) rather than nil.
// The prior code returned nil predicates permanently, which left every <1024
// infra-VIP bind denied for the daemon's whole life — cluster DNS never came up.
func TestBuildServiceSetDenyAllUntilReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	missing := filepath.Join(t.TempDir(), "does-not-exist.kubeconfig")
	declares, lbDeclarers, _ := buildServiceSet(ctx, missing, quietLogger())

	// The predicates must be non-nil: a nil PortAuthorizer input can never later
	// authorize, so the async swap-in only works if the closures exist up front.
	if declares == nil || lbDeclarers == nil {
		t.Fatal("buildServiceSet returned nil predicates for a not-yet-present kubeconfig; must be non-nil deny-all so the async authorizer can swap in")
	}
	// Deny-all while the lister is nil (the boot window before the swap).
	if declares(443) || len(lbDeclarers(53)) != 0 {
		t.Fatal("expected deny (no declarers) before the Service authorizer syncs")
	}
}

// TestCanonicalLBServiceIsTheIngressService pins the ONE identity the netd
// node-address allowlist is bound to (B133). The assembler must name the very
// Service pkg/ingresshost provisions — a drifted or widened ref here would hand
// the root helper's node-address bind to some other Service, which is exactly
// the permissiveness B133 removed.
func TestCanonicalLBServiceIsTheIngressService(t *testing.T) {
	ref := canonicalLBService()
	if ref.Namespace != ingresshost.ServiceNamespace || ref.Name != ingresshost.ServiceName {
		t.Fatalf("canonicalLBService() = %s, want %s/%s (pkg/ingresshost is the single source)",
			ref, ingresshost.ServiceNamespace, ingresshost.ServiceName)
	}
	if ref.String() != "kube-system/k3sm-ingress" {
		t.Errorf("canonical node-address subject = %s, want kube-system/k3sm-ingress", ref)
	}
}

// TestBuildServiceSetEmptyKubeconfigDenies keeps the documented posture: no
// --kubeconfig configured → nil predicates (netd denies every <1024 bind, the
// existing "no authoritative Service set" contract).
func TestBuildServiceSetEmptyKubeconfigDenies(t *testing.T) {
	declares, lbDeclarers, _ := buildServiceSet(context.Background(), "", quietLogger())
	if declares != nil || lbDeclarers != nil {
		t.Fatal("empty --kubeconfig must yield nil predicates (deny-all, no authoritative set)")
	}
}

// TestStartServiceInformerRetryableOnMissingKubeconfig proves the informer bring-up
// returns a retryable error (does NOT hang) when the kubeconfig is absent — the
// exact boot-race condition activateServiceAuthorizer loops on.
func TestStartServiceInformerRetryableOnMissingKubeconfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := startServiceInformer(ctx, filepath.Join(t.TempDir(), "absent.kubeconfig"))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for a missing kubeconfig")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("startServiceInformer hung on a missing kubeconfig; must return a retryable error")
	}
}
