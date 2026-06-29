//go:build e2e

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

// M6 synthetic conformance criteria (DESIGN §9 M6; docs/PHASES.md M6.0) — HA:
// kine→Postgres multi-writer datastore + leader election. These are LAB-tier
// (hack/lab/m6.sh, K3SM_LAB=1): they need TWO control-plane servers sharing ONE
// Postgres. $KUBECONFIG points at server A; $K3SM_KUBECONFIG_B at server B. A
// criterion SKIPS (which the non-vacuous guard turns RED under K3SM_LAB — "you said
// you have the rig, prove it") unless server B's kubeconfig is provided.
//
// The M6.0 acceptance is: two servers run against one Postgres; a write on A is read
// on B; killing A leaves the cluster serving via B. The kill-A→serve-via-B failover
// is an operator step in hack/lab/m6.sh (it stops server A's daemon, then re-checks
// /healthz on B); the API-verifiable halves live here.
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// serverBClient connects to the SECOND HA control-plane server via
// $K3SM_KUBECONFIG_B, skipping when it is unset (single-server run — the multi-writer
// criteria cannot be proven). Both servers share one Postgres, so a client of either
// observes the same datastore.
func serverBClient(t *testing.T) kubernetes.Interface {
	t.Helper()
	kb := os.Getenv("K3SM_KUBECONFIG_B")
	if kb == "" {
		t.Skip("M6: $K3SM_KUBECONFIG_B unset — the second HA server's kubeconfig is required for the multi-writer criteria")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kb)
	if err != nil {
		t.Fatalf("load server-B kubeconfig %s: %v", kb, err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("build server-B client: %v", err)
	}
	return cs
}

// TestM6_WriteOnAReadOnB proves the multi-writer datastore: a write committed on
// server A is read on server B (they share one Postgres — the single source of
// truth). This is the core M6.0 acceptance behavior.
func TestM6_WriteOnAReadOnB(t *testing.T) {
	a := Up(t)            // server A (admin $KUBECONFIG); skips if unset
	b := serverBClient(t) // server B (skips if $K3SM_KUBECONFIG_B unset)
	ctx := context.Background()

	const ns, name = "default", "m6-multiwriter"
	want := fmt.Sprintf("written-on-A-%d", time.Now().UnixNano())
	_ = a.Client.CoreV1().ConfigMaps(ns).Delete(ctx, name, metav1.DeleteOptions{})
	t.Cleanup(func() { _ = a.Client.CoreV1().ConfigMaps(ns).Delete(ctx, name, metav1.DeleteOptions{}) })

	if _, err := a.Client.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Data:       map[string]string{"k": want},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create ConfigMap on server A: %v", err)
	}

	// Server B must observe A's committed write. A consistent read (ResourceVersion
	// unset) goes to the shared datastore, so a small bound covers replication of the
	// apiserver watch caches.
	var last string
	if !pollUntil(15*time.Second, func() bool {
		cm, err := b.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			last = err.Error()
			return false
		}
		last = cm.Data["k"]
		return last == want
	}) {
		t.Fatalf("server B never read server A's write %q (last %q) — the datastore is not shared/consistent", want, last)
	}
}

// TestM6_LeaderElectionSingleActive proves leader election is ON in HA: the
// scheduler and controller-manager hold their coordination.k8s.io Leases in
// kube-system. With --leader-elect=false (single-node) those components run WITHOUT a
// Lease, so a held Lease is direct evidence the HA posture took effect — and the two
// servers therefore do NOT both run active schedulers/KCMs. When server B is present,
// both servers resolve the SAME holder (the shared datastore yields one leader).
func TestM6_LeaderElectionSingleActive(t *testing.T) {
	a := Up(t)
	ctx := context.Background()

	for _, lease := range []string{"kube-scheduler", "kube-controller-manager"} {
		l, err := a.Client.CoordinationV1().Leases("kube-system").Get(ctx, lease, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			t.Fatalf("Lease kube-system/%s not found — leader election is OFF (not the HA posture)", lease)
		}
		if err != nil {
			t.Fatalf("get Lease kube-system/%s: %v", lease, err)
		}
		if l.Spec.HolderIdentity == nil || *l.Spec.HolderIdentity == "" {
			t.Errorf("Lease kube-system/%s has no holder — no active leader", lease)
			continue
		}
		// If server B is reachable, it must resolve the SAME leader (single active).
		if kb := os.Getenv("K3SM_KUBECONFIG_B"); kb != "" {
			b := serverBClient(t)
			lb, err := b.CoordinationV1().Leases("kube-system").Get(ctx, lease, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get Lease kube-system/%s on server B: %v", lease, err)
			}
			if lb.Spec.HolderIdentity == nil || *lb.Spec.HolderIdentity != *l.Spec.HolderIdentity {
				t.Errorf("Lease %s: server A holder %v != server B holder %v (not a single active leader)", lease, *l.Spec.HolderIdentity, lb.Spec.HolderIdentity)
			}
		}
	}
}

// TestM6_SecondServerJoinsReconstructsCAs is the M6.1 acceptance (lab-tier): the second
// control-plane server reconstructed the IDENTICAL cluster CA from the first server's
// AES-256-GCM bootstrap bundle. Both servers' admin kubeconfigs (the signing-CA-issued
// client-cert kubeconfigs the HA path writes) must embed the SAME cluster
// certificate-authority-data — direct evidence the joining server rebuilt the identical
// CA hierarchy rather than minting its own divergent one. It needs both kubeconfigs
// ($KUBECONFIG = server A, $K3SM_KUBECONFIG_B = server B), each CA-bearing (the HA admin
// kubeconfig, not the loopback token kubeconfig). The live failover is the m6.sh
// kill-A→serve-via-B leg.
func TestM6_SecondServerJoinsReconstructsCAs(t *testing.T) {
	_ = Up(t)            // skips if $KUBECONFIG unset
	_ = serverBClient(t) // skips if $K3SM_KUBECONFIG_B unset
	caA := clusterCAData(t, os.Getenv("KUBECONFIG"))
	caB := clusterCAData(t, os.Getenv("K3SM_KUBECONFIG_B"))
	if len(caA) == 0 || len(caB) == 0 {
		t.Skip("M6.1: both kubeconfigs must embed the cluster CA (use the HA admin kubeconfig, not the loopback token kubeconfig)")
	}
	if !bytes.Equal(caA, caB) {
		t.Fatalf("server A and server B embed DIFFERENT cluster CAs — the second server did not reconstruct the identical CA from the bundle")
	}
}

// clusterCAData returns the cluster certificate-authority-data the kubeconfig at path
// embeds (empty when it uses insecure-skip / a CA file path).
func clusterCAData(t *testing.T, path string) []byte {
	t.Helper()
	cfg, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load kubeconfig %s: %v", path, err)
	}
	for _, cl := range cfg.Clusters {
		if len(cl.CertificateAuthorityData) > 0 {
			return cl.CertificateAuthorityData
		}
	}
	return nil
}

// TestM6_WatchStalenessSoak is the PRODUCTION-TRUST gate (the kine#577 failure mode):
// under sustained churn, a consistent LIST on server B taken immediately after server
// A's committed write MUST reflect that write. It writes a unique ConfigMap on A and
// asserts a consistent (ResourceVersion="") LIST on B sees it within a tight bound,
// repeated for $K3SM_M6_SOAK_DURATION (default 20s) while a background goroutine
// churns the namespace. A staleness window (B's consistent read missing A's committed
// write) fails the criterion. Lab-only; skips without server B.
func TestM6_WatchStalenessSoak(t *testing.T) {
	a := Up(t)
	b := serverBClient(t)
	ctx := context.Background()

	dur := 20 * time.Second
	if v := os.Getenv("K3SM_M6_SOAK_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			dur = d
		}
	}
	const ns = "default"

	// Background churn: unrelated writes on A keep the datastore + watch caches busy.
	churnCtx, stopChurn := context.WithCancel(ctx)
	defer stopChurn()
	go func() {
		for i := 0; churnCtx.Err() == nil; i++ {
			name := fmt.Sprintf("m6-churn-%d", i%8)
			cm, err := a.Client.CoreV1().ConfigMaps(ns).Get(churnCtx, name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				_, _ = a.Client.CoreV1().ConfigMaps(ns).Create(churnCtx,
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}, metav1.CreateOptions{})
			} else if err == nil {
				cm.Data = map[string]string{"i": fmt.Sprint(i)}
				_, _ = a.Client.CoreV1().ConfigMaps(ns).Update(churnCtx, cm, metav1.UpdateOptions{})
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	t.Cleanup(func() {
		for i := 0; i < 8; i++ {
			_ = a.Client.CoreV1().ConfigMaps(ns).Delete(ctx, fmt.Sprintf("m6-churn-%d", i), metav1.DeleteOptions{})
		}
	})

	deadline := time.Now().Add(dur)
	for round := 0; time.Now().Before(deadline); round++ {
		name := fmt.Sprintf("m6-soak-%d", round)
		if _, err := a.Client.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("soak write on A (round %d): %v", round, err)
		}
		// Consistent LIST on B (ResourceVersion="" => most-recent, not the cache) must
		// reflect A's just-committed write immediately.
		list, err := b.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{ResourceVersion: ""})
		if err != nil {
			t.Fatalf("consistent LIST on B (round %d): %v", round, err)
		}
		seen := false
		for i := range list.Items {
			if list.Items[i].Name == name {
				seen = true
				break
			}
		}
		_ = a.Client.CoreV1().ConfigMaps(ns).Delete(ctx, name, metav1.DeleteOptions{})
		if !seen {
			t.Fatalf("round %d: server B's consistent LIST did not reflect server A's committed write %q (watch-staleness / kine#577)", round, name)
		}
	}
}
