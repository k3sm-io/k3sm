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

// M6 synthetic conformance criteria (DESIGN §9 M6; docs/PHASES.md M6.0/M6.1) — HA:
// embedded etcd (one member per server, learner join + promotion) and leader
// election. These are LAB-tier (hack/lab/m6.sh, K3SM_LAB=1): they need TWO
// control-plane servers, A (--cluster-init) and B (--server-join). $KUBECONFIG points
// at server A; $K3SM_KUBECONFIG_B at server B. A criterion SKIPS (which the
// non-vacuous guard turns RED under K3SM_LAB — "you said you have the rig, prove
// it") unless its inputs are provided.
//
// On two Macs this proves the mechanics (join, TLS, replication, leader election,
// quorum loss, recovery, reset, cold restart), not fault tolerance: two voting
// members tolerate zero failures. The quorum-loss, recovery, reset and cold-restart
// legs stop daemons, so they live in hack/lab/m6.sh; the API-verifiable halves live
// here.
//
// The etcd client listener is loopback-only, so nothing here dials etcd. The script
// asks each server's own member, on that host's loopback with that host's
// client.crt, and hands this suite the answers as files: the member list
// ($K3SM_M6_MEMBERS_A / _B) and the etcd CA certificates ($K3SM_M6_ETCD_CA_A / _B,
// directories holding server-ca.crt and peer-ca.crt).
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/certs"
)

// serverBClient connects to the SECOND HA control-plane server via
// $K3SM_KUBECONFIG_B, skipping when it is unset (single-server run — the two-server
// criteria cannot be proven). Each server's apiserver talks to its own etcd member,
// and the members replicate, so a client of either observes the same data.
func serverBClient(t *testing.T) kubernetes.Interface {
	t.Helper()
	kb := os.Getenv("K3SM_KUBECONFIG_B")
	if kb == "" {
		t.Skip("M6: $K3SM_KUBECONFIG_B unset — the second HA server's kubeconfig is required for the two-server criteria")
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

// TestM6_WriteOnAReadOnB proves replication: a write committed through server A's
// apiserver (into A's etcd member) is read through server B's apiserver (from B's
// member).
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
	// unset) is a quorum read of etcd, so a small bound covers B's apiserver catching
	// up.
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
		t.Fatalf("server B never read server A's write %q (last %q) — the members are not replicating", want, last)
	}
}

// TestM6_LeaderElectionSingleActive proves leader election is ON in HA: the
// scheduler and controller-manager hold their coordination.k8s.io Leases in
// kube-system. With --leader-elect=false (single-node) those components run WITHOUT a
// Lease, so a held Lease is direct evidence the HA posture took effect — and the two
// servers therefore do NOT both run active schedulers/KCMs. When server B is present,
// both servers resolve the SAME holder (one etcd cluster yields one leader).
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
// kubeconfig, not the loopback token kubeconfig). The etcd CA pins are compared
// from the CA files hack/lab/m6.sh collects from each server.
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

	// Bundle v2 carries the two etcd CAs: both servers must hold the same etcd server
	// CA and the same etcd peer CA (a joining server that minted its own would be
	// refused by every peer and could not read the cluster's client listener).
	dirA, dirB := os.Getenv("K3SM_M6_ETCD_CA_A"), os.Getenv("K3SM_M6_ETCD_CA_B")
	if dirA == "" || dirB == "" {
		t.Skip("M6.1: $K3SM_M6_ETCD_CA_A / $K3SM_M6_ETCD_CA_B unset — each server's tls/etcd/server-ca.crt and peer-ca.crt are required (hack/lab/m6.sh collects them)")
	}
	for _, name := range []string{"server-ca.crt", "peer-ca.crt"} {
		pinA, pinB := caPin(t, filepath.Join(dirA, name)), caPin(t, filepath.Join(dirB, name))
		if pinA != pinB {
			t.Errorf("etcd %s differs between the servers (A pin %s, B pin %s) — the second server did not import the etcd CAs from the bundle", name, pinA, pinB)
		}
	}
	if caPin(t, filepath.Join(dirA, "server-ca.crt")) == caPin(t, filepath.Join(dirA, "peer-ca.crt")) {
		t.Error("the etcd server CA and the etcd peer CA are the same certificate; they must be distinct roots")
	}
}

// caPin returns the pin of the CA certificate at path.
func caPin(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	pin, err := certs.CertPin(b)
	if err != nil {
		t.Fatalf("pin %s: %v", path, err)
	}
	return pin
}

// etcdMemberList is the part of etcd's v3 JSON gateway member-list answer
// (POST /v3/cluster/member/list) this suite reads. The gateway renders uint64s as
// strings and omits zero values, so an absent isLearner is a voting member.
type etcdMemberList struct {
	Header struct {
		ClusterID string `json:"cluster_id"`
		MemberID  string `json:"member_id"`
	} `json:"header"`
	Members []struct {
		ID         string   `json:"ID"`
		Name       string   `json:"name"`
		PeerURLs   []string `json:"peerURLs"`
		ClientURLs []string `json:"clientURLs"`
		IsLearner  bool     `json:"isLearner"`
	} `json:"members"`
}

// TestM6_EtcdTwoVotingMembers proves the join and the promotion: each server's own
// member, asked on its own loopback with a linearizable member list, reports the same
// cluster of exactly two STARTED VOTING members (a name and a client URL each, no
// learner), and answers as one of them.
func TestM6_EtcdTwoVotingMembers(t *testing.T) {
	pathA, pathB := os.Getenv("K3SM_M6_MEMBERS_A"), os.Getenv("K3SM_M6_MEMBERS_B")
	if pathA == "" || pathB == "" {
		t.Skip("M6: $K3SM_M6_MEMBERS_A / $K3SM_M6_MEMBERS_B unset — each server's member-list answer is required (hack/lab/m6.sh collects them)")
	}
	var clusterID string
	names := map[string]map[string]bool{}
	for server, path := range map[string]string{"A": pathA, "B": pathB} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("server %s member list: %v", server, err)
		}
		var ml etcdMemberList
		if err := json.Unmarshal(raw, &ml); err != nil {
			t.Fatalf("server %s member list %s: %v", server, path, err)
		}
		if ml.Header.ClusterID == "" {
			t.Fatalf("server %s member list carries no cluster id (not an etcd answer): %s", server, raw)
		}
		if clusterID == "" {
			clusterID = ml.Header.ClusterID
		} else if ml.Header.ClusterID != clusterID {
			t.Fatalf("servers A and B are in DIFFERENT etcd clusters (%s vs %s)", clusterID, ml.Header.ClusterID)
		}
		if len(ml.Members) != 2 {
			t.Fatalf("server %s sees %d members, want 2: %s", server, len(ml.Members), raw)
		}
		self := false
		names[server] = map[string]bool{}
		for _, m := range ml.Members {
			if m.IsLearner {
				t.Errorf("server %s: member %s (%s) is still a learner — the promotion did not happen", server, m.Name, m.ID)
			}
			if m.Name == "" || len(m.ClientURLs) == 0 {
				t.Errorf("server %s: member %s at %v never started", server, m.ID, m.PeerURLs)
			}
			names[server][m.Name] = true
			self = self || m.ID == ml.Header.MemberID
		}
		if !self {
			t.Errorf("server %s answered as member %s, which is not in its own member list", server, ml.Header.MemberID)
		}
	}
	for name := range names["A"] {
		if !names["B"][name] {
			t.Errorf("member %s is in A's list but not in B's", name)
		}
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

// TestM6_WatchStalenessSoak is the cross-server read-after-write smoke: under
// sustained churn, a consistent LIST on server B taken immediately after server A's
// committed write MUST reflect that write. It writes a unique ConfigMap on A and
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

	// Background churn: unrelated writes on A keep etcd and the watch caches busy.
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
			t.Fatalf("round %d: server B's consistent LIST did not reflect server A's committed write %q (watch staleness)", round, name)
		}
	}
}
