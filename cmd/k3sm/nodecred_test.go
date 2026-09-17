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
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/nodecred"
)

// The restart gate: a joined agent that restarts must present the credential it
// already holds, not re-run its join.
//
// The defect: runAgent ran the full token join on EVERY start and persisted only
// the kubeconfig, so a restart after the join token's TTL (24h by default) failed
// with "join rejected (401)" — and under a KeepAlive LaunchDaemon that is a spawn
// loop, not a stopped node. The two halves of the fix are both asserted here: the
// store persists the whole join outcome and loads it back intact, and
// agentStartPlan chooses reuse over a join whenever a usable credential exists.
//
// What this test is NOT: a live restart. A real server + agent bring-up is the lab
// tier (TestIntegrationAgentRestartReusesItsNodeCredential, `integration &&
// darwin`, root + K3SM_LAB=1). So this is the strongest HERMETIC version — real
// CA-issued certificates through pkg/certs, a real work dir, the real writer and
// the real reader — and it covers what a one-host test can actually decide: that
// nothing is lost between save and load, that the node wiring a restart feeds
// downstream is the wiring a join fed, and that every branch of the start
// decision is the intended one.

const (
	nodeCredTestNode  = "k3sm-restart-worker"
	nodeCredTestAPI   = "https://100.64.1.1:6444"
	nodeCredPodCIDR   = "100.64.2.0/24"
	nodeCredMeshIP    = "100.64.2.1"
	nodeCredClientTTL = 365 * 24 * time.Hour
)

// nodeCredFixture mints a synthetic but REAL join outcome: a cluster CA that
// issues the kubelet serving pair (the anchor an apiserver started with
// --kubelet-certificate-authority verifies :10250 against) and a separate signing
// CA that issues the system:node client cert, exactly as the two-CA hierarchy
// does. It returns the result and both CAs so a test can compare pins.
func nodeCredFixture(t *testing.T, clientTTL, servingTTL time.Duration) (*bootstrap.JoinResult, *certs.CA, *certs.CA) {
	t.Helper()
	clusterCA, err := certs.NewCA("k3sm-restart-cluster-ca")
	if err != nil {
		t.Fatalf("mint the cluster CA: %v", err)
	}
	signingCA, err := certs.NewCA("k3sm-restart-signing-ca")
	if err != nil {
		t.Fatalf("mint the signing CA: %v", err)
	}
	servingCert, servingKey, err := clusterCA.IssueServing(nodeCredTestNode,
		[]string{nodeCredTestNode, "localhost"},
		[]net.IP{net.ParseIP(nodeCredMeshIP)}, servingTTL)
	if err != nil {
		t.Fatalf("issue the kubelet serving pair: %v", err)
	}
	clientCert, clientKey, err := signingCA.IssueClient("system:node:"+nodeCredTestNode,
		[]string{"system:nodes"}, clientTTL)
	if err != nil {
		t.Fatalf("issue the node client cert: %v", err)
	}
	return &bootstrap.JoinResult{
		NodeName:              nodeCredTestNode,
		ClusterCAPEM:          clusterCA.CertPEM,
		ClientCAPEM:           signingCA.CertPEM,
		NodeClientCertPEM:     clientCert,
		NodeClientKeyPEM:      clientKey,
		KubeletServingCertPEM: servingCert,
		KubeletServingKeyPEM:  servingKey,
		PodCIDR:               nodeCredPodCIDR,
		MeshIP:                nodeCredMeshIP,
		Peers: []netv1.MeshPeerSpec{
			{NodeName: "k3sm-restart-server", PodCIDR: "100.64.1.0/24", MeshIP: "100.64.1.1", Endpoint: "192.0.2.10:51820"},
		},
		WGPrivateKeyB64: "join-time-private-key",
		APIServers:      []string{"100.64.1.1:6444"},
	}, clusterCA, signingCA
}

// savedStore writes one join outcome into a fresh work dir and returns the store.
func savedStore(t *testing.T, res *bootstrap.JoinResult) nodeCredentialStore {
	t.Helper()
	store := nodeCredentialStore{dir: t.TempDir()}
	if err := store.Save(nodeCredTestAPI, nodeCredTestNode, res); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return store
}

func TestAgentRestartReusesItsNodeCredential(t *testing.T) {
	t.Parallel()

	t.Run("the store round-trips the whole join outcome", func(t *testing.T) {
		t.Parallel()
		res, clusterCA, signingCA := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		store := savedStore(t, res)

		status, cred, err := store.Status(time.Now())
		if err != nil {
			t.Fatalf("Status after Save: %v", err)
		}
		if status != credentialValid {
			t.Fatalf("Status after Save = %s, want valid", status)
		}

		// Every byte a restart needs. The serving pair and the client CA are the
		// three artifacts the old code never persisted at all, which is why a
		// restart had no way to rebuild the node options without re-joining.
		for _, c := range []struct {
			what      string
			got, want []byte
		}{
			{"cluster CA", cred.ClusterCAPEM, res.ClusterCAPEM},
			{"node client cert", cred.ClientCertPEM, res.NodeClientCertPEM},
			{"node client key", cred.ClientKeyPEM, res.NodeClientKeyPEM},
			{"kubelet serving cert", cred.ServingCertPEM, res.KubeletServingCertPEM},
			{"kubelet serving key", cred.ServingKeyPEM, res.KubeletServingKeyPEM},
			{"kubelet client CA", cred.ClientCAPEM, res.ClientCAPEM},
		} {
			if !bytes.Equal(c.got, c.want) {
				t.Errorf("loaded %s does not match what was saved", c.what)
			}
		}
		if cred.APIServerURL != nodeCredTestAPI {
			t.Errorf("apiserverURL = %q, want %q", cred.APIServerURL, nodeCredTestAPI)
		}
		if cred.ClusterCAPin != clusterCA.PinHash() {
			t.Errorf("clusterCAPin = %q, want the cluster CA's pin %q", cred.ClusterCAPin, clusterCA.PinHash())
		}
		if cred.ClusterCAPin == signingCA.PinHash() {
			t.Error("clusterCAPin equals the SIGNING CA's pin: a token is compared against the CLUSTER CA")
		}

		// The server-assigned half. It cannot be re-read from the apiserver at
		// start (the worker's kubeconfig points at the server's mesh address,
		// reachable only once the mesh these values build is up), so losing it
		// would make the reuse path impossible however good the certs were.
		if cred.Assignment.PodCIDR != res.PodCIDR || cred.Assignment.MeshIP != res.MeshIP {
			t.Errorf("assignment = %s/%s, want %s/%s",
				cred.Assignment.PodCIDR, cred.Assignment.MeshIP, res.PodCIDR, res.MeshIP)
		}
		if len(cred.Assignment.APIServers) != 1 || cred.Assignment.APIServers[0] != res.APIServers[0] {
			t.Errorf("assignment APIServers = %v, want %v", cred.Assignment.APIServers, res.APIServers)
		}
		if len(cred.Assignment.Peers) != 1 || cred.Assignment.Peers[0].NodeName != res.Peers[0].NodeName ||
			cred.Assignment.Peers[0].Endpoint != res.Peers[0].Endpoint {
			t.Errorf("assignment Peers = %+v, want the join snapshot %+v", cred.Assignment.Peers, res.Peers)
		}

		// The secret halves are 0600; a CA certificate is public material at 0644.
		for _, c := range []struct {
			path string
			want os.FileMode
		}{
			{store.kubeconfigPath(), 0o600},
			{store.servingCertPath(), 0o600},
			{store.servingKeyPath(), 0o600},
			{store.clientCAPath(), 0o644},
		} {
			fi, err := os.Stat(c.path)
			if err != nil {
				t.Fatalf("stat %s: %v", c.path, err)
			}
			if fi.Mode().Perm() != c.want {
				t.Errorf("%s mode = %o, want %o", filepath.Base(c.path), fi.Mode().Perm(), c.want)
			}
		}
	})

	t.Run("a restart rebuilds the same node wiring without a join", func(t *testing.T) {
		t.Parallel()
		res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		store := savedStore(t, res)
		_, cred, err := store.Status(time.Now())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}

		// What agentResumeFromCredential feeds downstream, minus the network leg.
		resumed := joinResultFrom(cred, nodeCredTestNode, "restart-time-private-key", "restart-time-public-key")

		// The refusal runAgent applies to both paths must pass on a resumed
		// credential: a restart that lost the serving pair would register Ready with
		// an unusable :10250.
		if err := requireJoinedServingPair(resumed); err != nil {
			t.Fatalf("requireJoinedServingPair on the resumed credential: %v", err)
		}

		opts := agentOptions{
			nodeName:  nodeCredTestNode,
			nodeIP:    nodeCredMeshIP,
			workDir:   store.dir,
			podRoot:   filepath.Join(store.dir, "pods"),
			clusterIP: "10.43.0.10",
			domain:    "cluster.local",
			rtName:    "runtimed",
		}
		nodeOpts := agentNodeOptions(opts, resumed, store.kubeconfigPath(), hostnet.Mode{Backend: hostnet.BackendNone}, nil)

		if !bytes.Equal(nodeOpts.kubeletServingCertPEM, res.KubeletServingCertPEM) ||
			!bytes.Equal(nodeOpts.kubeletServingKeyPEM, res.KubeletServingKeyPEM) {
			t.Error("the restarted node does not serve :10250 with the CLUSTER-CA-issued pair it was issued at join")
		}
		if !bytes.Equal(nodeOpts.kubeletClientCAPEM, res.ClientCAPEM) {
			t.Error("the restarted node has no client-identity CA anchor: startNode refuses, and it should not have to")
		}
		if nodeOpts.podCIDR != res.PodCIDR {
			t.Errorf("podCIDR = %q, want the join-assigned %q (the mesh AllowedIPs and the pod IPAM are one value)", nodeOpts.podCIDR, res.PodCIDR)
		}
		if nodeOpts.kubeconfig != store.kubeconfigPath() {
			t.Errorf("kubeconfig = %q, want the stored %q", nodeOpts.kubeconfig, store.kubeconfigPath())
		}
		if !nodeOpts.serveTLS {
			t.Error("serveTLS = false on a restarted worker")
		}

		// The mesh identity is the node's PERSISTED key, never a per-start mint:
		// the public key derived from it is what every peer programs.
		if resumed.WGPrivateKeyB64 != "restart-time-private-key" {
			t.Errorf("WGPrivateKeyB64 = %q, want the persisted key the caller passed", resumed.WGPrivateKeyB64)
		}
		// The proxy's mesh-egress source survives the restart too.
		cfg := workerNetserveConfig(opts, resumed, hostnet.Mode{Backend: hostnet.BackendDirect}, false, nil)
		if cfg.MeshEgressIP != res.MeshIP || cfg.PodCIDR != res.PodCIDR {
			t.Errorf("netserve config = %s/%s, want the stored assignment %s/%s",
				cfg.MeshEgressIP, cfg.PodCIDR, res.MeshIP, res.PodCIDR)
		}
	})

	t.Run("an incomplete store is absent, never half-usable", func(t *testing.T) {
		t.Parallel()
		res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		for _, missing := range []string{
			nodecred.KubeconfigFile, nodecred.ServingCertFile, nodecred.ServingKeyFile,
			nodecred.ClientCAFile, nodecred.NodeAssignmentFile,
		} {
			t.Run("without "+missing, func(t *testing.T) {
				t.Parallel()
				store := savedStore(t, res)
				if err := os.Remove(filepath.Join(store.dir, missing)); err != nil {
					t.Fatalf("remove %s: %v", missing, err)
				}
				status, cred, err := store.Status(time.Now())
				if err != nil {
					t.Fatalf("Status with %s removed: %v (a missing file is absent, not corrupt)", missing, err)
				}
				if status != credentialAbsent || cred != nil {
					t.Errorf("Status with %s removed = %s (cred!=nil: %v), want absent", missing, status, cred != nil)
				}
			})
		}
	})

	t.Run("expiry", func(t *testing.T) {
		t.Parallel()
		// A 48h client cert makes both boundaries reachable from one fixture: inside
		// the 24h margin, and past NotAfter.
		res, _, _ := nodeCredFixture(t, 48*time.Hour, nodeCredClientTTL)
		store := savedStore(t, res)

		for _, tc := range []struct {
			name string
			at   time.Time
			want credentialStatus
		}{
			{"well inside its validity → valid", time.Now(), credentialValid},
			{"inside the 24h margin before NotAfter → expired", time.Now().Add(30 * time.Hour), credentialExpired},
			{"past the client cert's NotAfter → expired", time.Now().Add(49 * time.Hour), credentialExpired},
		} {
			t.Run(tc.name, func(t *testing.T) {
				status, cred, err := store.Status(tc.at)
				if err != nil {
					t.Fatalf("Status: %v", err)
				}
				if status != tc.want {
					t.Errorf("Status = %s, want %s", status, tc.want)
				}
				if cred == nil {
					t.Error("Status returned no credential: an expired credential still parsed, and the caller logs what it holds")
				}
			})
		}

		t.Run("a serving cert past NotAfter → expired even with a long-lived client cert", func(t *testing.T) {
			t.Parallel()
			res, _, _ := nodeCredFixture(t, nodeCredClientTTL, 2*time.Hour)
			store := savedStore(t, res)
			status, _, err := store.Status(time.Now().Add(3 * time.Hour))
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if status != credentialExpired {
				t.Errorf("Status = %s, want expired — an expired :10250 cert breaks every kubectl logs/exec against this node", status)
			}
		})
	})

	t.Run("corruption is a hard error naming the file", func(t *testing.T) {
		t.Parallel()

		t.Run("a truncated serving key", func(t *testing.T) {
			t.Parallel()
			res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
			store := savedStore(t, res)
			if err := os.WriteFile(store.servingKeyPath(), res.KubeletServingKeyPEM[:40], 0o600); err != nil {
				t.Fatalf("truncate the serving key: %v", err)
			}
			status, cred, err := store.Status(time.Now())
			if err == nil {
				t.Fatal("Status accepted a truncated serving key: a re-mint on unreadable state would destroy the evidence and re-issue this node's identity")
			}
			if status != credentialCorrupt || cred != nil {
				t.Errorf("Status = %s (cred!=nil: %v), want corrupt with no credential", status, cred != nil)
			}
			if !strings.Contains(err.Error(), nodecred.ServingCertFile) && !strings.Contains(err.Error(), nodecred.ServingKeyFile) {
				t.Errorf("error %q names neither serving file", err)
			}
			if !strings.Contains(err.Error(), "remove it to force a fresh token join") {
				t.Errorf("error %q carries no remedy", err)
			}
		})

		t.Run("a client key that does not match its certificate", func(t *testing.T) {
			t.Parallel()
			res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
			other, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
			res.NodeClientKeyPEM = other.NodeClientKeyPEM
			store := savedStore(t, res)
			status, _, err := store.Status(time.Now())
			if err == nil {
				t.Fatal("Status accepted a mismatched client keypair: it authenticates as nothing, and would surface as an opaque apiserver handshake failure long after start")
			}
			if status != credentialCorrupt {
				t.Errorf("Status = %s, want corrupt", status)
			}
			if !strings.Contains(err.Error(), nodecred.KubeconfigFile) {
				t.Errorf("error %q does not name %s", err, nodecred.KubeconfigFile)
			}
		})

		t.Run("an unparseable assignment", func(t *testing.T) {
			t.Parallel()
			res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
			store := savedStore(t, res)
			if err := os.WriteFile(store.assignmentPath(), []byte("{not json"), 0o644); err != nil {
				t.Fatalf("corrupt the assignment: %v", err)
			}
			status, _, err := store.Status(time.Now())
			if err == nil || status != credentialCorrupt {
				t.Fatalf("Status = %s, err = %v; want corrupt with an error", status, err)
			}
			if !strings.Contains(err.Error(), nodecred.NodeAssignmentFile) {
				t.Errorf("error %q does not name %s", err, nodecred.NodeAssignmentFile)
			}
		})
	})

	t.Run("a restart that changes nothing rewrites nothing", func(t *testing.T) {
		t.Parallel()
		res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		store := savedStore(t, res)

		// Backdate every artifact, then re-save exactly what is already there. Save
		// runs on EVERY start now, so the routine case must be a no-op on disk: a
		// file that is not touched cannot be damaged by a crash, and a credential
		// rewritten thousands of times for no reason is thousands of chances to be.
		backdated := time.Now().Add(-48 * time.Hour)
		for _, p := range store.reader().Paths() {
			if err := os.Chtimes(p, backdated, backdated); err != nil {
				t.Fatalf("backdate %s: %v", p, err)
			}
		}
		if err := store.Save(nodeCredTestAPI, nodeCredTestNode, res); err != nil {
			t.Fatalf("second Save: %v", err)
		}
		for _, p := range store.reader().Paths() {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatalf("stat %s: %v", p, err)
			}
			if !fi.ModTime().Equal(backdated) {
				t.Errorf("%s was rewritten by a Save of identical content (mtime moved to %s)",
					filepath.Base(p), fi.ModTime())
			}
		}

		// A changed apiserver URL (an `--api-port` move) still lands.
		if err := store.Save("https://100.64.1.1:6666", nodeCredTestNode, res); err != nil {
			t.Fatalf("Save with a new apiserver URL: %v", err)
		}
		_, cred, err := store.Status(time.Now())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if cred.APIServerURL != "https://100.64.1.1:6666" {
			t.Errorf("apiserverURL = %q, want the newly saved one", cred.APIServerURL)
		}
	})

	t.Run("a save interrupted partway leaves a readable credential", func(t *testing.T) {
		t.Parallel()
		first, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		store := savedStore(t, first)
		second, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)

		// Fail the fourth of the five writes, deterministically and without a seam
		// in the production path: a DIRECTORY sitting where that artifact's staging
		// file must be created cannot be opened as a file. What the save has done by
		// then is what an interruption would have left.
		blocked := store.clientCAPath() + storeTmpSuffix
		if err := os.Mkdir(blocked, 0o755); err != nil {
			t.Fatalf("block the client CA write: %v", err)
		}
		if err := store.Save(nodeCredTestAPI, nodeCredTestNode, second); err == nil {
			t.Fatal("Save reported success while one artifact could not be written")
		}

		// The store is still a credential: parseable, self-consistent, in date. The
		// atomic install is what buys this — a torn file would be corrupt, and a
		// corrupt store is a node that will not start.
		status, cred, err := store.Status(time.Now())
		if err != nil {
			t.Fatalf("Status after an interrupted Save: %v", err)
		}
		if status != credentialValid {
			t.Fatalf("Status after an interrupted Save = %s, want valid", status)
		}

		// Every artifact is WHOLLY one generation or the other, never a prefix.
		if !bytes.Equal(cred.ClientCAPEM, first.ClientCAPEM) {
			t.Error("the artifact whose write failed is not the one that was there before it")
		}
		if !bytes.Equal(cred.ServingCertPEM, second.KubeletServingCertPEM) ||
			!bytes.Equal(cred.ServingKeyPEM, second.KubeletServingKeyPEM) {
			t.Error("an artifact written before the failure is neither the old nor the new one: a write was torn")
		}
		if cred.Assignment.PodCIDR != first.PodCIDR {
			t.Errorf("assignment podCIDR = %q; the write after the failure must not have run", cred.Assignment.PodCIDR)
		}

		// And the retry converges: nothing about the interruption is sticky.
		if err := os.Remove(blocked); err != nil {
			t.Fatalf("unblock: %v", err)
		}
		if err := store.Save(nodeCredTestAPI, nodeCredTestNode, second); err != nil {
			t.Fatalf("Save after unblocking: %v", err)
		}
		status, cred, err = store.Status(time.Now())
		if err != nil || status != credentialValid {
			t.Fatalf("Status after the retry = %s, err %v", status, err)
		}
		if !bytes.Equal(cred.ClientCAPEM, second.ClientCAPEM) || !bytes.Equal(cred.ClientCertPEM, second.NodeClientCertPEM) {
			t.Error("the retried Save did not converge the store on the new credential")
		}
		for _, p := range store.reader().Paths() {
			if _, err := os.Stat(p + storeTmpSuffix); err == nil {
				t.Errorf("%s%s survived a successful save", filepath.Base(p), storeTmpSuffix)
			}
		}
	})

	t.Run("a leftover staging file from a crash is ignored", func(t *testing.T) {
		t.Parallel()
		res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		store := savedStore(t, res)
		for _, p := range store.reader().Paths() {
			if err := os.WriteFile(p+storeTmpSuffix, []byte("half a file"), 0o600); err != nil {
				t.Fatalf("plant a leftover for %s: %v", p, err)
			}
		}
		status, cred, err := store.Status(time.Now())
		if err != nil {
			t.Fatalf("Status with leftover staging files: %v", err)
		}
		if status != credentialValid || !bytes.Equal(cred.ClientCertPEM, res.NodeClientCertPEM) {
			t.Errorf("Status = %s; a leftover staging file must never be read as part of the credential", status)
		}
	})

	t.Run("the start plan", func(t *testing.T) {
		t.Parallel()
		const storedPin = "aa11"
		for _, tc := range []struct {
			name         string
			status       credentialStatus
			tokenPresent bool
			tokenParses  bool
			tokenCAHash  string
			want         startMode
			wantErr      error
		}{
			{
				name:   "valid credential, no token → reuse (the restart this exists for)",
				status: credentialValid, want: startModeReuseCredential,
			},
			{
				name:   "valid credential, token pinning the SAME cluster CA → reuse, token ignored",
				status: credentialValid, tokenPresent: true, tokenParses: true, tokenCAHash: storedPin,
				want: startModeReuseCredential,
			},
			{
				name:   "valid credential, token pinning a DIFFERENT cluster CA → token join (the operator repointed this Mac)",
				status: credentialValid, tokenPresent: true, tokenParses: true, tokenCAHash: "bb22",
				want: startModeTokenJoin,
			},
			{
				name:   "valid credential, unparseable token → reuse (a typo must not stop a joined node)",
				status: credentialValid, tokenPresent: true, tokenParses: false,
				want: startModeReuseCredential,
			},
			{
				name:   "no credential, token → token join",
				status: credentialAbsent, tokenPresent: true, tokenParses: true, tokenCAHash: "bb22",
				want: startModeTokenJoin,
			},
			{
				name:   "no credential, no token → terminal",
				status: credentialAbsent, wantErr: errNoCredentialNoToken,
			},
			{
				name:   "expired credential, token → token join (the certs are re-issued)",
				status: credentialExpired, tokenPresent: true, tokenParses: true, tokenCAHash: storedPin,
				want: startModeTokenJoin,
			},
			{
				name:   "expired credential, no token → terminal",
				status: credentialExpired, wantErr: errExpiredCredential,
			},
			{
				name:   "corrupt credential → terminal even with a token",
				status: credentialCorrupt, tokenPresent: true, tokenParses: true, tokenCAHash: storedPin,
				wantErr: errCorruptCredential,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				got, err := agentStartPlan(tc.status, tc.tokenPresent, tc.tokenParses, tc.tokenCAHash, storedPin)
				if tc.wantErr != nil {
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("err = %v, want %v", err, tc.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatalf("agentStartPlan: %v", err)
				}
				if got != tc.want {
					t.Errorf("mode = %s, want %s", got, tc.want)
				}
			})
		}
	})

	t.Run("the CA-pin comparison is over real pins", func(t *testing.T) {
		t.Parallel()
		// The pin rows above use placeholders; this asserts the value the agent
		// actually feeds them is the stored CLUSTER CA's pin — the same value a K10
		// token carries — so a token minted by this cluster compares equal and one
		// minted by another does not.
		res, clusterCA, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		store := savedStore(t, res)
		_, cred, err := store.Status(time.Now())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		sameCluster, err := bootstrap.ParseToken(bootstrap.FormatToken(clusterCA.PinHash(), "node", "s3cret"))
		if err != nil {
			t.Fatalf("parse a token for this cluster: %v", err)
		}
		mode, err := agentStartPlan(credentialValid, true, true, sameCluster.CAHash, cred.ClusterCAPin)
		if err != nil || mode != startModeReuseCredential {
			t.Errorf("a token for THIS cluster gave (%s, %v), want reuse", mode, err)
		}

		otherCA, err := certs.NewCA("k3sm-restart-other-cluster-ca")
		if err != nil {
			t.Fatalf("mint another cluster's CA: %v", err)
		}
		otherCluster, err := bootstrap.ParseToken(bootstrap.FormatToken(otherCA.PinHash(), "node", "s3cret"))
		if err != nil {
			t.Fatalf("parse a token for another cluster: %v", err)
		}
		mode, err = agentStartPlan(credentialValid, true, true, otherCluster.CAHash, cred.ClusterCAPin)
		if err != nil || mode != startModeTokenJoin {
			t.Errorf("a token for ANOTHER cluster gave (%s, %v), want a token join", mode, err)
		}
	})
}
