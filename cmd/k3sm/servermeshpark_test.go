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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/status"
)

// TestEnrollServerMeshFailureKeepsTheMeshIPRange: step 4b seeds the node's pod
// range from --mesh-ip BEFORE the enrol, so whatever the enrol does the range stays
// the one the lo0 alias and the netd seed use. A range another node holds is a
// DATA-PATH refusal (the node, pod network and mesh egress do not start); any other
// mesh fault keeps its survivable, logged posture with no refusal.
func TestEnrollServerMeshFailureKeepsTheMeshIPRange(t *testing.T) {
	t.Run("a held range refuses the data path", func(t *testing.T) {
		api := newMeshPeerAPIStub()
		seedPeer(t, api, "worker-1", "100.64.1.0/24")
		sm := runEnrollServerMesh(t, api, joinedServer, joinedMeshIP)
		if !errors.Is(sm.dataPathRefused, ErrMeshIndexClaimed) {
			t.Fatalf("dataPathRefused = %v, want ErrMeshIndexClaimed", sm.dataPathRefused)
		}
		if sm.podCIDR != "100.64.1.0/24" {
			t.Errorf("podCIDR = %q, want the --mesh-ip range even on a refusal", sm.podCIDR)
		}
		if sm.egressIP != "" {
			t.Errorf("a refused server has mesh egress %q", sm.egressIP)
		}
	})
	t.Run("another mesh fault is survivable and refuses nothing", func(t *testing.T) {
		api := newMeshPeerAPIStub()
		failingList := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == meshPeerAPIPath {
				writeStatus(w, http.StatusInternalServerError, metav1.StatusReasonInternalError)
				return
			}
			api.ServeHTTP(w, r)
		})
		sm := runEnrollServerMesh(t, failingList, joinedServer, joinedMeshIP)
		if sm.dataPathRefused != nil {
			t.Errorf("a list failure refused the data path: %v", sm.dataPathRefused)
		}
		if sm.podCIDR != "100.64.1.0/24" {
			t.Errorf("podCIDR = %q, want the --mesh-ip range", sm.podCIDR)
		}
	})
	t.Run("a --mesh-ip that names no range refuses the data path", func(t *testing.T) {
		sm := runEnrollServerMesh(t, newMeshPeerAPIStub(), joinedServer, "100.64.1.7")
		if !errors.Is(sm.dataPathRefused, errServerMeshIPNoRange) {
			t.Errorf("dataPathRefused = %v, want errServerMeshIPNoRange", sm.dataPathRefused)
		}
	})
	t.Run("the classification", func(t *testing.T) {
		for _, tc := range []struct {
			err  error
			want bool
		}{
			{fmt.Errorf("x: %w", ErrMeshIndexClaimed), true},
			{&meshRangeError{sentinel: bootstrap.ErrMeshClaimRefused, detail: "moved"}, true},
			{fmt.Errorf("y: %w", errServerMeshIPNoRange), true},
			{bootstrap.ErrNodePasswordMismatch, false},
			{errors.New("list mesh peers: 500"), false},
		} {
			if got := isServerMeshDataPathRefusal(tc.err); got != tc.want {
				t.Errorf("isServerMeshDataPathRefusal(%v) = %v, want %v", tc.err, got, tc.want)
			}
		}
	})
}

// TestServerParksTheDataPathWithoutTheBreaker: a parked server says why and what to
// do, then waits for shutdown and returns nil — so runServer's crash check and the
// crash-loop breaker never see it, and etcd keeps this member's vote.
func TestServerParksTheDataPathWithoutTheBreaker(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	refusal := &meshRangeError{sentinel: ErrMeshIndexClaimed, cidr: "100.64.1.0/24", holder: "worker-1", claim: "kube-system/meshrange-1"}
	go func() {
		done <- parkServerDataPath(ctx, serverOptions{nodeName: joinedServer, meshIP: joinedMeshIP}, refusal, logger)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("parkServerDataPath = %v, want nil: a park is not a crash", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parkServerDataPath did not return on shutdown")
	}
	out := buf.String()
	for _, want := range []string{"worker-1", "kube-system/meshrange-1", "--cluster-reset", "launchctl kickstart"} {
		if !strings.Contains(out, want) {
			t.Errorf("the park message does not name %q:\n%s", want, out)
		}
	}
}

// TestMemberRoute409IsPermanent: the existing server's refusal of a held range is a
// PERMANENT member-route failure — the joiner parks instead of re-asking — and its
// remedy is the mesh one, chosen by the refusal reason, never by the message.
func TestMemberRoute409IsPermanent(t *testing.T) {
	refusal := &bootstrap.ServerRouteError{Path: bootstrap.EtcdMemberPath, Status: "409 Conflict", StatusCode: http.StatusConflict,
		Message: "refused: the server's mesh range is held by another node", Reason: bootstrap.RefusalMeshRangeClaimed}
	j := &serverEtcdJoin{
		memberExists: func() bool { return false },
		member: func(context.Context, bootstrap.EtcdMemberRequest) (bootstrap.EtcdMemberResponse, error) {
			return bootstrap.EtcdMemberResponse{}, refusal
		},
		wait: func(context.Context, time.Duration) error {
			t.Fatal("a permanent refusal was retried")
			return nil
		},
	}
	base := executor.Config{WorkDir: t.TempDir(), Etcd: &executor.EtcdConfig{Role: executor.EtcdJoin, Name: joinedServer, PeerIP: "192.0.2.11", PeerPort: 2380}}
	_, err := joinEtcdMember(context.Background(), j, "192.0.2.10", base, quietLogger())
	if !errors.Is(err, errEtcdMemberRoutePermanent) {
		t.Fatalf("err = %v, want a permanent member-route failure", err)
	}
	if got := etcdMemberRouteRemedyFor(err); got != etcdMemberRouteMeshRemedy {
		t.Errorf("remedy = %q, want the mesh remedy", got)
	}
	// The same status without the mesh reason keeps the general remedy.
	other := *refusal
	other.Reason = ""
	if got := etcdMemberRouteRemedyFor(fmt.Errorf("w: %w", &other)); got != etcdMemberRouteRemedy {
		t.Errorf("a 409 with no mesh reason got remedy %q", got)
	}
}

// TestJoinerRefusesAnUnacknowledgedMeshClaim is R5's capability handshake: a joiner
// that sent a mesh claim and got an answer without meshClaim=reserved (an existing
// server that predates claims, which reserved nothing) refuses to start its member,
// permanently, naming the upgrade. With the acknowledgement it proceeds, and a
// joiner with no mesh needs none.
func TestJoinerRefusesAnUnacknowledgedMeshClaim(t *testing.T) {
	base := executor.Config{WorkDir: t.TempDir(), Etcd: &executor.EtcdConfig{Role: executor.EtcdJoin, Name: joinedServer, PeerIP: "192.0.2.11", PeerPort: 2380}}
	claim := joinedClaim()
	run := func(ack string, withClaim bool) (bootstrap.EtcdMemberRequest, error) {
		var sent bootstrap.EtcdMemberRequest
		j := &serverEtcdJoin{
			memberExists: func() bool { return false },
			member: func(_ context.Context, req bootstrap.EtcdMemberRequest) (bootstrap.EtcdMemberResponse, error) {
				sent = req
				return bootstrap.EtcdMemberResponse{MemberID: 0xb, InitialCluster: "a=https://192.0.2.10:2380,laptop=https://192.0.2.11:2380", MeshClaim: ack}, nil
			},
			identity: func(peerIP string) (memberIdentity, error) {
				id := memberIdentity{nodePassword: "pw"}
				if withClaim {
					c := claim
					id.claim = &c
				}
				return id, nil
			},
		}
		_, err := joinEtcdMember(context.Background(), j, "192.0.2.10", base, quietLogger())
		return sent, err
	}

	sent, err := run("", true)
	if !errors.Is(err, errMeshClaimUnacknowledged) || !errors.Is(err, errEtcdMemberRoutePermanent) {
		t.Fatalf("an unacknowledged claim: err = %v, want a permanent errMeshClaimUnacknowledged", err)
	}
	if sent.MeshClaim == nil || sent.NodePassword != "pw" {
		t.Errorf("the request did not carry the claim and the node-password: %+v", sent)
	}
	if got := etcdMemberRouteRemedyFor(err); got != etcdMemberRouteUnacknowledgedRemedy {
		t.Errorf("remedy = %q, want the upgrade remedy", got)
	}
	if _, err := run(bootstrap.MeshClaimReserved, true); err != nil {
		t.Errorf("an acknowledged claim was refused: %v", err)
	}
	if _, err := run("", false); err != nil {
		t.Errorf("a joiner with no mesh claim was refused: %v", err)
	}
}

// TestAbandonedServerClaims is R7's predicate. A claim older than the abandonment
// age is abandoned when it is a server's range with no Ready Node and no etcd member
// (by name, or by the peer host its reservation recorded — all an unstarted learner
// has), or when its holder has no MeshPeer at the range. Everything else is kept:
// this server's own, a young claim, a Ready server, a member, a worker with a peer,
// and any server reservation when the member list is unknown.
func TestAbandonedServerClaims(t *testing.T) {
	e, _ := enrollerOverHandler(t)
	now := time.Now()
	old := metav1.NewMicroTime(now.Add(-20 * time.Minute))
	young := metav1.NewMicroTime(now.Add(-time.Minute))
	claim := func(name, holder, cidr string, at metav1.MicroTime, server bool, peerHost string) coordinationv1.Lease {
		l := coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{}, Annotations: map[string]string{meshRangeClaimPodCIDRAnnotation: cidr}},
			Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, AcquireTime: &at}}
		if server {
			l.Labels[meshPeerServerLabel] = "true"
		}
		if peerHost != "" {
			l.Annotations[meshRangeClaimPeerHostAnnotation] = peerHost
		}
		return l
	}
	peer := func(name, cidr string, server bool) netv1.MeshPeer {
		p := netv1.MeshPeer{Spec: netv1.MeshPeerSpec{NodeName: name, PodCIDR: cidr}}
		p.Name = name
		if server {
			p.Labels = map[string]string{meshPeerServerLabel: "true"}
		}
		return p
	}
	in := abandonedClaimInputs{
		claims: []coordinationv1.Lease{
			claim("meshrange-0", firstServer, "100.64.0.0/24", old, true, ""),
			claim("meshrange-1", "never-joined", "100.64.1.0/24", old, true, "192.0.2.11"),
			claim("meshrange-2", "young", "100.64.2.0/24", young, true, "192.0.2.12"),
			claim("meshrange-3", "ready", "100.64.3.0/24", old, true, "192.0.2.13"),
			claim("meshrange-4", "learner", "100.64.4.0/24", old, true, "192.0.2.14"),
			claim("meshrange-5", "worker-off", "100.64.5.0/24", old, false, ""),
			claim("meshrange-6", "orphan", "100.64.6.0/24", old, false, ""),
		},
		peers: []netv1.MeshPeer{
			peer(firstServer, "100.64.0.0/24", false),
			peer("never-joined", "100.64.1.0/24", true),
			peer("young", "100.64.2.0/24", true),
			peer("ready", "100.64.3.0/24", true),
			peer("learner", "100.64.4.0/24", true),
			peer("worker-off", "100.64.5.0/24", false),
		},
		readyNodes:   map[string]bool{firstServer: true, "ready": true},
		members:      []bootstrap.EtcdMember{{Name: firstServer, PeerURLs: []string{"https://192.0.2.10:2380"}}, {PeerURLs: []string{"https://192.0.2.14:2380"}, IsLearner: true}},
		membersKnown: true,
		self:         firstServer,
		now:          now,
	}
	got := map[string]string{}
	for _, a := range e.abandonedClaims(in) {
		got[a.claim.Name] = a.kind
	}
	want := map[string]string{"meshrange-1": status.MeshClaimServerReservation, "meshrange-6": status.MeshClaimOrphan}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("abandoned = %v, want %v", got, want)
	}
	in.membersKnown = false
	got = map[string]string{}
	for _, a := range e.abandonedClaims(in) {
		got[a.claim.Name] = a.kind
	}
	if fmt.Sprint(got) != fmt.Sprint(map[string]string{"meshrange-6": status.MeshClaimOrphan}) {
		t.Errorf("with no member list, abandoned = %v; want only the orphan", got)
	}
}

// TestAbandonedServerClaimsAreSweptAndRecorded drives the sweep end to end: a
// reservation that never became a member is removed — its MeshPeer and its claim —
// and the record `k3sm status` reads lists what is abandoned between starts.
func TestAbandonedServerClaimsAreSweptAndRecorded(t *testing.T) {
	ctx := context.Background()
	e, api := enrollerOverHandler(t)
	e.nodes = fake.NewClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: firstServer},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}).CoreV1().Nodes()
	if _, err := e.EnrollSelf(ctx, firstServer, firstServerCIDR, enrollRequest(firstServer)); err != nil {
		t.Fatalf("EnrollSelf: %v", err)
	}
	if _, err := e.ReserveServerMesh(ctx, joinedServer, joinedClaim()); err != nil {
		t.Fatalf("ReserveServerMesh: %v", err)
	}
	members := func(context.Context) ([]bootstrap.EtcdMember, error) {
		return []bootstrap.EtcdMember{{Name: firstServer, PeerURLs: []string{"https://192.0.2.10:2380"}}}, nil
	}

	// Young: recorded as nothing, swept as nothing.
	workDir := t.TempDir()
	if err := e.recordAbandonedClaims(ctx, workDir, firstServer, members); err != nil {
		t.Fatalf("record: %v", err)
	}
	if rec := readClaimRecord(t, workDir); len(rec.Abandoned) != 0 {
		t.Errorf("a young reservation was recorded abandoned: %+v", rec.Abandoned)
	}

	api.mu.Lock()
	aged := metav1.NewMicroTime(time.Now().Add(-20 * time.Minute))
	api.leases[meshRangeClaimName(1)].Spec.AcquireTime = &aged
	api.mu.Unlock()

	if err := e.recordAbandonedClaims(ctx, workDir, firstServer, members); err != nil {
		t.Fatalf("record: %v", err)
	}
	rec := readClaimRecord(t, workDir)
	if len(rec.Abandoned) != 1 || rec.Abandoned[0].Holder != joinedServer || rec.Abandoned[0].Kind != status.MeshClaimServerReservation {
		t.Fatalf("record = %+v, want the joined server's reservation", rec.Abandoned)
	}

	left, err := e.SweepAbandonedClaims(ctx, firstServer, members)
	if err != nil || len(left) != 0 {
		t.Fatalf("sweep: left %d, %v", len(left), err)
	}
	if api.peer(joinedServer) != nil || api.lease(meshRangeClaimName(1)) != nil {
		t.Error("the abandoned reservation's MeshPeer or claim survived the sweep")
	}
	if api.peer(firstServer) == nil || api.lease(meshRangeClaimName(0)) == nil {
		t.Error("the sweep removed this server's own range")
	}
}

func readClaimRecord(t *testing.T, workDir string) status.MeshClaimsRecord {
	t.Helper()
	b, err := os.ReadFile(status.MeshClaimsPath(workDir))
	if err != nil {
		t.Fatalf("read the record: %v", err)
	}
	var rec status.MeshClaimsRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatalf("parse the record: %v", err)
	}
	return rec
}
