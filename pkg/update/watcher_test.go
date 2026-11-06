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

package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/version"
)

const (
	rollTestNode = "worker"
	rollTestTag  = "v0.2.0"
	rollTestURL  = "https://github.com/k3sm-io/k3sm/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz"
)

var errConnReset = errors.New("read tcp 100.64.1.255:55559->100.64.0.1:6444: read: connection reset by peer")

// rollRig is a worker's Watcher on a fake apiserver that can go away: while
// down, every read and write of the Node fails the way the tracer's did.
type rollRig struct {
	t  *testing.T
	cs *fake.Clientset
	w  *Watcher

	mu sync.Mutex
	// down is the outage. loseAt starts it when a patch writes that phase;
	// applied says that patch reached the store and only its response was lost.
	down    bool
	loseAt  string
	applied bool
	// upAfter ends the outage after that many backoff waits; negative never does.
	upAfter int
	waits   int
	waited  time.Duration
	written []string
	fetches int
	netd    int
	netdErr error
	netdHit chan struct{}
}

func (r *rollRig) Fetch(context.Context, string) (io.ReadCloser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fetches++
	return io.NopCloser(bytes.NewReader([]byte("the archive"))), nil
}

// ApplyUpdate stands in for the root helper: every call would swap the binary.
func (r *rollRig) ApplyUpdate(_ context.Context, _ wire.ApplyUpdateArgs, progress func(wire.UpdatePhase)) (wire.UpdateResult, error) {
	r.mu.Lock()
	r.netd++
	err := r.netdErr
	hit := r.netdHit
	r.mu.Unlock()
	if hit != nil {
		select {
		case hit <- struct{}{}:
		default:
		}
	}
	progress(wire.UpdatePhaseInstalling)
	if err != nil {
		return wire.UpdateResult{Log: "the installer failed"}, err
	}
	return wire.UpdateResult{Phase: wire.UpdatePhaseRestarting}, nil
}

func (r *rollRig) outage(clienttesting.Action) (bool, runtime.Object, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.down {
		return true, nil, errConnReset
	}
	return false, nil, nil
}

func (r *rollRig) onPatch(a clienttesting.Action) (bool, runtime.Object, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.down {
		return true, nil, errConnReset
	}
	raw := patchedPhase(r.t, a.(clienttesting.PatchAction).GetPatch())
	phase, _ := ParsePhase(raw)
	if string(phase) == r.loseAt {
		r.loseAt = ""
		r.down = true
		if !r.applied {
			return true, nil, errConnReset
		}
		r.written = append(r.written, string(phase))
		// The patch lands, then the reset: the store changes under the error.
		r.storePhase(raw)
		return true, nil, errConnReset
	}
	r.written = append(r.written, string(phase))
	return false, nil, nil
}

func patchedPhase(t *testing.T, patch []byte) string {
	t.Helper()
	var p struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(patch, &p); err != nil {
		t.Errorf("decode the patch %s: %v", patch, err)
	}
	return p.Metadata.Annotations[updatesv1alpha1.AnnotationUpdatePhase]
}

// backoff is the Watcher's wait: the clock never runs, and the outage ends
// after upAfter waits.
func (r *rollRig) backoff(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waits++
	r.waited += d
	if r.upAfter >= 0 && r.waits >= r.upAfter {
		r.down = false
	}
	return nil
}

func newRollRig(t *testing.T, running string, sum string) *rollRig {
	t.Helper()
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ca.IssueUpdateSigner()
	if err != nil {
		t.Fatal(err)
	}
	if sum == "" {
		s := sha256.Sum256([]byte("the archive"))
		sum = hex.EncodeToString(s[:])
	}
	raw, err := EncodePayload(Payload{Version: rollTestTag, URL: rollTestURL, SHA256: sum, Signature: updatesv1alpha1.UpdateSignatureIfSigned})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignPayload(signer, raw)
	if err != nil {
		t.Fatal(err)
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: rollTestNode, Annotations: map[string]string{
		updatesv1alpha1.AnnotationUpdateVersion: rollTestTag,
		AnnotationUpdatePayload:                 string(raw),
		AnnotationUpdatePayloadSig:              sig,
		AnnotationUpdateSigner:                  string(signer.CertPEM),
	}}}
	root := filepath.Join(t.TempDir(), "updates")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	r := &rollRig{t: t, cs: fake.NewClientset(node)}
	r.cs.PrependReactor("get", "nodes", r.outage)
	r.cs.PrependReactor("patch", "nodes", r.onPatch)
	w, err := New(Config{
		Node:      rollTestNode,
		Client:    r.cs,
		Running:   version.Info{Version: running, KubeVersion: "v1.37.1"},
		Root:      root,
		Fetcher:   r,
		Netd:      r,
		ClusterCA: CAPool(ca.CertPEM),
		Log:       slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.wait = r.backoff
	r.w = w
	return r
}

// storedNode reads the Node from the store, past any outage.
func (r *rollRig) storedNode() *corev1.Node {
	r.t.Helper()
	obj, err := r.cs.Tracker().Get(corev1.SchemeGroupVersion.WithResource("nodes"), "", rollTestNode)
	if err != nil {
		r.t.Fatalf("read the Node: %v", err)
	}
	return obj.(*corev1.Node)
}

// storePhase writes the phase annotation straight to the store.
func (r *rollRig) storePhase(raw string) {
	r.t.Helper()
	n := r.storedNode()
	n.Annotations[updatesv1alpha1.AnnotationUpdatePhase] = raw
	if err := r.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), n, ""); err != nil {
		r.t.Fatalf("store the phase: %v", err)
	}
}

func (r *rollRig) phaseOnNode() string {
	r.t.Helper()
	p, _ := ParsePhase(r.storedNode().Annotations[updatesv1alpha1.AnnotationUpdatePhase])
	return string(p)
}

// TestRollSurvivesAStatusWriteLostToAServerRestart is the tracer's stall: the
// server restarts as a worker writes a phase, the write fails with a connection
// reset, and the worker must carry the roll on when the server is back, without
// fetching or swapping anything twice.
func TestRollSurvivesAStatusWriteLostToAServerRestart(t *testing.T) {
	t.Parallel()
	mid := []string{"Downloading", "Verifying", "Installing", "Restarting"}
	for _, tc := range []struct {
		name    string
		lose    string
		applied bool
		// written is every phase a patch of the watcher's carried to the store.
		written []string
	}{
		{name: "Downloading is lost", lose: "Downloading", written: mid},
		{name: "Verifying is lost", lose: "Verifying", written: mid},
		{name: "Installing is lost", lose: "Installing", written: mid},
		{name: "Restarting is lost", lose: "Restarting", written: mid},
		{name: "Verifying landed and only its response is lost", lose: "Verifying", applied: true, written: mid},
		{name: "Installing landed and only its response is lost", lose: "Installing", applied: true, written: mid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRollRig(t, "v0.1.0", "")
			r.loseAt, r.applied, r.upAfter = tc.lose, tc.applied, 3
			if err := r.w.Sync(context.Background()); err != nil {
				t.Fatalf("Sync = %v, want the roll carried on", err)
			}
			if got := r.phaseOnNode(); got != "Restarting" {
				t.Fatalf("the phase on the Node = %q, want Restarting", got)
			}
			if r.fetches != 1 || r.netd != 1 {
				t.Fatalf("fetched %d times and ran the installer %d times, want once each", r.fetches, r.netd)
			}
			if r.waits == 0 {
				t.Fatal("the write landed without a backoff; the outage never bit")
			}
			if !slices.Equal(r.written, tc.written) {
				t.Fatalf("phases written %v, want %v", r.written, tc.written)
			}
		})
	}

	t.Run("Done is lost by the restarted daemon", func(t *testing.T) {
		t.Parallel()
		r := newRollRig(t, rollTestTag, "")
		r.loseAt, r.upAfter = "Done", 2
		if err := r.w.Sync(context.Background()); err != nil {
			t.Fatalf("Sync = %v", err)
		}
		if got := r.phaseOnNode(); got != "Done" {
			t.Fatalf("the phase on the Node = %q, want Done", got)
		}
		if r.fetches != 0 || r.netd != 0 {
			t.Fatalf("fetched %d times and ran the installer %d times, want neither", r.fetches, r.netd)
		}
	})

	t.Run("Failed is lost after a bad digest", func(t *testing.T) {
		t.Parallel()
		r := newRollRig(t, "v0.1.0", "0000000000000000000000000000000000000000000000000000000000000000")
		r.loseAt, r.upAfter = "Failed", 2
		if err := r.w.Sync(context.Background()); err != nil {
			t.Fatalf("Sync = %v", err)
		}
		if got := r.phaseOnNode(); got != "Failed" {
			t.Fatalf("the phase on the Node = %q, want Failed", got)
		}
		if r.netd != 0 {
			t.Fatalf("ran the installer %d times on a bad digest", r.netd)
		}
	})
}

// TestPhaseWriteThatNeverLands is the outage that outlasts the budget. The
// write gives up on its bound and the node stays out of the root helper; when
// the apiserver is back the attempt starts over, because nothing else would.
func TestPhaseWriteThatNeverLands(t *testing.T) {
	t.Parallel()
	r := newRollRig(t, "v0.1.0", "")
	r.loseAt, r.upAfter = "Verifying", -1
	err := r.w.Sync(context.Background())
	if !errors.Is(err, errPhaseWriteLost) {
		t.Fatalf("Sync = %v, want errPhaseWriteLost", err)
	}
	if r.waits != 23 || r.waited != phaseWriteBudget {
		t.Fatalf("%d waits adding up to %s, want 23 adding up to %s", r.waits, r.waited, phaseWriteBudget)
	}
	if r.netd != 0 {
		t.Fatalf("ran the installer %d times with no Installing on the Node", r.netd)
	}
	if got := r.phaseOnNode(); got != "Downloading" {
		t.Fatalf("the phase on the Node = %q, want the last one that landed", got)
	}

	// Still down: a look at the Node fails and starts nothing.
	if err := r.w.Sync(context.Background()); err == nil {
		t.Fatal("Sync during the outage = nil, want the read's error")
	}
	if r.fetches != 1 {
		t.Fatalf("fetched %d times during the outage, want 1", r.fetches)
	}

	r.down = false
	if err := r.w.Sync(context.Background()); err != nil {
		t.Fatalf("Sync after the outage = %v", err)
	}
	if got := r.phaseOnNode(); got != "Restarting" {
		t.Fatalf("the phase on the Node = %q, want Restarting", got)
	}
	if r.fetches != 2 || r.netd != 1 {
		t.Fatalf("fetched %d times and ran the installer %d times, want 2 and 1", r.fetches, r.netd)
	}
}

// TestInstallerRunsOnceWhenLaterWritesNeverLand covers the writes after the
// handover to the root helper: however they end, no later Sync swaps again.
func TestInstallerRunsOnceWhenLaterWritesNeverLand(t *testing.T) {
	t.Parallel()
	r := newRollRig(t, "v0.1.0", "")
	r.loseAt, r.upAfter = "Restarting", -1
	if err := r.w.Sync(context.Background()); err != nil {
		t.Fatalf("Sync = %v: the mirrored write is only logged", err)
	}
	r.down = false
	for range 3 {
		if err := r.w.Sync(context.Background()); err != nil {
			t.Fatalf("a later Sync = %v", err)
		}
	}
	if r.netd != 1 || r.fetches != 1 {
		t.Fatalf("fetched %d times and ran the installer %d times, want once each", r.fetches, r.netd)
	}
}

// TestFailedVerdictIsDeliveredWithoutARepeat has the installer fail and the
// Failed write use its budget. The next Sync delivers the verdict, and the
// install is not run again to reach it.
func TestFailedVerdictIsDeliveredWithoutARepeat(t *testing.T) {
	t.Parallel()
	r := newRollRig(t, "v0.1.0", "")
	r.netdErr = errors.New("the installer exited 1")
	r.loseAt, r.upAfter = "Failed", -1
	if err := r.w.Sync(context.Background()); !errors.Is(err, errPhaseWriteLost) {
		t.Fatalf("Sync = %v, want errPhaseWriteLost", err)
	}
	r.down = false
	for range 2 {
		if err := r.w.Sync(context.Background()); err != nil {
			t.Fatalf("a later Sync = %v", err)
		}
	}
	if got := r.phaseOnNode(); got != "Failed" {
		t.Fatalf("the phase on the Node = %q, want Failed", got)
	}
	raw := r.storedNode().Annotations[updatesv1alpha1.AnnotationUpdatePhase]
	if _, msg := ParsePhase(raw); !strings.Contains(msg, "the installer exited 1") || !strings.HasSuffix(msg, failRecovery) {
		t.Fatalf("the Failed message = %q", msg)
	}
	if r.netd != 1 || r.fetches != 1 {
		t.Fatalf("fetched %d times and ran the installer %d times, want once each", r.fetches, r.netd)
	}
}

// TestRequestMovedDuringTheOutageDropsTheAttempt is an abort that lands while
// this node cannot write: the retry finds the request gone, writes nothing back
// and never reaches the root helper.
func TestRequestMovedDuringTheOutageDropsTheAttempt(t *testing.T) {
	t.Parallel()
	r := newRollRig(t, "v0.1.0", "")
	r.loseAt, r.upAfter = "Verifying", 2
	r.cs.PrependReactor("get", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
		// The outage has ended by this read: abort has cleared the request.
		if n := r.storedNode(); n.Annotations[updatesv1alpha1.AnnotationUpdateVersion] != "" {
			r.mu.Lock()
			down := r.down
			r.mu.Unlock()
			if !down && r.fetchCount() > 0 {
				n.Annotations = map[string]string{}
				if err := r.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), n, ""); err != nil {
					t.Errorf("clear the request: %v", err)
				}
			}
		}
		return false, nil, nil
	})
	if err := r.w.Sync(context.Background()); err != nil {
		t.Fatalf("Sync = %v", err)
	}
	if r.netd != 0 {
		t.Fatalf("ran the installer %d times after the abort", r.netd)
	}
	if got := r.storedNode().Annotations[updatesv1alpha1.AnnotationUpdatePhase]; got != "" {
		t.Fatalf("the phase %q was written back over the abort", got)
	}
}

func (r *rollRig) fetchCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fetches
}

// TestStopDuringBackoffWritesNothing has this daemon stop while a write waits:
// the wait ends at once and the restarted daemon judges the outcome.
func TestStopDuringBackoffWritesNothing(t *testing.T) {
	t.Parallel()
	r := newRollRig(t, "v0.1.0", "")
	r.loseAt, r.upAfter = "Verifying", -1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.w.wait = func(ctx context.Context, d time.Duration) error {
		cancel()
		return waitContext(ctx, d)
	}
	if err := r.w.Sync(ctx); err == nil || errors.Is(err, errPhaseWriteLost) {
		t.Fatalf("Sync = %v, want the write's own error", err)
	}
	if r.netd != 0 {
		t.Fatalf("ran the installer %d times", r.netd)
	}
}

// TestRunLooksAgainAfterABudgetIsUsed drives the loop itself: nothing changes
// on the Node after the lost write, so no informer event comes, and only Run's
// own re-sync finishes the roll.
func TestRunLooksAgainAfterABudgetIsUsed(t *testing.T) {
	t.Parallel()
	r := newRollRig(t, "v0.1.0", "")
	r.loseAt, r.upAfter = "Downloading", -1
	r.netdHit = make(chan struct{}, 1)
	// The apiserver comes back only after the budget is used: the read after
	// the last wait is the write's last try, and the one after that is Run's.
	reads := 0
	r.cs.PrependReactor("get", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.waits == 23 {
			if reads++; reads == 2 {
				r.down = false
			}
		}
		return false, nil, nil
	})
	r.w.syncRetry = time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.w.Run(ctx)
	}()
	select {
	case <-r.netdHit:
	case <-ctx.Done():
		t.Error("the roll never reached the root helper")
	}
	cancel()
	<-done
}
