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

package provider

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
	"k8s.io/utils/clock"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/darwin-net/pkg/tcpseg"
	"k3sm.io/k3sm/pkg/gpucapacity"
	"k3sm.io/k3sm/pkg/provider/podlogs"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
	"k3sm.io/k3sm/pkg/version"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/mount"
	runtimed "k3sm.io/runtimed/pkg/runtime"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
)

// resyncInterval is the period of the GetPodStatus backstop poll that recovers
// any status event the streaming watch dropped (the runtime's broker drops on a
// full subscriber buffer). It bounds staleness independent of the stream.
const resyncInterval = 10 * time.Second

// runtimedRuntime is the Runtime backed by runtimed's in-process node runtime
// (runtimev1.RuntimeServer via runtime.New): OCI pull → clonefile → ad-hoc-sign
// → Seatbelt confine. It translates corev1.Pod ⇄ the runtime PodBox/PodStatus
// contract, deriving the corev1 fields runtimed's lossy renderer omits.
//
// Concurrency: mu guards the per-pod bookkeeping (the stable StartTime and the
// last-seen Pod spec keyed by pod id). The wrapped runtime is itself
// concurrency-safe. The status callback set by Watch runs OUTSIDE mu.
type runtimedRuntime struct {
	rt runtimev1.RuntimeServer
	// nodeSampler reads the host for the stats summary's node row; nil uses
	// defaultHostSampler. Set only before use (tests), never mutated after.
	nodeSampler hostSampler
	nodeName    string
	nodeIP      string
	rootfs      string
	dyldShim    string
	// pathShim is the path-rebase DYLD shim runtimed injects into every pod
	// (RuntimedConfig.PathShim). The provider does not inject it itself — it
	// keeps it only to name the file in each pod's Seatbelt read allow alongside
	// dyldShim (see stampShimReadPaths).
	pathShim string
	// resolverVIP and clusterDomain are the cluster DNS inputs buildBox feeds
	// dns.PodDNSConfig (per-pod namespace) to derive the K3SM_DNS_* env the DYLD
	// getaddrinfo shim reads — so an in-pod unqualified Service lookup expands and
	// resolves against the cluster DNS VIP. They mirror RuntimedConfig.ResolverVIP /
	// .ClusterDomain.
	resolverVIP   string
	clusterDomain string
	// apiServerVIP is the kubernetes Service ClusterIP every container is told
	// about through the kubelet's service environment (apiServerEnv).
	apiServerVIP string
	// podLogsDir is the root of the CRI container-log tree
	// (<dir>/<ns>_<pod>_<uid>/<container>/<n>.log) — the kubelet's --pod-logs-dir,
	// defaulted to /var/log/pods. The provider CREATES the directories, READS the
	// files for `kubectl logs`, ROTATES them and is their only DELETER; runtimed
	// opens the files and writes them and does nothing else with them.
	podLogsDir string
	// containerLogsDir is the flat symlink directory (/var/log/containers) log
	// shippers glob. Empty disables symlink creation and the dangling-symlink
	// sweep, which is what a node running without the installer's tree wants.
	containerLogsDir string
	// logLocks serialises the rotator and the log GC per pod directory (shared
	// with both, which is the point of holding it here).
	logLocks *podlogs.DirLocks
	// logRotator is the container-log rotation manager. Never nil after
	// construction: rotation disabled by a negative max size yields the stub.
	logRotator podlogs.ContainerLogManager
	// logGC removes dead instances, orphaned pod directories and dangling
	// symlinks. nil only in the fake-runtime tests that build no log tree.
	logGC *podlogs.GC
	// podsSynced records that the node has seen the cluster's pod set for this
	// node at least once. It ARMS the log GC's deletions and nothing else: before
	// the first sync an empty track map means "not told yet", not "every pod is
	// gone", and deleting on that reading would wipe the node's logs after every
	// restart. Guarded by mu.
	podsSynced bool
	// deniedSocks are AF_UNIX socket paths every pod's SBPL must deny connect()
	// to — the root k3sm-netd helper socket and the runtimed control socket, so a
	// same-uid (_k3sm) pod cannot drive a privileged daemon. Threaded onto each
	// PodBox's SandboxProfile (apis SandboxProfile.denied_unix_socket_paths).
	//
	// It is the UNION of the non-omittable base set this package derives
	// (baseSocketDenies) and whatever the caller supplied in
	// RuntimedConfig.DeniedUnixSocketPaths — sorted and deduplicated once, at
	// construction, so buildBox stamps a settled value.
	deniedSocks []string
	// deniedLocalPorts are loopback-only TCP ports every pod's SBPL denies
	// connect() to — this node's EFFECTIVE kine (etcd shim) port, which listens
	// in plaintext on 127.0.0.1: pods run as the same _k3sm uid as kine, so a
	// networked pod could otherwise dial the control-plane datastore directly.
	// Threaded as data, exactly like deniedSocks: the SBPL generator does not
	// know what listens on a given port, it only denies (apis
	// SandboxProfile.denied_local_ports, field 7).
	//
	// It is the sorted, deduplicated normalization of
	// RuntimedConfig.DeniedLocalPorts (normalizeLocalPortDenies) — computed once
	// at construction, so buildBox stamps a settled value. An out-of-range entry
	// fails NewRuntimed closed rather than reaching a pod's rendered profile.
	//
	// PORT-ONLY CEILING: this denies the port, not the service — a Service that
	// happens to be published on the same port is also unreachable from a
	// confined pod (see the proto field's own doc comment).
	deniedLocalPorts []uint32
	// history is the node's persisted eviction, OOM and restart history
	// (budgethistory.go), opened from RuntimedConfig.BudgetDir. nil records
	// nothing. Set at construction, never replaced.
	history *BudgetHistory
	log     *slog.Logger

	// developerDir is this node's active developer directory (`xcode-select -p`),
	// resolved ONCE at construction and stamped onto the SandboxProfile of every
	// pod that carries runtimev1.AnnotationXcodeToolchain. Empty means the node has
	// no toolchain — the annotation then grants nothing, which the constructor
	// logged when it looked.
	developerDir string

	// resolver supplies ConfigMap/Secret data for the env resolution the
	// provider performs before sending the box to runtimed (runtimed reads only
	// literal env). It is the SAME resolver wired into runtimed's Deps for volume
	// materialization. nil ⇒ data-backed env/volumes fail closed.
	resolver mount.Resolver

	// refs is the pod-reference registry the resolver reads through, when the
	// resolver is a kubeResolver over one (newRuntimedWith derives it). Every
	// pod is registered before its first read and unregistered once torn down.
	// nil ⇒ no registry; registration is then a no-op.
	refs *podRefManager

	// network is the per-node pod-IP seam (the podnet adapter) — the SAME
	// instance wired into runtimed's Deps.Network, so the provider's
	// allocate-before-translate Setup and the runtimed-side seam Setup are one
	// idempotent authority. nil ⇒ podIP ≈ nodeIP (the --network none / no-datapath
	// posture; runtimed then keeps its single-node NodeNetwork).
	network PodNetwork

	// transport is the vm-pod transport-override feed (the consumer half):
	// it publishes the published-/32 -> live-lease map into the Service proxy's
	// routing table as each vm pod's guest reports its DHCP lease. nil is the
	// inert feed (no sink configured — the --network none / no-datapath posture),
	// and every method tolerates a nil receiver.
	transport *transportFeed

	// interconnect owns the pod interconnect opt-in (interconnect.go): the
	// node's pod slots, each attached pod's alias, env and condition. Never nil
	// after construction; with no root helper or desired annotation wired every
	// attach is refused under the pod's fallback.
	interconnect *interconnectAttacher

	// guestArtifacts records whether this node's pinned guest boot artifacts were
	// ensured and verified at construction — the VMArtifactsAvailable
	// capability Capabilities reports and cmd/k3sm turns into the
	// k3sm.io/vm-artifacts node label.
	//
	// It is a k3sm-side fact, not a runtimed RuntimeCondition, because ENSURE runS
	// here: runtimed owns the mechanism (guestartifacts.EnsureGuestArtifacts) but
	// the daemon that calls it is this one, and a node may not advertise a
	// capability whose outcome the advertiser did not observe. It mirrors exactly
	// what was wired into the vm backend — true iff a locator was installed — so
	// the label can never claim more than CreateVM can deliver.
	guestArtifacts bool

	// clk, dial, and probeTransport are the provider-served probe seams:
	// the clock that schedules probe loops and the http/tcp I/O the checks use.
	// Production defaults are wired in newRuntimedWith; tests inject fakes.
	// EVERY probe dial converges on dial: a prober's http transport is built per
	// pod over it (probeSeamsFor), so probeTransport itself now serves only the
	// httpGet lifecycle hooks.
	clk            clock.Clock
	dial           dialFunc
	probeTransport http.RoundTripper

	// client force-deletes a pod from the apiserver the instant its containers are
	// torn down. Virtual Kubelet's PodController (v1.14.0) otherwise delays the
	// API-side delete of a running-then-deleted pod by the FULL
	// deletionGracePeriodSeconds: its prompt path (syncPodInProvider force-deleting
	// on !running) is reachable only via the informer, whose podShouldEnqueue →
	// podsEqual ignores .status, so a terminal NotifyPods report can't trigger it.
	// runtimed already stopped the pod synchronously in DeletePod, so a grace-0
	// delete here is correct and safe (VK's later delayed delete no-ops on NotFound).
	// nil in unit tests that don't exercise the API removal.
	client kubernetes.Interface

	// podSource is the LIVE apiserver read the orphan reaper (orphanreap.go)
	// decides from: one node-scoped List per tick, then a direct Get per
	// candidate. It is never an informer cache. Derived from client at
	// construction; nil (no client) disables the reaper.
	podSource apiPodSource
	// orphanMu guards orphanGauges, the reaper's per-pod-id consecutive
	// not-found counters. Held only around a gauge read-modify-write, never
	// together with mu.
	orphanMu     sync.Mutex
	orphanGauges map[string]*probeGauge

	// recorder emits the pod lifecycle Events the runtimed path owns.
	recorder record.EventRecorder

	// refresher re-renders a running pod's projected volumes
	// (projectedrefresh.go). It is the in-process runtime behind rt, reached
	// through a consumer-side capability rather than the runtime/v1 contract;
	// nil (a test double) disables the refresh loop.
	refresher projectedRefresher

	mu    sync.Mutex
	track map[string]*podTrack // pod id -> bookkeeping
	// retained holds the TERMINATED pods of this node a restarted daemon found
	// in the apiserver and does not track, keyed by pod UID: their log trees are
	// still owed to `kubectl logs` (runtimed_retained.go). Guarded by mu.
	retained map[string]*corev1.Pod
	probers  map[string]*podProber // pod id -> provider-served probe runner
	notify   func(*corev1.Pod)
	// admission is the pressure source CreatePod admits a new pod against
	// (admission.go); nil admits every pod. Guarded by mu.
	admission admissionPressure
	// admitting counts, per pod id, the creates admission let through that have
	// not yet returned (admission.go, admitOnCreate). A refusal for a pod with an
	// admitted create in flight yields to it, so the decision and its result are
	// published together. Guarded by mu; created on first use.
	admitting map[string]int
	// admitSettled holds, per pod id, a channel closed when the pod's last
	// admitted create returns, for an UpdatePod waiting for the verdict
	// (admission.go, awaitUpdateVerdictLocked). Guarded by mu; created on first use.
	admitSettled map[string]chan struct{}
	// updating counts, per pod id, the UpdatePods that have not returned, from
	// before they wait for a verdict, and the parked-create retries that have not
	// returned (retryParkedCreate). Each may still acquire the pod's /32, or build a
	// guest on it, so a release cannot start while it is non-zero (admission.go,
	// claimFenceReleaseLocked). Guarded by mu; created on first use.
	updating map[string]int
	// held is the set of pods a create or update has begun acquiring for with no
	// release since, by UID: what a refusal has to free, because a refused pod's
	// delete frees nothing, and what the orphan reaper frees for a pod with no track.
	// An address reserved by a startup re-attachment is not in it (attachPod). Set
	// before the acquiring, cleared by releasePodNetwork. Guarded by mu; created on
	// first use.
	held map[string]*corev1.Pod
	// deleteOwed holds, per pod id, a delete that landed behind a create or an
	// UpdatePod in flight, or a create's refusal beside an UpdatePod in flight. The
	// release and the track delete are the last call out's
	// (claimFenceReleaseLocked), since until then either can still acquire by the
	// pod's UID. Guarded by mu; created on first use.
	deleteOwed map[string]*owedDelete
	// tombstones remembers the UIDs of recent deletes, for an update that finds no
	// track and carries no deletion stamp (admission.go, uidTombstones). Guarded by
	// mu; usable at its zero value.
	tombstones uidTombstones
	// deleteInRPC counts, per pod id, the teardowns inside the runtime's DeletePod and
	// not yet remembered in tornDown (createBehindDelete). Guarded by mu; created on
	// first use.
	deleteInRPC map[string]int
	// tornDown remembers the UIDs of recent teardowns, for a create that arrives behind
	// one (createIsStale). Unlike tombstones it leaves out a refused pod's delete, which
	// tore nothing down. Guarded by mu; usable at its zero value.
	tornDown uidTombstones
	// admittedHook, when set, runs in CreatePod right after admission let the
	// create through, before anything is registered: the seam a test uses to hold
	// one create inside the admission window. Nil in production; set before any
	// create and never changed, so it is read without mu.
	admittedHook func(podID string)
	// fenceReleasing holds, per pod id, a channel closed when a claimed release is
	// over (admission.go, claimFenceReleaseLocked; runtimed.go, fenceRelease).
	// admitOnCreate and UpdatePod wait on it, so no create or update of the pod
	// acquires during the release. Guarded by mu; created on first use.
	fenceReleasing map[string]chan struct{}
	// fenceReleaseHook and fenceWaitHook, when set, run after a release is claimed
	// and before it frees anything, and in admitOnCreate before it waits on a
	// release: the seams a test uses to admit a create inside that window. Nil
	// in production; set before any create and never changed, read without mu.
	fenceReleaseHook func(podID string)
	fenceWaitHook    func(podID string)
	// updateWaitHook and updateCheckedHook, when set, run in UpdatePod before it
	// waits for an admission verdict and right after it passed its terminal
	// check: the seams a test uses to choose how an update overlaps a create. Nil
	// in production; set before any call and never changed, read without mu.
	updateWaitHook    func(podID string)
	updateCheckedHook func(podID string)
	// compensating is the set of pod ids with a compensating delete owed and in
	// flight — a guest a parked pod's retry built after the pod was deleted, which
	// nothing but this provider knows about (runtimed_pull.go). It is
	// PROVIDER-level rather than per-track for the only reason that matters: the
	// track is gone by then, so there is nowhere else to hold it, and the pod id
	// is what the delete is keyed on anyway. It is also the dedupe: one loop per
	// pod id, however many late creates land for it.
	compensating map[string]bool // pod id -> the delete is outstanding (true), or landed with its release running (false)
	// compensateAgain marks a pod id whose running compensating delete owes one more
	// attempt, for a late create that joined it. Guarded by mu; created on first use.
	compensateAgain map[string]bool

	// lifetime is closed when the provider shuts down — the Watch context, which
	// bounds every other provider-owned goroutine, ending. It bounds the ONE
	// worker that outlives the call that started it and has no pod to be
	// cancelled with: the compensating-delete retry loop, whose track is gone by
	// construction (runtimed_pull.go). It is a channel rather than a stored
	// Context because a Context in a struct is exactly what the standards forbid,
	// and closure is all a select needs.
	//
	// It is created at construction, not at Watch: a compensating delete can be
	// owed by a provider nobody ever called Watch on (every unit test, and the
	// window before the node's watch starts).
	lifetime     chan struct{}
	lifetimeOnce sync.Once

	// stopVerbMissingOnce limits the "upgrade runtimed" line to one per
	// process: a runtimed that answers StopContainer with a transport
	// Unimplemented predates the verb, and that is a node fact, not a per-pod
	// one (killAfterPostStart, poststart.go).
	stopVerbMissingOnce sync.Once
}

// shutdown closes the provider's lifetime channel, ending every worker bounded
// by it. Idempotent, and safe to call from any goroutine.
func (r *runtimedRuntime) shutdown() {
	r.lifetimeOnce.Do(func() { close(r.lifetime) })
}

// Close releases the embedded runtime: it ends the provider's lifetime workers,
// stops the runtime's pod supervision (every pod process keeps running) and
// lets go of the runtime root's lock, so a later runtime on the same root can
// start, as a restarted daemon does. Idempotent.
//
// The node does not call this: its exit path closes the same runtime through
// ServableRuntime (cmd/k3sm), after it has stopped the eviction loop and
// flushed the budget history, because both act through the runtime. Close is
// for an owner that holds only the provider.
func (r *runtimedRuntime) Close() error {
	r.shutdown()
	if c, ok := r.rt.(interface{ Close() error }); ok {
		if err := c.Close(); err != nil {
			return fmt.Errorf("close embedded runtime: %w", err)
		}
	}
	return nil
}

// podTrack is the provider-side bookkeeping the runtime does not retain: a stable
// StartTime (set once at CreatePod, never regenerated) and the last Pod object
// (for namespace/name lookup and status reconstruction by pod id).
type podTrack struct {
	pod       *corev1.Pod
	startTime metav1.Time

	// readyMu guards lastReady, the last PodReady condition buildStatus computed for
	// this pod. It is a STABLE prior for readyTransitionTime so PodReady's
	// LastTransitionTime flips only on a real status change — pod (the desired-spec
	// object) never carries the computed PodReady, so without this the LTT would reset
	// to Now() every resync tick (see buildStatus). readyMu is separate from r.mu
	// because GetPods reconstructs status OUTSIDE r.mu.
	//
	// readyMu also guards lastReadyToStart, the same prior for the
	// PodReadyToStartContainers condition (computeReadyToStartContainers).
	readyMu          sync.Mutex
	lastReady        corev1.PodCondition
	lastReadyToStart corev1.PodCondition

	// restartMu guards restarts — the per-container exit-driven restart
	// bookkeeping (runtimed_restart.go): the termination
	// idempotency latch, the CrashLoopBackOff schedule, and the pending-re-exec
	// state the status overlay renders. Separate from r.mu for the same reason
	// as readyMu (buildStatus runs outside r.mu); lock order is r.mu →
	// restartMu, never the reverse.
	restartMu sync.Mutex
	restarts  map[string]*containerRestart // container name -> restart bookkeeping
	// diedWhileDown names the containers of a re-attached pod (runtimed_attach.go)
	// that the attach reported Terminated: they died while the node daemon was
	// down, so no process of theirs exists under this daemon and runtimed refuses
	// RestartContainer on them. Their next restart is StartContainer, the
	// runtime's recovery for such an entry; a successful start removes the name.
	// Set once at attach, before the track is published; guarded by restartMu.
	diedWhileDown map[string]bool
	// pulls is the per-image retry bookkeeping of the image pull-failure path
	// (runtimed_pull.go): the schedule that paces StartContainer re-attempts for
	// a container that never started, keyed by image reference (the track is
	// already per pod UID, so the key is the kubelet's pod UID × image).
	//
	// It is guarded by restartMu ABOVE, deliberately and not by a mutex of its
	// own: both maps are read by the same buildStatus overlay chain, so one lock
	// is the honest shape and a second would only add a lock-order rule.
	pulls map[string]*imagePullRetry // image reference -> pull retry schedule
	// pulling is the per-container Pulling→Pulled attempt window
	// (runtimed_pull.go): a container the provider has announced a start attempt
	// for, owed the kubelet's Pulled event until a status carries that attempt's
	// image_pull outcome. Guarded by restartMu with the rest of the pull surface.
	pulling map[string]*pullAttempt // container name -> open attempt window
	// parked, when non-nil, records a CreatePod runtimed refused for a
	// CONTAINER-class image failure — the vm shape, where the whole guest was
	// never built. The pod stays tracked and reports the kubelet's waiting
	// surface from this record while the create is retried; see createFailure
	// for why the refusal is not returned to virtual-kubelet.
	parked *createFailure
	// claims, when non-nil, marks a pod held because a PersistentVolumeClaim it
	// mounts does not resolve to a bound volume (claimwait.go). The runtime
	// holds nothing for it; its re-check worker runs the create once the claims
	// resolve. Guarded by restartMu.
	claims *claimWait
	// deleting is set the instant DeletePod begins, BEFORE it cancels a single
	// worker, and is never cleared (the track is discarded moments later, and an
	// idempotent CreatePod installs a fresh one). It is the fence a late create
	// checks: cancelling a worker's context does not un-build what the runtime
	// has already built, so a parked pod's CreatePod can still return SUCCESS
	// after the pod is gone. Guarded by restartMu with the rest of the pull
	// surface, so the check and the unpark are one critical section
	// (commitParkedCreate).
	deleting bool
	// stop is the state of the runtime DeletePod calls made for this track, which
	// a log follower reads to tell a pod still stopping from one that is gone
	// (followRunning). Guarded by restartMu with deleting.
	stop runtimeStop
	// evicted, when non-nil, is the terminal status of a pod the node-pressure
	// eviction manager evicted (evictPod). It is set BEFORE the runtime teardown
	// starts and never cleared; every status path returns it first, so nothing the
	// runtime reports during or after the teardown can turn an evicted pod back
	// into a running or restarting one. Guarded by restartMu with deleting.
	evicted *corev1.PodStatus
	// rejected marks a track whose pod was refused at admission (admission.go):
	// evicted holds its rejected status, and the runtime never heard of it, so
	// DeletePod forgets it without a runtime teardown. Set before the track is
	// published and never changed.
	rejected bool

	// hookMu guards postStart — the per-container postStart hook bookkeeping of
	// the postStart fidelity path (poststart.go): the pending/failed readiness gate the
	// status overlay reads, and the pod-scoped cancel of each in-flight hook.
	// Separate from r.mu for the same reason as readyMu (buildStatus runs outside
	// r.mu); it is never held together with r.mu or restartMu.
	hookMu    sync.Mutex
	postStart map[string]*postStartHook // container name -> postStart bookkeeping

	// shimMu guards shimWarned, the set of k3sm.io/shim-inactive reasons already
	// recorded as a ShimInactive Event for this pod (observeShimInactive), so a
	// condition present on every status build fires its Event once. Separate
	// from r.mu for the same reason as readyMu (buildStatus runs outside r.mu);
	// it is never held together with another lock, and the Event is recorded
	// after it is released.
	shimMu     sync.Mutex
	shimWarned map[string]bool

	// refreshWarnMu guards refreshWarned, the set of volume × failure-class
	// pairs already recorded as a ProjectedVolumeRefreshFailed Event for this
	// pod (projectedrefresh.go), bounded by maxRefreshWarnings. A volume's
	// entries clear when it refreshes again. Never held with another lock.
	refreshWarnMu sync.Mutex
	refreshWarned map[string]bool

	// lifecycleMu guards instances, the per-container instance latch of the
	// container lifecycle Events (runtimed_lifecycle.go): the last instance whose
	// Created and Started were recorded, its last observed running state, and
	// whether a Killing was recorded for it. Never held with another lock; the
	// Events are recorded after it is released. An idempotent CreatePod copies
	// it onto the replacing track (inheritLifecycle).
	lifecycleMu sync.Mutex
	instances   map[string]*containerInstance
}

// RuntimedConfig configures a runtimedRuntime.
type RuntimedConfig struct {
	// NodeName is the registering node's name.
	NodeName string
	// Recorder receives the pod lifecycle Events the provider emits.
	Recorder record.EventRecorder
	// NodeIP is the node InternalIP stamped as HostIP on every pod status.
	NodeIP string
	// Root is runtimed's on-disk root (image cache + pod dirs); empty uses the
	// runtimed default (/var/lib/k3sm).
	Root string
	// StatusRecordDir is the data root's status directory, where this node
	// publishes the records `k3sm status` reads. The records are owned by the uid
	// pods run as, so the Seatbelt deny runtimed renders from this value is their
	// only write barrier, and the data root is Root only when the pod root is left
	// at its default. Empty (the standalone `k3sm node`, which publishes nothing)
	// renders no extra deny. NewRuntimed refuses a value the deny would not match
	// (ErrStatusRecordDirNotCanonical).
	StatusRecordDir string
	// DataRoot is the data root, whose server and agent directories hold the CA
	// keys, the kine database and the node password. It is Root only when the pod
	// root is left at its default, and the Seatbelt denies runtimed renders from
	// this value name those directories wherever Root is. Empty (the standalone
	// `k3sm node`, which keeps no such state) renders no extra deny, and so does the
	// runtime's own root. Otherwise NewRuntimed refuses a value the denies would not
	// match (ErrDataRootNotCanonical).
	DataRoot string
	// DyldShim, when set, is the getaddrinfo DNS shim dylib injected into each
	// pod via the PodBox annotation runtimed maps to DYLD_INSERT_LIBRARIES. The
	// file is also added to every pod's Seatbelt read allow (stampShimReadPaths).
	DyldShim string
	// ShadowBinDir, when set, is the node's directory of ad-hoc re-signed host
	// binary copies (pkg/shadow, made by `sudo k3sm install`): the shells, tar
	// and the common coreutils of runtimed's shadowset list. runtimed execs a
	// copy in place of the host binary so dyld keeps the pod shims loaded
	// (runtime.Config.ShadowBinDir). Empty keeps the host binaries.
	ShadowBinDir string
	// PathShim, when set, is the path-rebase DYLD shim dylib runtimed injects into a
	// mounting container so an absolute volume mount resolves under the pod data
	// volume (no chroot). Empty leaves a pod's absolute mount path reaching the host.
	// Like DyldShim, the file joins every pod's Seatbelt read allow.
	PathShim string
	// ResolverVIP is the cluster DNS Service VIP (10.43.0.10) the per-pod Seatbelt
	// egress allow-list is scoped to (threaded into runtimed's sandbox.Posture), so
	// a confined pod's DNS reaches the node-local resolver. Empty leaves runtimed's
	// built-in default (sandbox.DefaultResolverVIP), which is NOT the k3sm VIP — the
	// commands always set it from the cluster DNS VIP.
	ResolverVIP string
	// ClusterDomain is the cluster DNS suffix (e.g. "cluster.local") buildBox feeds
	// dns.PodDNSConfig to build the in-pod shim search list. It MUST match the served
	// zone the per-node resolver answers for (the same --cluster-domain the
	// resolver is started with): a mismatch makes every unqualified Service lookup
	// NXDOMAIN. Empty defaults to dns.DefaultClusterDomain ("cluster.local",
	// darwin-net) inside PodDNSConfig.
	ClusterDomain string
	// APIServerVIP is the in-cluster Kubernetes API Service VIP (the kubernetes
	// ClusterIP, 10.43.0.1) the per-pod Seatbelt egress is ADDITIONALLY scoped to,
	// so a confined pod's in-cluster client-go (in-pod kubectl) can reach the API
	// VIP. Empty emits no API-server egress rule.
	APIServerVIP string
	// DeniedUnixSocketPaths are ADDITIONAL AF_UNIX socket paths every pod's SBPL
	// denies connect() to (the root k3sm-netd helper socket): pods run as the same
	// _k3sm uid as the legitimate helper client, so the socket must be denied at the
	// sandbox so a pod cannot drive the privileged daemon. Threaded as data because
	// runtimed cannot import darwin-net.
	//
	// It EXTENDS, and can never replace or shrink, the base deny-set the provider
	// derives for itself (baseSocketDenies) — an empty value still yields a
	// profile that denies the runtimed control socket.
	DeniedUnixSocketPaths []string
	// DeniedLocalPorts are loopback-only TCP ports every pod's SBPL denies
	// connect() to — notably this node's EFFECTIVE kine (etcd shim) port,
	// 127.0.0.1:<KinePort>: pods run as the same _k3sm uid as kine, so without
	// this a networked native pod could dial the control-plane datastore
	// directly. The SBPL generator does not know what listens on a given port,
	// it only denies, so the caller (cmd/k3sm) supplies the node's resolved
	// port here. Threaded as data for the same reason as
	// DeniedUnixSocketPaths: runtimed cannot import the distribution.
	//
	// Every value MUST be a valid TCP port (1-65535); NewRuntimed rejects an
	// out-of-range value and fails construction closed rather than silently
	// stamping pods with a garbage deny. An empty list denies nothing.
	//
	// PORT-ONLY CEILING: the generator can only deny the port, not the
	// service — a Service published on the same port is equally unreachable
	// from a confined pod.
	DeniedLocalPorts []int
	// Network is the pod-IP seam (the podnet adapter over darwin-net's IPAM,
	// shared verbatim with the embedded runtimed daemon (Deps.Network) so
	// there is exactly ONE allocator: the provider's CreatePod resolves the pod's
	// /32 through it BEFORE translation (box.PodIp + the downward-API status.podIP
	// env carry it), and runtimed's later seam Setup — idempotent per podID —
	// returns the SAME address. nil keeps runtimed's single-node NodeNetwork
	// (podIP ≈ NodeIP): the explicit --network none / no-datapath posture, never a
	// silent production fallback (the commands fail fast via the runtimed
	// preflight instead).
	Network PodNetwork
	// TransportOverrides is the Service-proxy seam a vm pod's LIVE TRANSPORT
	// address is published through (darwin-net's *proxy.RoutingTable, reached via
	// the node's netserve Server). The provider is the only component holding both
	// halves of a vm pod's two-address identity — the published /32 its IPAM
	// carved and the DHCP lease the guest reported through runtimed — so it is the
	// only one that can feed the map. nil runs the feed inert: no override is ever
	// installed and every backend is dialed at its published address exactly as a
	// host-process pod's is.
	TransportOverrides TransportOverrideSink
	// Interconnect wires the pod opt-in to an interconnect
	// (k3sm.io/interconnects): the root helper's alias verbs and this node's
	// desired annotation. The zero value refuses every attach.
	Interconnect InterconnectConfig
	// Client is the apiserver client the provider resolves ConfigMap/Secret data,
	// SA tokens (volumes/env), and imagePullSecret credentials with —
	// runtimed never talks to the apiserver. nil disables data-backed
	// volumes/env/credentials (they fail closed / pull anonymously).
	Client kubernetes.Interface
	// ImageMirrors supplies the CLUSTER MIRROR candidates runtimed's puller falls
	// back to when this node's own ingest registry misses a NODE-RELATIVE
	// reference (a `localhost:<port>/…` image the operator pushed on a different
	// Mac). k3sm.io/k3sm/pkg/clustermirror is the shipped implementation; the
	// contract, including why the puller and not the source does the reference
	// rewrite and why no credential crosses the seam, is owned by
	// runtimed/pkg/image's MirrorSource.
	//
	// nil is the SINGLE-NODE posture and the complete, correct behavior there: no
	// candidate is ever produced, so no fallback can run and a pull's own registry
	// error stands as its answer. The provider never blocks on it — the source
	// answers from a cache that may not have synced, and "no candidates yet" is a
	// valid answer at any moment.
	ImageMirrors image.MirrorSource
	// ClusterRegistries names ADDITIONAL registry authorities that spell THIS
	// node's own ingest registry — its per-node Service DNS name and the VIP
	// behind it — which runtimed's puller must classify exactly as it classifies a
	// loopback spelling: plain HTTP on the primary fetch (go-containerregistry
	// infers http only for loopback and RFC 1918, so a Service name would
	// otherwise be dialled as HTTPS against a plain-HTTP listener) and eligible
	// for the peer-mirror fallback. The contract, including why the set carries
	// its own fetcher, is owned by runtimed/pkg/image's WithClusterRegistries.
	//
	// nil is the default and leaves the loopback-only classification byte for
	// byte. runtimed REFUSES a malformed authority at construction rather than
	// silently never matching it, so a bad value here fails the node's bring-up.
	ClusterRegistries []string
	// LocalRegistryHost names THIS NODE's own ingest registry as a reference
	// spells it ("localhost:<port>"). When set, a pull for a reference that names
	// no registry at all resolves against it before normalising to Docker Hub —
	// the local-development loop `k3sm image load` and the ingest registry exist
	// for. The contract, and the bounded cost of the divergence, are owned by
	// runtimed/pkg/image's WithLocalRegistry.
	//
	// It MUST be a loopback spelling or one of ClusterRegistries above; runtimed
	// refuses anything else at construction, which fails the node's bring-up
	// rather than silently treating a third-party registry as this node's own. ""
	// is the default and leaves bare-name resolution stock.
	LocalRegistryHost string
	// FlatRegistry maps the cluster's one registry name to the endpoint this
	// node reaches it at, with the loopback spellings recorded under it. The
	// contract is runtimed/pkg/image's FlatRegistry; the zero value maps nothing,
	// and runtimed refuses an invalid mapping at construction.
	FlatRegistry image.FlatRegistry
	// GuestArtifacts is this node's ENSURED, digest-verified guest boot artifact
	// set — the kernel, the initramfs and the cmdline a vm pod boots from.
	// It is DATA, already materialised by GuestArtifactSource.Ensure before this
	// config is built, never a directory this constructor would fetch into: daemon
	// start is not a place to discover that a hundred megabytes are missing.
	//
	// nil is the FAIL-CLOSED posture and the shipped one on any node whose ensure
	// did not succeed (an unminted pin, no network, a digest mismatch). It leaves
	// the vm backend's artifact locator unset, so CreateVM fails every vm pod with
	// sandbox.ErrGuestArtifactsUnavailable while every native pod is untouched.
	GuestArtifacts *EnsuredGuestArtifacts
	// PodLogsDir is the root of the CRI container-log tree, the kubelet's
	// --pod-logs-dir. Empty defaults to podlogs.DefaultPodLogsDir
	// (/var/log/pods) — the same default and the same layout a kubelet uses, so
	// a k8s operator's habits and every log shipper's glob keep working.
	PodLogsDir string
	// ContainerLogsDir is the flat per-container symlink directory
	// (/var/log/containers). Empty disables the symlinks entirely rather than
	// defaulting, because a node that was not installed has no root-owned tree to
	// write them into and a failed symlink per container start is noise.
	ContainerLogsDir string
	// ContainerLogMaxSize is the resource.Quantity string at which a container
	// log is rotated (kubelet containerLogMaxSize; default "10Mi"). A NEGATIVE
	// value disables rotation, as upstream.
	ContainerLogMaxSize string
	// ContainerLogMaxFiles is the total number of files one container keeps
	// (kubelet containerLogMaxFiles; default 5, must be > 1).
	ContainerLogMaxFiles int
	// ContainerLogMaxWorkers is the rotation worker count (kubelet
	// containerLogMaxWorkers; default 1).
	ContainerLogMaxWorkers int
	// ContainerLogMonitorInterval is how often the rotation scan runs (kubelet
	// containerLogMonitorInterval; default 10s).
	ContainerLogMonitorInterval time.Duration
	// BudgetDir is the node's budget state directory, <workdir>/budget/ under
	// the node's own (server or agent) work dir: protected, mode 0700, outside
	// every tree a pod can open. The persisted eviction, OOM and restart
	// history lives there. Empty keeps no history (a standalone `k3sm node`).
	BudgetDir string
	// Logger is the structured logger; a discard logger is used if nil.
	Logger *slog.Logger

	// rootLockWait is runtimed's Deps.RootLockWait: how long New waits for
	// another runtime to let go of Root. Zero is runtimed's default; it is a
	// test seam, so a test whose runtime was not closed fails at once.
	rootLockWait time.Duration
}

// NewRuntimed builds a runtimedRuntime, constructing the in-process runtime with
// production defaults (real image puller/signer, the exec-shim Seatbelt backend,
// posix_spawn/kqueue supervisor). It returns an error if the runtime cannot be
// constructed (e.g. its cache dir).
//
// ctx bounds the startup re-attachment (adoptNodePods), the one part of
// construction that talks to the apiserver.
func NewRuntimed(ctx context.Context, cfg RuntimedConfig) (*runtimedRuntime, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// Validated FIRST, before any real construction below: an out-of-range
	// denied local port is a config bug, and this node must fail closed rather
	// than build a runtime whose pods carry a silently-wrong (or silently
	// empty) deny stanza for the control-plane datastore port.
	if _, err := normalizeLocalPortDenies(cfg.DeniedLocalPorts); err != nil {
		return nil, fmt.Errorf("init runtimed: %w", err)
	}
	// Also before any real construction, and logged as well as returned: this
	// refusal stops the node, and what it protects fails silently if ignored.
	statusRecordDir, err := statusRecordDirOf(cfg)
	if err != nil {
		log.Error("refusing to start: pods could write the status records", "err", err)
		return nil, fmt.Errorf("init runtimed: %w", err)
	}
	dataRoot, err := dataRootOf(cfg)
	if err != nil {
		log.Error("refusing to start: the sandbox could not deny the control-plane state", "err", err)
		return nil, fmt.Errorf("init runtimed: %w", err)
	}
	// The budget history opens before anything runs, so the first exit the
	// startup attach observes is classified against the persisted intents.
	var history *BudgetHistory
	if cfg.BudgetDir != "" {
		// It never fails the node: an unusable dir or file degrades to an
		// in-memory history with a Warn log.
		history = OpenBudgetHistory(cfg.BudgetDir, budgetFingerprint(binaryIdentity(version.Get())), log)
	}
	// runtimed never talks to the apiserver: the provider (which holds the client)
	// supplies the volume Resolver + imagePullSecret CredentialResolver. nil client
	// ⇒ nil seams ⇒ data-backed volumes fail closed, pulls are anonymous.
	//
	// Both read Secrets and ConfigMaps through one podRefManager: by name, and
	// only for an object a pod on this node references (podrefs.go). The
	// runtime registers its pods with it (newRuntimedWith finds it on the
	// resolver), so the registry and the reads are one instance by
	// construction.
	var resolver mount.Resolver
	var creds runtimed.CredentialResolver
	if cfg.Client != nil {
		refs := newPodRefManager(cfg.Client, clock.RealClock{}, log)
		resolver = newKubeResolver(cfg.Client, refs)
		creds = newKubeCredentials(refs)
	}
	// The pod network runtimed drives: the injected podnet adapter (per-pod /32
	// lo0 aliases + the startup stale-alias reconcile) when configured, else the
	// single-node NodeNetwork pinned to this node's IP (podIP ≈ nodeIP — the
	// documented --network none posture).
	var network supervisor.PodNetwork = supervisor.NodeNetwork{IP: cfg.NodeIP}
	if cfg.Network != nil {
		network = cfg.Network
	}
	// The vm backend is constructed HERE, rather than left to runtimed's own
	// default, ONLY when this node has verified guest artifacts to wire into it:
	// sandbox.WithGuestArtifacts is a construction option, and runtimed's default
	// backend deliberately leaves the locator unset (its feeder — this — is a
	// separate deliverable). Everything else about the backend is runtimed's
	// default reproduced verbatim, so the ONE difference between a node with
	// artifacts and a node without is the locator.
	//
	// The state root is passed through runtimeRoot for a reason worth keeping: an
	// empty Root means "runtimed's default", and a backend built with an empty
	// state root has its vm orphan store DISABLED — a daemon `kill -9`ed while a
	// guest ran would leave a helper no later start could find. Defaulting the
	// root at this call site is what makes the override behaviourally identical to
	// the default it replaces.
	var deps runtimed.Deps
	if cfg.GuestArtifacts != nil {
		deps.VMBackend = sandbox.NewVMBackend(
			sandbox.WithStateRoot(runtimeRoot(cfg.Root)),
			sandbox.WithLogger(log),
			sandbox.WithGuestArtifacts(guestArtifactLocator(*cfg.GuestArtifacts)),
		)
	}
	deps.Resolver = resolver
	deps.RootLockWait = cfg.rootLockWait
	deps.Credentials = creds
	deps.Network = network
	// The cluster-mirror seam. Threaded as DATA, exactly like the resolver and the
	// credential resolver above and for the same reason: runtimed never reads the
	// apiserver, so the component that knows the cluster's peers is the one that
	// must supply them. nil (single node, or a node with no client) leaves
	// runtimed's puller byte-identical to its pre-mirror behavior.
	deps.ImageMirrors = cfg.ImageMirrors
	// The same DATA treatment, and for the same reason: runtimed never reads the
	// apiserver, so the component that published the Service is the one that must
	// name it.
	deps.ClusterRegistries = cfg.ClusterRegistries
	deps.LocalRegistryHost = cfg.LocalRegistryHost
	deps.FlatRegistry = cfg.FlatRegistry
	rt, err := runtimed.New(runtimed.Config{
		Root:           cfg.Root,
		RuntimeVersion: version.Get().Version,
		Logger:         log,
		// Scope each pod's Seatbelt egress to the cluster DNS + API VIPs so a
		// confined pod's DNS and in-pod client-go reach the node-local resolver /
		// API VIP. runtimed threads these into its per-pod sandbox.Posture.
		ResolverVIP:  cfg.ResolverVIP,
		APIServerVIP: cfg.APIServerVIP,
		// The container-log root, threaded so runtimed's Seatbelt profile denies
		// every confined pod read AND write access to the tree its own output is
		// written into. It is REQUIRED by runtimed and deliberately has no default
		// there: a deny rendered for /var/log/pods on a node whose logs actually
		// live under a `k3sm dev` instance directory protects nothing while
		// reading like protection. Resolved here through the same expression the
		// provider's own tree uses, so the denied path and the written path are
		// one value.
		PodLogsDir: podLogsDirOf(cfg),
		// The status records' real location, denied beside <Root>/status. On a
		// default node the two are one path and the profile does not change.
		StatusRecordDir: statusRecordDir,
		// The control-plane state's real location, denied beside <Root>/server
		// and <Root>/agent. On a default node the two are one path and the profile
		// does not change.
		DataRoot:     dataRoot,
		PathShimPath: cfg.PathShim,
		ShadowBinDir: cfg.ShadowBinDir,
	}, deps)
	if err != nil {
		if errors.Is(err, sandbox.ErrInvalidStatusRecordDir) {
			log.Error("refusing to start: pods could write the status records", "err", err)
		}
		if errors.Is(err, sandbox.ErrInvalidDataRoot) {
			log.Error("refusing to start: the sandbox could not deny the control-plane state", "err", err)
		}
		return nil, fmt.Errorf("init runtimed: %w", err)
	}
	r := newRuntimedWith(rt, cfg, resolver, log)
	r.history = history
	// Startup re-attachment, then the startup pod reap — MUST run here,
	// in-process, before any CreatePod can be served. The embedded node drives
	// this Runtime by direct RPC and never runs runtime.Server.Serve, so
	// runtimed's own once-before-serve reap never fires on the shipped path: the
	// reaper existed but was UNREACHABLE here, leaving pod process groups a prior
	// `launchctl kickstart -k` orphaned onto launchd running (holding ports,
	// surviving uninstall). This is the exact sibling of the network startup
	// reconcile, and for the exact same reason — see the comment block at
	// cmd/k3sm/node.go's netAdapter.ReconcileStartup call.
	//
	// adoptNodePods first re-attaches every running pod of this node whose
	// processes survived (runtimed_attach.go), and only then calls
	// ReapOrphanedPods: the reap kills every recorded group no registered pod
	// owns, so an attach after it would find nothing left to attach to. It is
	// sourced HERE, in the constructor, rather than in cmd: a caller cannot omit
	// it or reorder it, no create can precede it (Virtual Kubelet starts on the
	// provider this returns), and the wiring is unit-testable without a live node
	// (cmd is a thin main).
	//
	// DEGRADES, it does not fail closed — the one way it differs from that network
	// sibling, which returns its error and aborts node startup. ReapOrphanedPods
	// always returns nil by contract (an unreadable reap store alerts and skips the
	// reap): a best-effort orphan store is not a scheduling precondition, and
	// propagating its I/O fault would exit main and launchd-crash-loop the node.
	// The returned error is therefore checked-and-logged, never propagated — do NOT
	// "harden" this into a startup failure. A failed attach degrades the same way:
	// the pod is created again.
	r.adoptNodePods(ctx, rt)
	return r, nil
}

// refsOf returns the podRefManager resolver reads Secrets and ConfigMaps
// through, or nil when it has none.
func refsOf(resolver mount.Resolver) *podRefManager {
	if kr, ok := resolver.(*kubeResolver); ok {
		if m, ok := kr.objects.(*podRefManager); ok {
			return m
		}
	}
	return nil
}

// Objects returns this runtime's by-name Secret/ConfigMap reader for the
// node's Virtual Kubelet listers, or nil when it has none.
func (r *runtimedRuntime) Objects() vkadapter.ObjectGetter {
	if r.refs == nil {
		return nil
	}
	return r.refs
}

// newRuntimedWith wraps an existing runtime server (tests inject a fake) with the
// volume/env Resolver. The Summary API (kubectl top) is served off the runtime's
// typed ListPodStats RPC, so no per-pod-metrics capability is captured here.
func newRuntimedWith(rt runtimev1.RuntimeServer, cfg RuntimedConfig, resolver mount.Resolver, log *slog.Logger) *runtimedRuntime {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// Startup visibility for BOTH pod-support shims: an empty dyld_shim (the
	// getaddrinfo shim was not resolved beside the binary) or a wrong resolver_vip
	// silently leaves pods on the system resolver (cluster names NXDOMAIN), and an
	// empty path_shim silently ENOENTs every ABSOLUTE volume-mount path in-pod
	// (runtimed injects no path rebase).
	//
	// Both keys are logged UNCONDITIONALLY, empty value included: path_shim was
	// omitted from this line while its dns sibling was logged, so an absent
	// path-rebase shim — the exact cause of the in-pod ENOENTs — was INVISIBLE in
	// the server log and got mis-diagnosed as another subsystem. An absent shim
	// must read as empty here, never as a missing key.
	var recorder record.EventRecorder = nopRecorder{}
	if cfg.Recorder != nil {
		recorder = newEventSpacer(cfg.Recorder)
	}
	log.Info("runtimed provider configured",
		"dyld_shim", cfg.DyldShim,
		"path_shim", cfg.PathShim,
		"resolver_vip", cfg.ResolverVIP,
		"cluster_domain", cfg.ClusterDomain)
	log.Info("projected-volume refresh configured",
		"enabled", refresherOf(rt) != nil,
		"interval", projectedRefreshInterval)
	podLogsDir := podLogsDirOf(cfg)
	locks := podlogs.NewDirLocks()
	// NewRuntimed already fails construction closed on an out-of-range entry
	// (validated before it ever calls this helper), so the only caller that can
	// reach an error here is a test injecting newRuntimedWith directly with a
	// bad value — treat that the same way an unresolved toolchain dir is
	// treated: log it and carry no denial, rather than panicking a helper with
	// no error return.
	deniedLocalPorts, err := normalizeLocalPortDenies(cfg.DeniedLocalPorts)
	if err != nil {
		log.Error("denied local ports config invalid, denying none", "err", err)
	}
	r := &runtimedRuntime{
		rt:            rt,
		nodeName:      cfg.NodeName,
		nodeIP:        cfg.NodeIP,
		rootfs:        cfg.Root,
		dyldShim:      cfg.DyldShim,
		pathShim:      cfg.PathShim,
		resolverVIP:   cfg.ResolverVIP,
		clusterDomain: cfg.ClusterDomain,
		apiServerVIP:  cfg.APIServerVIP,
		// Derived HERE, in the one constructor production and the fake-injected
		// tests share, so no caller can construct a provider whose pods are missing
		// the base deny-set.
		deniedSocks: unionSocketDenies(baseSocketDenies(cfg.Root), cfg.DeniedUnixSocketPaths),
		// Computed HERE for the same reason: a node fact the pod path must
		// never re-derive per pod.
		deniedLocalPorts: deniedLocalPorts,
		// Resolved HERE, in the one constructor production and the fake-injected
		// tests share, for the same reason as the deny-set above: a node fact the
		// pod path must never re-derive per pod.
		developerDir:   resolveDeveloperDir(log),
		resolver:       resolver,
		refs:           refsOf(resolver),
		network:        cfg.Network,
		transport:      newTransportFeed(cfg.TransportOverrides, log),
		interconnect:   newInterconnectAttacher(cfg.Interconnect, recorder, log),
		guestArtifacts: cfg.GuestArtifacts != nil,
		client:         cfg.Client,
		podSource:      newClientPodSource(cfg.Client),
		orphanGauges:   map[string]*probeGauge{},
		log:            log,
		recorder:       recorder,
		refresher:      refresherOf(rt),
		clk:            clock.RealClock{},
		dial:           (&tcpseg.Dialer{}).DialContext,
		probeTransport: newProbeTransport(),
		track:          map[string]*podTrack{},
		probers:        map[string]*podProber{},
		compensating:   map[string]bool{},
		lifetime:       make(chan struct{}),

		podLogsDir:       podLogsDir,
		containerLogsDir: cfg.ContainerLogsDir,
		logLocks:         locks,
	}
	// The rotator and the GC are built here, in the ONE constructor production and
	// the fake-injected tests share, for the same reason the socket deny-set is:
	// a node whose logs are never rotated fills the system volume, and that must
	// not be reachable by a caller forgetting to wire something.
	//
	// A bad rotation policy DEGRADES rather than failing construction: the flags
	// are validated at parse time in cmd/k3sm (so an operator hears about a typo
	// at startup), and a node that refused to start because it could not rotate
	// logs would be trading a bounded disk problem for a total outage.
	rotator, err := podlogs.NewContainerLogManager(r, rotationMaxSize(cfg), rotationMaxFiles(cfg), cfg.ContainerLogMaxWorkers, cfg.ContainerLogMonitorInterval, locks, log)
	if err != nil {
		log.Error("container log rotation is DISABLED: the rotation policy is invalid", "err", err)
		rotator = podlogs.NewStubContainerLogManager()
	}
	r.logRotator = rotator
	r.logGC = podlogs.NewGC(podLogsDir, cfg.ContainerLogsDir, r, locks, log)
	return r
}

// podLogsDirOf returns the configured container-log root, defaulting to the
// kubelet's own /var/log/pods. It is one function because the value has two
// consumers that must never disagree: the provider's own tree, and the Seatbelt
// deny runtimed renders against it.
func podLogsDirOf(cfg RuntimedConfig) string {
	if cfg.PodLogsDir == "" {
		return podlogs.DefaultPodLogsDir
	}
	return cfg.PodLogsDir
}

// ErrStatusRecordDirNotCanonical reports a status record directory that exists
// under a path other than the one configured, a symlink or a spelling the macOS
// firmlinks do not explain. libsandbox matches resolved paths, so the Seatbelt
// deny written from the configured string would match nothing, and pods could
// forge the records with no error from anything.
var ErrStatusRecordDirNotCanonical = errors.New("status record dir is not its own resolved path")

// statusRecordDirOf returns the status record directory the Seatbelt deny is
// written from, or an error when the deny could not match it. A relative value
// (a relative --work-dir) is made absolute, because that is where the records it
// names are written, and runtime.New refuses a relative one.
//
// A status directory that is the runtime's own <root>/status returns in the
// runtime's spelling and is not checked. The profile denies <WorkDir>/status
// whatever this value says, so there is no new deny that could fail to match, and
// refusing a node that starts today would change a default node for nothing.
func statusRecordDirOf(cfg RuntimedConfig) (string, error) {
	dir, err := absDenyDir(cfg.StatusRecordDir, ErrStatusRecordDirNotCanonical)
	if err != nil {
		return "", err
	}
	own := filepath.Join(runtimeRoot(cfg.Root), sandbox.StatusSubdir)
	if dir != "" && withoutFirmlink(dir) == withoutFirmlink(own) {
		warnStatusDirEscapes(cfg.Logger, own)
		return own, nil
	}
	if err := checkStatusRecordDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// warnStatusDirEscapes logs once when the runtime's own status directory resolves
// to a different place than its spelling, because the sandbox deny written from
// the spelling does not follow the link. A resolution error (the directory does
// not exist yet) logs nothing: the node still starts.
func warnStatusDirEscapes(log *slog.Logger, own string) {
	if log == nil {
		return
	}
	resolved, err := filepath.EvalSymlinks(own)
	if err != nil || withoutFirmlink(resolved) == withoutFirmlink(own) {
		return
	}
	log.Warn("the status directory resolves elsewhere; the sandbox deny on it does not cover the real location",
		"status_dir", own, "resolved", resolved)
}

// ErrDataRootNotCanonical reports a data root, or its server or agent directory,
// that exists under a path other than the one configured, a symlink or a spelling
// the macOS firmlinks do not explain. libsandbox matches resolved paths, so the
// Seatbelt deny written from the configured string would match nothing, and
// nothing would report it.
var ErrDataRootNotCanonical = errors.New("data root is not its own resolved path")

// dataRootOf returns the data root the Seatbelt denies are written from, or an
// error when a deny could not match. A relative value (a relative --work-dir) is
// made absolute, because that is where the state it names is written, and
// runtime.New refuses a relative one.
//
// A data root that is the runtime's own root returns in the runtime's spelling and
// is not checked. The profile adds no deny for it, so there is no new deny that could
// fail to match, and refusing a node that starts today would change a default node
// for nothing.
func dataRootOf(cfg RuntimedConfig) (string, error) {
	dir, err := absDenyDir(cfg.DataRoot, ErrDataRootNotCanonical)
	if err != nil {
		return "", err
	}
	root := runtimeRoot(cfg.Root)
	if dir != "" && withoutFirmlink(dir) == withoutFirmlink(root) {
		return root, nil
	}
	if err := checkDataRoot(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// checkDataRoot refuses a data root whose resolved path is not the configured
// string, and one whose denied children are not, since either would leave a deny
// matching nothing. The list is the one the profile renders.
func checkDataRoot(dir string) error {
	if dir == "" {
		return nil
	}
	if err := checkResolvedDir(dir, ErrDataRootNotCanonical); err != nil {
		return err
	}
	for _, sub := range sandbox.DataRootDenySubdirs() {
		if err := checkResolvedDir(filepath.Join(dir, sub), ErrDataRootNotCanonical); err != nil {
			return err
		}
	}
	return nil
}

// absDenyDir makes a set deny directory absolute. Empty stays empty.
func absDenyDir(dir string, sentinel error) (string, error) {
	if dir == "" || filepath.IsAbs(dir) {
		return dir, nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", sentinel, dir, err)
	}
	return abs, nil
}

// checkStatusRecordDir refuses a status record directory whose resolved path is
// not the configured string, the /var, /tmp and /etc firmlinks aside. A directory
// that does not exist has nothing to mismatch yet (the writers skip it). One that
// cannot be read fails closed, because the deny could not be shown to match.
func checkStatusRecordDir(dir string) error {
	if dir == "" {
		return nil
	}
	return checkResolvedDir(dir, ErrStatusRecordDirNotCanonical)
}

// checkResolvedDir refuses, with sentinel, a directory that exists under a path
// other than dir, the firmlinks aside. A missing directory passes and an unreadable
// one fails, for the reasons checkStatusRecordDir gives.
func checkResolvedDir(dir string, sentinel error) error {
	if _, err := os.Lstat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: %q: %w", sentinel, dir, err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", sentinel, dir, err)
	}
	if withoutFirmlink(resolved) != withoutFirmlink(dir) {
		return fmt.Errorf("%w: %q resolves to %q", sentinel, dir, resolved)
	}
	return nil
}

// withoutFirmlink returns path in its /var, /tmp or /etc spelling when it is
// written under the /private directory those three resolve to.
func withoutFirmlink(path string) string {
	for _, target := range []string{"/private/var", "/private/tmp", "/private/etc"} {
		if path == target || strings.HasPrefix(path, target+"/") {
			return strings.TrimPrefix(path, "/private")
		}
	}
	return path
}

// rotationMaxSize returns the configured container-log max size, defaulting to
// the kubelet's own.
func rotationMaxSize(cfg RuntimedConfig) string {
	if cfg.ContainerLogMaxSize == "" {
		return podlogs.DefaultContainerLogMaxSize
	}
	return cfg.ContainerLogMaxSize
}

// rotationMaxFiles returns the configured container-log file count, defaulting to
// the kubelet's own. Zero means "unset" here, not "keep nothing": the flag layer
// rejects an explicit value <= 1 before it ever reaches this point.
func rotationMaxFiles(cfg RuntimedConfig) int {
	if cfg.ContainerLogMaxFiles == 0 {
		return podlogs.DefaultContainerLogMaxFiles
	}
	return cfg.ContainerLogMaxFiles
}

// StartLogMaintenance starts container-log rotation and the log garbage
// collector, and ARMS the GC by recording that the node's pod set has synced.
//
// It is called once, by the node bring-up, AFTER Virtual Kubelet reports the node
// ready — which is after its pod informer has synced, so the provider's track map
// is the cluster's view of this node rather than an empty map that has not been
// filled in yet. Starting the GC any earlier would let it read "no pods" and
// delete every pod log tree on the node after each restart.
func (r *runtimedRuntime) StartLogMaintenance(ctx context.Context) {
	r.MarkPodsSynced()
	r.logRotator.Start(ctx)
	go r.logGC.Run(ctx)
}

// baseSocketDenies returns the AF_UNIX deny-set the provider adds to every
// pod profile ON ITS OWN AUTHORITY: the runtimed control socket, in both
// spellings a daemon can serve it at. root is RuntimedConfig.Root (empty ⇒ the
// runtime default work-dir).
//
// It is derived rather than accepted from the caller because a deny the producer
// must remember to list is a deny that gets forgotten — the caller-supplied list
// (RuntimedConfig.DeniedUnixSocketPaths) named the k3sm-netd helper socket and
// not this one. Callers EXTEND this set; they cannot shrink it.
//
// TWO SPELLINGS, and neither implies the other:
//
//   - runtimed.DefaultSocketPath — the absolute default a daemon started without
//     an explicit socket path listens on, wherever its work-dir happens to be; and
//   - <root>/run/runtimed.sock — the work-dir-derived spelling THIS node serves,
//     produced by RuntimedSocketPath. That is the ONE derivation the node's
//     control-socket listener also goes through, so the socket a node actually
//     binds is by construction a socket every pod profile denies. The standalone
//     k3sm-runtimed daemon still takes its socket from --socket, defaulting to
//     the absolute const above and never derived from --root, which is why both
//     spellings are emitted rather than one; in the default posture they coincide
//     and the dedupe leaves a single entry.
//
// This mirrors the SBPL generator's own posture resolution, which pins the
// ABSOLUTE run-dir into the file-deny set in addition to the work-dir-derived one
// for exactly this asymmetry (see sandbox.RunSubdir). Both leaf names are taken
// from runtimed's exported const so a rename upstream cannot leave a deny
// guarding a socket nobody serves. In the default posture the two spellings
// coincide and only one is emitted.
//
// WHAT THIS BUYS, precisely: the node builds its runtime IN-PROCESS (NewRuntimed
// → runtime.New) and SERVES it on the derived socket above, so this deny closes
// a LIVE channel rather than pre-positioning against a future one. It has to:
// the socket's 0700-dir / 0600-node posture admits the daemon's own uid, and a
// confined pod runs as that same uid, so the filesystem permissions alone do not
// fence a pod out of the node's control API. The deny is what does. It also
// fences the standalone k3sm-runtimed posture used in a lab.
//
// WHAT IT DOES NOT COVER. A Seatbelt path-deny is not a capability boundary:
//
//   - a daemon started with a different --socket path: this is a const plus a
//     work-dir derivation and does not track that flag;
//   - any control endpoint reachable over TCP/localhost, which the profile's
//     allow_network stanza permits outright; and
//   - a socket fd already open and inherited across exec, which no path deny can
//     revoke.
//
// netd's socket is in the base set for the SAME reason, and deliberately so: the
// node command still passes it, but a deny that only exists because a caller
// remembered to pass it is the exact defect this base set exists to remove — and
// netd being the ONE the caller did remember is not a reason to leave it the one
// that can be forgotten. Both are unioned, so the caller's list stays additive.
func baseSocketDenies(root string) []string {
	if root == "" {
		root = sandbox.DefaultWorkDir
	}
	return []string{
		runtimed.DefaultSocketPath,
		RuntimedSocketPath(root),
		netd.DefaultSocketPath,
		filepath.Join(root, sandbox.RunSubdir, filepath.Base(netd.DefaultSocketPath)),
	}
}

// RuntimedSocketPath returns the unix socket a node whose runtime root is root
// serves its runtimed gRPC control API on: <root>/run/runtimed.sock, the leaf
// name taken from runtimed's own exported default so a rename upstream cannot
// leave the two out of step. An empty root means the runtime default work-dir,
// for which the result is exactly runtimed.DefaultSocketPath — so a stock
// install serves the very path `k3sm image` dials by default, and a second
// instance with its own root (a `k3sm dev` cluster, a lab node) serves beside
// its own image store instead of contending for the shared one.
//
// It is EXPORTED and used by baseSocketDenies so there is exactly one derivation
// of this path in the tree. That is the point: the served socket and the pod
// deny-set are then the same string by construction, and a node cannot come to
// serve a control API at an address no pod profile denies.
func RuntimedSocketPath(root string) string {
	if root == "" {
		root = sandbox.DefaultWorkDir
	}
	return filepath.Join(root, sandbox.RunSubdir, filepath.Base(runtimed.DefaultSocketPath))
}

// stampSocketDenies merges the provider's non-omittable deny-set onto sp.
//
// It is a method rather than two inline lines so the union is FALSIFIABLE: no
// end-to-end case can tell a union from a plain assignment today, because
// nothing in the translation path pre-sets the field — so without a seam to
// assert through, a regression to `=` would be caught by nothing. A nil profile
// is a no-op; it fails closed further down, where the generator refuses a box
// with no data volume.
func (r *runtimedRuntime) stampSocketDenies(sp *runtimev1.SandboxProfile) {
	if sp == nil {
		return
	}
	sp.DeniedUnixSocketPaths = unionSocketDenies(sp.GetDeniedUnixSocketPaths(), r.deniedSocks)
}

// unionSocketDenies returns the sorted, deduplicated union of the socket-path
// sets, dropping empty entries. Union — never replace — is what keeps a
// caller-supplied list additive with respect to the base deny-set.
func unionSocketDenies(sets ...[]string) []string {
	var out []string
	for _, set := range sets {
		for _, p := range set {
			if p != "" {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// stampLocalPortDenies merges the node's denied-local-port set onto sp,
// UNCONDITIONALLY — for every pod, exactly like stampSocketDenies, and for the
// same reason: the SBPL generator (not this method) is what decides whether a
// pod that requested no network gets a deny stanza emitted at all, and the
// provider must not pre-empt that by omitting the field for a "plain" pod. A
// nil profile is a no-op.
func (r *runtimedRuntime) stampLocalPortDenies(sp *runtimev1.SandboxProfile) {
	if sp == nil {
		return
	}
	sp.DeniedLocalPorts = unionLocalPortDenies(sp.GetDeniedLocalPorts(), r.deniedLocalPorts)
}

// stampShimReadPaths adds the node's pod-support DYLD shim files to the pod's
// Seatbelt read allow (SandboxProfile.ExtraReadPaths). dyld loads an inserted
// library INSIDE the confined pod, so the pod profile must be able to read the
// file, and its read baseline is only /System, /usr, /bin and /Library: a shim
// staged anywhere else (a rootless `k3sm dev` instance stages beside its runtime
// root) is unreadable there, and dyld fails CLOSED, killing the pod at exec.
//
// The grant is exactly the configured FILES, never their directory, so nothing
// else that lands beside them becomes pod-readable. It is uniform: for a shim
// under /Library the entry is already inside the baseline and changes nothing.
// A union, like the deny stamps above, so a grant an earlier translation step
// put on the profile survives. A nil profile is a no-op.
func (r *runtimedRuntime) stampShimReadPaths(sp *runtimev1.SandboxProfile) {
	if sp == nil {
		return
	}
	paths := sp.GetExtraReadPaths()
	for _, shim := range []string{r.dyldShim, r.pathShim} {
		if shim != "" && !slices.Contains(paths, shim) {
			paths = append(paths, shim)
		}
	}
	sp.ExtraReadPaths = paths
}

// unionLocalPortDenies returns the sorted, deduplicated union of the port
// sets. Union — never replace — for the same additivity reason as
// unionSocketDenies.
func unionLocalPortDenies(sets ...[]uint32) []uint32 {
	var out []uint32
	for _, set := range sets {
		out = append(out, set...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// normalizeLocalPortDenies validates and returns the sorted, deduplicated set
// of RuntimedConfig.DeniedLocalPorts as the apis wire type (uint32). Every
// value MUST be a valid TCP port (1-65535); an out-of-range value is rejected
// with an error rather than silently dropped or clamped, so a misconfigured
// node fails construction closed instead of stamping pods with a deny stanza
// that reads as protection it never applied.
func normalizeLocalPortDenies(ports []int) ([]uint32, error) {
	out := make([]uint32, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("denied local port %d out of range 1-65535", p)
		}
		out = append(out, uint32(p))
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// ConditionVMArtifactsAvailable is the NAME the guest-artifact capability is
// narrated under.
//
// It is a k3sm-local string, NOT one of runtimed's imported RuntimeCondition Type
// constants, because no RuntimeCondition carries this fact: the ensure runs here,
// so runtimed has nothing to report (see NodeCapabilities.VMArtifacts). It is
// exported so the log line, the ledger, the docs and the integration gate all
// spell the capability the same way — a capability whose name is retyped at each
// site is one an operator cannot grep for.
const ConditionVMArtifactsAvailable = "VMArtifactsAvailable"

// NodeCapabilities are the node-capability facts runtimed advertises as
// GetRuntimeInfo RuntimeConditions and the node command turns into truthful node
// labels. They travel as ONE struct, from ONE RPC, deliberately: three separate
// probes could each observe a DIFFERENT daemon state and produce an incoherent
// label set (k3sm.io/rosetta-linux stamped from a later observation while
// k3sm.io/virtualization was deleted from an earlier one). Every field fails CLOSED
// — the zero value advertises nothing.
type NodeCapabilities struct {
	// VMBackend is the VMBackendAvailable condition: this host can run the vm
	// RuntimeClass (Virtualization.framework isSupported + the
	// com.apple.security.virtualization entitlement). Drives k3sm.io/virtualization.
	VMBackend bool
	// VMArtifacts is the VMArtifactsAvailable condition: this node holds the pinned
	// guest kernel + initramfs, digest-verified on THIS daemon start, so a booted
	// guest has something to boot. Drives k3sm.io/vm-artifacts.
	//
	// It is the ONE field here that does NOT come off the GetRuntimeInfo response,
	// and the asymmetry is deliberate rather than an oversight: the ensure runs in
	// k3sm (GuestArtifactSource.Ensure, at daemon start), so runtimed has no
	// condition to report — it is handed the outcome as a construction input. It
	// still fails CLOSED with the rest of the struct: the zero value advertises
	// nothing, and a probe error leaves it false along with everything else.
	//
	// It is INDEPENDENT of VMBackend. The two answer different questions — "can
	// this Mac run a guest" and "does this node have a guest to run" — and either
	// can be true without the other (an entitled Mac that could not fetch; an
	// air-gap-seeded cache on a Mac with no VZ). A vm pod needs both, which is why
	// the vm RuntimeClass still selects on k3sm.io/virtualization and this label is
	// additive advertisement, not a second scheduling gate.
	VMArtifacts bool
	// RosettaHost is the RosettaHostAvailable condition: this host can translate
	// darwin/amd64 Mach-O payloads via Rosetta 2 on the NATIVE host-process spine.
	// Drives k3sm.io/rosetta.
	RosettaHost bool
	// RosettaGuest is the RosettaGuestAvailable condition: a Linux guest on this host
	// could translate linux/amd64 ELF payloads via Rosetta for Linux. It is only HALF
	// of k3sm.io/rosetta-linux — that label is RosettaGuest AND VMBackend, since
	// without the vm backend there is no guest to translate in (see
	// cmd/k3sm applyRosettaLabels).
	RosettaGuest bool
	// GPU is the host's GPU facts as runtimed reports them, carried VERBATIM from
	// GetRuntimeInfoResponse.gpu (the raw chip_brand keeps its spaces — the node-label
	// slug is derived by the advertiser, per the mlx.k3sm.io chip-slug rule). It drives
	// the mlx.k3sm.io/gpu extended resource and the mlx.k3sm.io chip/memory labels (see
	// cmd/k3sm applyGPUAdvertisement).
	//
	// nil means this daemon reports no GPU facts AT ALL — an older daemon — which is
	// DISTINCT from a report of a host with no usable GPU (present, MetalAvailable
	// false). The two are deliberately not collapsed here: they advertise the same
	// nothing, but only one of them is fixed by upgrading the daemon, and the consumer
	// says so in its log line. A pointer, unlike the bools above, is therefore a
	// three-state fact and its zero value still fails CLOSED.
	GPU *runtimev1.GPUFacts
}

// Capabilities probes runtimed ONCE and reports every node capability the node
// command labels from. One RPC for all three booleans is load-bearing: separate
// calls could straddle a daemon restart and yield a mutually-inconsistent label set.
// It fails CLOSED (the zero value — nothing advertised) on an RPC error, so a probe
// failure never FALSELY advertises a capability the node does not have.
func (r *runtimedRuntime) Capabilities(ctx context.Context) NodeCapabilities {
	info, err := r.rt.GetRuntimeInfo(ctx, &runtimev1.GetRuntimeInfoRequest{})
	if err != nil {
		r.log.Warn("node-capability probe failed; advertising no capabilities (fail-closed)", "err", err)
		return NodeCapabilities{}
	}
	caps := nodeCapabilitiesFromInfo(info)
	// Stamped from what THIS provider wired, not read back off the response: the
	// ensure is k3sm's (see NodeCapabilities.VMArtifacts), so the runtime has no
	// opinion to report and a `conditionTrue` read would be permanently false.
	caps.VMArtifacts = r.guestArtifacts
	// Log at the boundary WITH each withheld capability's Reason: the condition's
	// Reason/Message is the only answer to "why is my node not labelled rosetta?",
	// and it is discarded once this returns a bare bool.
	logWithheldCapability(r.log, info, runtimed.ConditionVMBackendAvailable, caps.VMBackend)
	logWithheldCapability(r.log, info, runtimed.ConditionRosettaHostAvailable, caps.RosettaHost)
	logWithheldCapability(r.log, info, runtimed.ConditionRosettaGuestAvailable, caps.RosettaGuest)
	// The artifact capability has no RuntimeCondition to carry a Reason, so its
	// withheld case is narrated here with the condition name the ledger and the
	// docs use. GuestArtifactSource.Ensure already logged the CAUSE at start; this
	// line is what an operator finds when they ask why the node is not labelled.
	if !caps.VMArtifacts {
		r.log.Info("node capability withheld: "+ConditionVMArtifactsAvailable+
			" is false — no digest-verified guest boot artifacts were wired into this runtime, so every vm pod fails closed",
			"condition", ConditionVMArtifactsAvailable)
	}
	return caps
}

// GetRuntimeInfo forwards one runtime-info probe to the in-process runtime,
// verbatim — no interpretation, no fail-closed substitution.
//
// It exists so a consumer that needs a FACT off the runtime-info response rather
// than a node-capability verdict (the MLX operator's GPU facts, which carry the
// memory ceilings its pre-render fit check sizes against) can read it from the
// SAME embedded runtime this provider already drives, instead of opening a second
// connection to a daemon the shipped install does not even run standalone.
//
// It deliberately returns the error rather than swallowing it the way Capabilities
// and Healthy do: those two answer "may this node advertise X", where an
// unanswerable probe MUST read as no; this one answers "what did the runtime say",
// where an unanswerable probe is not a fact about the host and the caller has to
// be able to tell the two apart.
//
// The signature matches runtimev1.RuntimeServer's method exactly, so this value
// satisfies a one-method consumer interface over that RPC with no adapter.
func (r *runtimedRuntime) GetRuntimeInfo(ctx context.Context, req *runtimev1.GetRuntimeInfoRequest) (*runtimev1.GetRuntimeInfoResponse, error) {
	return r.rt.GetRuntimeInfo(ctx, req)
}

// Healthy reports whether runtimed considers itself able to serve pods, from the
// overall health flag on its runtime-info response (the conditions detail which
// subsystem is at fault; this is the summary the node's Ready condition needs).
//
// It fails CLOSED: a failed probe reports unhealthy, because a runtime that
// cannot answer is not a runtime that has answered yes. The caller debounces the
// verdict over consecutive samples, so one failed probe never reaches the node
// object on its own.
func (r *runtimedRuntime) Healthy(ctx context.Context) bool {
	info, err := r.rt.GetRuntimeInfo(ctx, &runtimev1.GetRuntimeInfoRequest{})
	if err != nil {
		r.log.Warn("runtime health probe failed; reporting unhealthy (fail-closed)", "err", err)
		return false
	}
	if !info.GetHealthy() {
		r.log.Warn("runtime reports itself unhealthy", "conditions", len(info.GetConditions()))
	}
	return info.GetHealthy()
}

// nodeCapabilitiesFromInfo maps a GetRuntimeInfo response to the node capabilities.
// Pure — so the truthful-labeling mapping is unit-tested without a live runtimed.
//
// It fails CLOSED on every degenerate input: a nil response, an empty condition
// list, a condition ABSENT from the list (an older runtimed that predates the
// capability), and any status that is not explicitly TRUE — including UNKNOWN and
// the proto zero UNSPECIFIED, which a `!= FALSE` test would have read as capable.
// The condition Type strings are IMPORTED from runtimed, never restated here: the
// reader fails closed, so a typo would mean a permanently-absent label with no error
// anywhere — importing makes a producer/consumer rename a COMPILE error.
func nodeCapabilitiesFromInfo(info *runtimev1.GetRuntimeInfoResponse) NodeCapabilities {
	return NodeCapabilities{
		VMBackend:    conditionTrue(info, runtimed.ConditionVMBackendAvailable),
		RosettaHost:  conditionTrue(info, runtimed.ConditionRosettaHostAvailable),
		RosettaGuest: conditionTrue(info, runtimed.ConditionRosettaGuestAvailable),
		// The GPU facts are a MESSAGE on the response, not a RuntimeCondition, so they
		// are read straight through rather than via conditionTrue. The getter is
		// nil-safe on both the response and the field, which is what makes the
		// older-daemon case (no gpu field) a nil that advertises nothing.
		GPU: info.GetGpu(),
	}
}

// conditionTrue reports whether info carries condType with status TRUE. FIRST match
// wins (a duplicated Type — which runtimed never emits — is resolved by the first
// occurrence, the documented verdict); an absent condition or any non-TRUE status is
// false.
func conditionTrue(info *runtimev1.GetRuntimeInfoResponse, condType string) bool {
	c := findRuntimeCondition(info, condType)
	return c.GetStatus() == runtimev1.ConditionStatus_CONDITION_STATUS_TRUE
}

// findRuntimeCondition returns the FIRST condition of the given Type, or nil. The
// proto getters are nil-safe, so callers may use the result unchecked.
func findRuntimeCondition(info *runtimev1.GetRuntimeInfoResponse, condType string) *runtimev1.RuntimeCondition {
	for _, c := range info.GetConditions() {
		if c.GetType() == condType {
			return c
		}
	}
	return nil
}

// logWithheldCapability logs, at the capability boundary, why a capability is NOT
// advertised — carrying the condition's Reason/Message (the runtimed reason
// vocabulary: NotInstalled / TranslationFailed / NotSupported / QueryFailed /
// VMBackendUnavailable) so an operator can answer "why is my node not labelled
// rosetta?" from server.log. An advertised capability is logged at Debug; an ABSENT
// condition (an older runtimed) is reported as such rather than as a silent false.
//
// It names the CONDITION, never a k3sm.io/* label key: this package holds no label
// vocabulary (the keys live in pkg/runtimeclass, next to the selector that consumes
// them), and one condition does not map 1:1 to one label anyway — rosetta-linux is a
// conjunction. The paired line naming the LABEL the verdict resolved to is emitted by
// cmd/k3sm's setLabelPresence / applyRosettaLabels, which own that decision.
func logWithheldCapability(log *slog.Logger, info *runtimev1.GetRuntimeInfoResponse, condType string, advertised bool) {
	if advertised {
		log.Debug("node capability advertised", "condition", condType)
		return
	}
	c := findRuntimeCondition(info, condType)
	if c == nil {
		log.Info("node capability withheld: runtimed does not report this condition (older daemon); failing closed",
			"condition", condType)
		return
	}
	log.Info("node capability withheld by runtimed; the node will NOT be labelled for it",
		"condition", condType, "status", c.GetStatus().String(), "reason", c.GetReason(), "message", c.GetMessage())
}

// ServableRuntime implements the optional ControlSocketSource capability: it
// hands back the in-process *runtime.Runtime this provider drives, so the node
// can additionally SERVE it on runtimed's gRPC control socket and the
// daemon-side `k3sm image` commands work on a stock install.
//
// It is comma-ok rather than a bare pointer because the field it reads is the
// runtimev1.RuntimeServer seam newRuntimedWith accepts, and the unit tests
// inject a fake through exactly that seam. false therefore means "this provider
// is not driving a real runtimed runtime" — a test double, or any future
// out-of-process backend — and the caller serves nothing, which is the only
// honest answer: a Server can only be built over the concrete runtime.
//
// It returns the runtime UNWRAPPED and shared, not a copy: the whole point is
// that the socket serves the SAME instance the VK node drives, so an image
// loaded over the socket is visible to the next pod this node starts. A second
// runtime over the same root would be a second writer to one image store.
func (r *runtimedRuntime) ServableRuntime() (*runtimed.Runtime, bool) {
	rt, ok := r.rt.(*runtimed.Runtime)
	return rt, ok
}

// errNoImageIndex is returned by ImageIndexSnapshot when the runtime behind
// this provider keeps no image index (a test double).
var errNoImageIndex = errors.New("runtime keeps no image index")

// ImageIndexSnapshot implements the optional ImageInventory capability: the
// image index of the in-process runtime, which is what the runtime's
// ListImages RPC serves, read without a socket round trip.
func (r *runtimedRuntime) ImageIndexSnapshot(ctx context.Context) ([]image.IndexEntry, error) {
	inv, ok := r.rt.(ImageInventory)
	if !ok {
		return nil, errNoImageIndex
	}
	return inv.ImageIndexSnapshot(ctx)
}

// Compile-time check that runtimedRuntime satisfies the Runtime seam and the
// optional StatsSource capability (the Summary API surface).
var (
	_ Runtime             = (*runtimedRuntime)(nil)
	_ StatsSource         = (*runtimedRuntime)(nil)
	_ HealthReporter      = (*runtimedRuntime)(nil)
	_ ControlSocketSource = (*runtimedRuntime)(nil)
	_ ImageInventory      = (*runtimedRuntime)(nil)
)

// podIP resolves the pod's IP BEFORE translation — the ordering rule: the
// /32 must exist before toPodBox so box.PodIp, the downward-API status.podIP
// env fieldRefs (resolvePodBoxEnv reads box.GetPodIp()), the SBPL bind
// discipline, and pod status all carry ONE authority. The runtimed-side seam's
// later Setup for the same podID is idempotent and returns the SAME address.
//
// Branches (each documented, never a silent fallback):
//
//   - no adapter (nil network — the --network none posture): podIP ≈ nodeIP.
//
//   - spec.hostNetwork: the pod shares the node's addresses — no /32. The pod is
//     marked on the adapter so the runtimed-side seam Setup (which the
//     host-process spine calls unconditionally) also resolves it to the node IP.
//
//   - vm RuntimeClass: the /32 darwin-net podnet.Network.SetupGuest allocated for
//     the guest, via setupGuestNetwork — the SAME address the adapter carries to
//     runtimed as sandbox.VMSpec.Network through the runtime.GuestNetworker seam.
//     SetupGuest is idempotent per podID, so buildBox's later call a few frames
//     down returns this very address and there is still exactly one authority.
//     SetupGuest also aliases the /32 on lo0 for the pod's lifetime, owned by
//     the HOST, not the guest: the guest never holds this address. The alias is
//     what makes the published address answer on this node, and what the mesh's
//     route for the node's /24 delivers remote traffic to.
//
//     WHY THE GUEST'S /32 IS PUBLISHED WHILE THE GUEST DOES NOT HOLD IT. A vm pod
//     has TWO addresses and they are never reconciled into one. This /32 is its
//     cluster IDENTITY — what status.podIP, its EndpointSlices, cluster DNS and
//     every NetworkPolicy carry. The address that carries bytes is the guest's
//     macOS-assigned vmnet DHCP lease, reported by the guest agent as
//     PodStatus.guest_transport_address; it is never published, because a lease
//     churns on every guest restart while an identity must not. The node
//     TRANSLATES between the two: observeTransport feeds the Service proxy a
//     published->live transport map keyed on exactly this /32, with the pod's
//     declared TCP ports (proxy.RoutingTable.SetTransportOverrides), so a Service
//     backend picked and policy-checked on the identity is dialed at the lease,
//     and the proxy's relay listens on the aliased /32 for each declared or
//     Service-targeted TCP port and forwards to the lease. Publishing the node IP
//     here — which this branch used to do — gave
//     every vm pod on a node the same status.podIP, which no override map can be
//     keyed on and which no Service could distinguish.
//
//   - otherwise: the podnet /32. Pool exhaustion surfaces as a distinguishable
//     error (errors.Is(err, podnet.ErrPoolExhausted) holds through the wrap) —
//     identically for the guest branch, which draws from the same node pool.
func (r *runtimedRuntime) podIP(ctx context.Context, pod *corev1.Pod) (string, error) {
	if r.network == nil {
		return r.nodeIP, nil
	}
	id := string(pod.UID)
	if pod.Spec.HostNetwork {
		r.network.MarkHostNetwork(id)
		return r.nodeIP, nil
	}
	if backend, err := podSandboxBackend(pod); err == nil && backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		// An unknown RuntimeClass error is NOT handled here — toPodBox owns that
		// fail-closed rejection; this branch only routes a resolved vm pod to the
		// guest allocation instead of the host-process one.
		//
		// The dropped truncation count is buildBox's to report: podDNSConfig is
		// pure and this is the FIRST of the create path's two calls, so warning
		// here would double-report one pod's truncated search list.
		dnsCfg, _ := r.podDNSConfig(pod)
		gn, err := r.setupGuestNetwork(ctx, pod, dnsCfg)
		if err != nil {
			return "", err
		}
		if !gn.PodIP.IsValid() {
			// The seam allocated nothing. Fail the create rather than fall back to
			// the node IP: a vm pod published at the node's address is unaddressable
			// as a Service backend and indistinguishable from every other guest.
			return "", fmt.Errorf("allocate pod ip for %s/%s: the guest network carries no address", pod.Namespace, pod.Name)
		}
		return gn.PodIP.String(), nil
	}
	ip, err := r.network.Setup(ctx, id)
	if err != nil {
		return "", r.allocError(pod, err)
	}
	return ip, nil
}

// allocError names a pod-IP allocation failure. Exhaustion of the node pool gets
// the FRIENDLY leading clause (the 253-address ceiling is a node fact an operator
// can act on, not an internal error), and the podnet sentinel is preserved with %w
// either way.
//
// It is one function because there are now TWO consumers of that one pool — the
// host-process Setup above and the vm-guest SetupGuest — and exhaustion must read
// the same from both. Duplicating the phrasing at the second call site is exactly
// how one of them would later stop being legible.
func (r *runtimedRuntime) allocError(pod *corev1.Pod, err error) error {
	if errors.Is(err, podnet.ErrPoolExhausted) {
		return fmt.Errorf("pod ip pool exhausted on node %s (253 pods/node): allocate pod ip for %s/%s: %w", r.nodeName, pod.Namespace, pod.Name, err)
	}
	return fmt.Errorf("allocate pod ip for %s/%s: %w", pod.Namespace, pod.Name, err)
}

// releasePodNetwork tears down the pod's network allocation, log-and-continue —
// a teardown error never blocks pod deletion. runtimed's DeletePod RPC already
// tears the seam down on its side; this provider-side call (idempotent no-op
// then) covers the paths where the RPC failed or the pod never reached the
// runtime (a translate failure after allocation), so a churned pod cannot leak
// one of the 253 node addresses. The adapter's startup sweep is the backstop.
//
// ORDER: TRANSPORT OVERRIDE FIRST, THEN THE ALIAS. For a vm pod the published /32
// is a host-owned lo0 alias the Service proxy's relay listens on, and the
// override is what keeps that relay up. Dropping the override closes the relay's
// listeners and every connection it was relaying before the call returns
// (transportFeed.beginRelease -> proxy.RoutingTable.SetTransportOverrides), so
// the alias is removed only once nothing is listening on or relaying from it.
// The reverse order would pull the address out from under live sockets and
// leave the relay retrying a bind on an address the node no longer holds.
//
// NO REINSTALL WHILE RELEASING. A status observation can run concurrently and
// would otherwise put the override (and the relay) back between the drop and
// the alias removal. beginRelease marks the pod so observe refuses it, and
// endRelease clears the mark only after the adapter's Teardown has deleted the
// guest record that observe re-checks under the same lock, so no window exists
// in which an observation can reinstall it.
//
// Every path that releases a pod's /32 goes through here (DeletePod and the
// orphan reaper via teardownPod, a refused create, a refused re-attach), so the
// order holds on all of them by construction; for a host-process pod the drop
// is a no-op. The one path that drops an override WITHOUT releasing the /32 is
// eviction (evictPod): the evicted pod stays in the apiserver, its guest is
// stopped, its override and relay go, and its /32 is released by the DeletePod
// that follows, through here. teardownPod takes the override down earlier still,
// when the guest's stop succeeds, and this call finds it gone and clears the mark.
func (r *runtimedRuntime) releasePodNetwork(pod *corev1.Pod) {
	id := string(pod.UID)
	// Before the release, so a mark an overlapping call sets after this survives it.
	r.mu.Lock()
	delete(r.held, id)
	r.mu.Unlock()
	// The interconnect alias and slot go with the pod's network, on every
	// release path, and do not depend on the pod-network seam.
	r.interconnect.detach(pod)
	// Unconditional: the feed (nil-tolerant) holds the override even on a node
	// whose pod-network seam is absent, and its liveness obligation does not
	// depend on that seam.
	r.transport.beginRelease(id)
	defer r.transport.endRelease(id)
	if r.network == nil {
		return
	}
	if err := r.network.Teardown(id); err != nil {
		r.log.Warn("pod network teardown", "namespace", pod.Namespace, "name", pod.Name, "err", err)
	}
}

// setupGuestNetwork produces the guest network config of a vm-RuntimeClass pod
// and hands it to the adapter, which records it for runtimed to read back on the
// vm route (runtime.GuestNetworker -> sandbox.VMSpec.Network). It is the
// producer half; runtimed is the consumer half and never derives this itself.
// It RETURNS the config, because podIP publishes the allocated /32 as the pod's
// cluster identity — the zero value (with an invalid PodIP) for every pod the
// guards below exclude.
//
// WHERE IT RUNS. Twice on the create path, both times before translation, and
// that is safe because it is idempotent per podID: podIP calls it to learn the
// address it must publish, and buildBox calls it immediately before toPodBox.
// The buildBox call site is the one the ordering argument below is about.
// It must be BEFORE translation (the pod's network exists before the box that
// describes it), and it must consume the SAME dnsCfg value toPodBox is given —
// the per-pod, namespace-scoped config after the spec.dnsConfig merge. Deriving it a second time here would create a second
// authority for one pod's DNS, and the guest's /etc/resolv.conf would be free to
// disagree with the host-process shim env built from the first.
//
// WHAT IS EXCLUDED, and why each:
//   - a nil adapter (--network none) has nothing to allocate from;
//   - a spec.hostNetwork pod allocates NOTHING by construction (podIP marks it
//     and returns the node IP), so it must not draw a guest address either — the
//     hostNetwork check comes FIRST here for exactly the reason it comes first in
//     podIP: one pod, one answer;
//   - a non-vm pod is served by the host-process Setup and reads no guest config.
//
// A RuntimeClass that does not resolve is NOT rejected here — toPodBox owns that
// fail-closed rejection a few lines later, and duplicating it would give one
// error two spellings.
//
// It FAILS the create: a vm pod whose guest config could not be produced would
// boot with no resolver, pass readiness, and fail on its first in-app DNS lookup
// — indistinguishable at that point from an application bug. Pool exhaustion is
// named through the shared allocError, so it reads identically to a host-process
// pod exhausting the same 253 addresses.
func (r *runtimedRuntime) setupGuestNetwork(ctx context.Context, pod *corev1.Pod, dnsCfg netv1.DNSConfig) (sandbox.GuestNetworkConfig, error) {
	if r.network == nil || pod.Spec.HostNetwork {
		return sandbox.GuestNetworkConfig{}, nil
	}
	backend, err := podSandboxBackend(pod)
	if err != nil || backend != runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		return sandbox.GuestNetworkConfig{}, nil
	}
	gn, err := r.network.SetupGuest(ctx, string(pod.UID), dnsCfg)
	if err != nil {
		return sandbox.GuestNetworkConfig{}, r.allocError(pod, err)
	}
	return gn, nil
}

// podDNSConfig derives one pod's cluster DNS config: the namespace-scoped cluster
// base (dns.PodDNSConfig), additively merged with a ClusterFirst pod's
// spec.dnsConfig (extra search domains appended+deduped, an ndots override).
// The merge is GATED on the cluster-DNS policy — NOT left to injectClusterDNSEnv's
// downstream gate — so the seam is structural: a None/Default pod gets the
// UNMERGED base, so when a later change makes None inject its own config it cannot
// inherit a cluster-base merge. dnsConfigOverride does the corev1→discrete-params extraction
// (k3sm is the corev1-aware layer); dns.MergeDNSConfig can only ADD search/ndots,
// never repoint the cluster server VIP.
//
// It returns the config and the number of search domains the in-pod cap DROPPED,
// and logs nothing: the create path calls it twice for a vm pod (podIP, to learn
// the guest address it must publish, and buildBox, to translate), so warning inside
// would double-report one pod's truncation. buildBox owns that warning.
//
// It exists as one function for the same reason allocError does: the guest's
// /etc/resolv.conf and its containers' injected K3SM_DNS_* env are derived from
// this value, and a second derivation is how the two would come to disagree.
func (r *runtimedRuntime) podDNSConfig(pod *corev1.Pod) (netv1.DNSConfig, int) {
	dnsCfg := dns.PodDNSConfig(r.resolverVIP, r.clusterDomain, pod.Namespace)
	if !clusterDNSPolicy(pod.Spec.DNSPolicy) || pod.Spec.DNSConfig == nil {
		return dnsCfg, 0
	}
	searches, ndots := dnsConfigOverride(pod.Spec.DNSConfig)
	return dns.MergeDNSConfig(dnsCfg, searches, ndots)
}

// buildBox translates pod to a PodBox and resolves its env into LITERAL values —
// runtimed reads only EnvVar.value and never talks to the apiserver, so the
// provider resolves configMap/secret/envFrom (via its Resolver) and downward-API
// (via the node identity) here, before the box crosses the runtime boundary.
// podIP is the pod's already-resolved IP (see podIP — allocated BEFORE this
// translation so the box and its resolved env carry the real /32).
func (r *runtimedRuntime) buildBox(ctx context.Context, pod *corev1.Pod, podIP string) (*runtimev1.PodBox, error) {
	// Per-pod cluster DNS config: the search list is namespace-scoped
	// (<ns>.svc.<domain>, …) so an unqualified Service name in this pod's namespace
	// resolves first. toPodBox injects it (DNSPolicy-gated) into the containers.
	dnsCfg, dropped := r.podDNSConfig(pod)
	if dropped > 0 {
		// The pod's merged search list exceeded the in-pod cap (MaxSearchDomains, a
		// deliberate divergence from upstream's 32); the tail was truncated. Log once
		// here at the corev1-aware boundary WITH pod identity — the darwin-net merge
		// primitive stays pure and returns the count rather than logging blind, and
		// podDNSConfig's other caller (podIP) deliberately drops the count so one
		// pod's truncation is reported once.
		r.log.WarnContext(ctx, "pod dnsConfig search list truncated to the in-pod cap",
			"namespace", pod.Namespace, "name", pod.Name, "dropped", dropped, "cap", dns.MaxSearchDomains)
	}
	// Produce the vm pod's GUEST network config BEFORE translation, from the very
	// dnsCfg above — the one-authority ordering applied to the guest carrier.
	// A no-op for every non-vm pod, and idempotent for a vm pod whose address podIP
	// already drew through this same call.
	if _, err := r.setupGuestNetwork(ctx, pod, dnsCfg); err != nil {
		return nil, err
	}
	box, err := toPodBox(pod, podIP, r.nodeIP, r.podRoot(string(pod.UID)), r.dyldShim, dnsCfg, r.log)
	if err != nil {
		return nil, err
	}
	// Deny every pod the daemon control sockets: pods share the _k3sm uid with the
	// legitimate daemon clients, so the sandbox is where a privileged daemon is
	// fenced off from the workload.
	//
	// UNCONDITIONAL on the deny-set being non-empty, and a UNION rather than an
	// assignment. An emptiness guard would let a caller that supplied no paths
	// render a profile with no socket-deny stanza at all — indistinguishable, in the
	// generated profile, from "nothing needed denying", which is the worst shape a
	// default-deny control can take; and a bare `=` would drop any deny a future
	// translation step had already put on the box.
	//
	// NO ASYMMETRY: baseSocketDenies carries BOTH daemon sockets non-omittably.
	// The node command still passes netd's, and that stays harmless because this
	// is a union — but a deny that exists only because a caller remembered to pass
	// it is precisely the defect the base set removes, and netd being the one the
	// caller did remember is no reason to leave it the one that can be forgotten.
	// The pod's CRI log directory, and the directories themselves. Applied HERE
	// rather than inside toPodBox for the same reason the socket denies below are:
	// the tree's root is a NODE fact (--pod-logs-dir), which the pure pod
	// translation neither carries nor should.
	//
	// The MkdirAll rides with it deliberately. runtimed opens
	// <log_directory>/<container>/<n>.log and creates no directory above the
	// container's own, so the box and the tree it names have to be produced
	// together or a pod starts with nowhere to write. It is idempotent, so the
	// update and parked-retry paths through this function cost one stat per
	// container.
	logDir, err := r.ensurePodLogDirs(pod)
	if err != nil {
		return nil, err
	}
	box.LogDirectory = logDir
	r.stampSocketDenies(box.SandboxProfile)
	r.stampLocalPortDenies(box.SandboxProfile)
	r.stampShimReadPaths(box.SandboxProfile)
	// Xcode-toolchain opt-in: stamp the node's developer dir onto a pod that asked
	// for it. Applied HERE and not inside toPodBox because the grant is a node
	// fact (this node's `xcode-select -p`), which the pure pod translation does not
	// and should not carry — the same split as the socket denies above.
	applyXcodeToolchain(box.SandboxProfile, pod, r.developerDir)
	// The namespace service links are resolved HERE, once per pod, where the
	// live pod (and so spec.enableServiceLinks) is in scope; env.go only
	// upserts the result into each container and stays free of corev1.
	links, err := namespaceServiceLinks(ctx, r.client, pod)
	if err != nil {
		return nil, err
	}
	// The service-account fact goes through the package's one resolver
	// (podServiceAccount) so the downward API and the token binding can never
	// disagree about the account a pod with an unset spec runs as.
	facts := podFacts{nodeName: r.nodeName, nodeIP: r.nodeIP, serviceAccount: podServiceAccount(pod), apiServerVIP: r.apiServerVIP, serviceLinks: links}
	if err := resolvePodBoxEnv(ctx, box, facts, r.resolver); err != nil {
		return nil, err
	}
	// The interconnect env goes AFTER the pod's own (resolved) env, so a
	// pod-supplied K3SM_INTERCONNECT_* value never survives. It reads the
	// create-time attach outcome; nothing here attaches.
	r.interconnect.injectEnv(pod, box)
	// In-pod cluster-DNS visibility: log the FINAL injected state (after
	// resolvePodBoxEnv) so a "no such host" failure shows whether the getaddrinfo
	// shim (dyld annotation) and its K3SM_DNS_SERVER env actually landed on the box.
	if cs := box.GetContainers(); len(cs) > 0 {
		var dnsServer string
		for _, e := range cs[0].GetEnv() {
			if e.GetName() == "K3SM_DNS_SERVER" {
				dnsServer = e.GetValue()
				break
			}
		}
		r.log.Info("pod box cluster-DNS wiring",
			"pod", pod.Name,
			"dyld_annotation", box.GetAnnotations()[dyldInsertAnnotation],
			"k3sm_dns_server", dnsServer,
			"dns_policy", string(pod.Spec.DNSPolicy))
	}
	return box, nil
}

// fenceRelease carries out a claim (claimFenceReleaseLocked): it frees what the
// pod's UID holds (the /32, the lo0 alias, the interconnect slot and the
// references), forgets the track if a delete is owed, then ends the wait new
// creates and updates of the pod are held in. The wait ends in a defer, so a panic
// in the release cannot leave them waiting; the panic is not recovered. Ending the
// wait decides again, for a delete owed while this release ran.
func (r *runtimedRuntime) fenceRelease(pod *corev1.Pod, c *fenceClaim) {
	id := string(pod.UID)
	defer func() {
		r.mu.Lock()
		delete(r.fenceReleasing, id)
		next := r.claimFenceReleaseLocked(id)
		r.mu.Unlock()
		close(c.released)
		if next != nil {
			r.fenceRelease(pod, next)
		}
	}()
	if hook := r.fenceReleaseHook; hook != nil {
		hook(id)
	}
	r.releasePodNetwork(pod)
	if c.del != nil {
		if c.del.refusal {
			r.removePodLogs(pod)
		}
		r.forgetTorndown(pod, c.del.owned)
		return
	}
	r.refs.UnregisterPod(pod.UID)
}

// CreatePod translates the pod to a PodBox and asks the runtime to start it. The
// runtime returns a typed failure inside the response (the RPC itself returns
// nil) when the fail-closed gate rejects the pod; CreatePod surfaces that as an
// error so VK marks the pod failed.
func (r *runtimedRuntime) CreatePod(ctx context.Context, pod *corev1.Pod) error {
	// An evicted pod is terminal: it is never created again, by a resync, a
	// daemon restart, or anything else. Virtual Kubelet already skips syncing a
	// Failed pod; this is the provider's own fence behind it, so a restarted
	// node cannot resurrect a restartPolicy: Always pod that was evicted for
	// filling memory.
	if isEvictedPod(pod) || isBudgetRejectedPod(pod) {
		r.log.Info("CreatePod: the pod was evicted from or rejected by this node; not creating it",
			"namespace", pod.Namespace, "name", pod.Name, "uid", string(pod.UID))
		return nil
	}
	// A UID this node has torn down is never created again, and a UID is never
	// reused, so this create read a pod that is gone. admitOnCreate reads it again
	// where it counts the create; past that, a delete behind the create is answered by
	// its fence below and by createBehindDelete.
	if r.createIsStale(string(pod.UID)) {
		r.log.Info("CreatePod: this node has already deleted the pod; not creating it",
			"namespace", pod.Namespace, "name", pod.Name, "uid", string(pod.UID))
		return nil
	}
	// Node-side admission under pressure (admission.go), before anything is
	// registered or allocated: a refused pod holds no address, no references and
	// no sandbox, only its terminal status.
	refused, admitted := r.admitOnCreate(ctx, pod)
	if refused {
		return nil
	}
	// A deferred call so a panic anywhere below still ends the count, and with it
	// runs any release this create is the last one out to owe.
	defer r.createDone(pod, admitted)
	if hook := r.admittedHook; hook != nil {
		hook(string(pod.UID))
	}
	// Bind the pod's identity (ServiceAccount + name + UID) to the request context
	// so the shared volume Resolver mints the in-pod-API token (projected SA-token
	// volume) against the RIGHT SA and pins it to THIS Pod object — runtimed
	// threads this ctx to mount.Materialize in-process. The pod-object half
	// is what makes the token die with the pod instead of outliving it to expiry
	// see kubeResolver.ServiceAccountToken.
	ctx = withPodIdentity(ctx, pod)
	// Register the pod's Secret/ConfigMap references BEFORE anything reads
	// one (env resolution, volume materialization, the image pull): the
	// resolver refuses an unreferenced object. The create deadline bounds the
	// Forbidden retry of every read this create makes, together.
	r.mu.Lock()
	r.noteHeldLocked(pod)
	r.mu.Unlock()
	r.refs.RegisterPod(pod)
	ctx = r.refs.withCreateFetchBudget(ctx)
	id := string(pod.UID)
	start := metav1.Now()
	r.log.Info("CreatePod", "namespace", pod.Namespace, "name", pod.Name)
	// A pod starts only once every claim it mounts is Bound to a volume this
	// node can mount, as the kubelet's WaitForAttachAndMount requires
	// (claimwait.go). Checked BEFORE the address is allocated, since a held pod
	// has no sandbox to give one to. A pod the provider already runs is not
	// re-checked: an idempotent re-create must not stop a running pod whose
	// claim has since changed, which upstream does not do either.
	if prior := r.trackByID(id); prior == nil || prior.claimWaiting() {
		if msg := r.unresolvedClaims(ctx, pod); msg != "" {
			r.holdForClaims(pod, msg)
			return nil
		}
	}
	// Ordering: allocate the pod's /32 BEFORE translation/env
	// resolution so box.PodIp and the status.podIP downward-API env carry it. A
	// translate failure below does NOT release it here (an idempotent retry, a
	// later refusal or a DeletePod reclaims it, or the orphan reaper once the object
	// is gone, since Virtual Kubelet may send no DeletePod for such a pod;
	// auto-releasing would also rip a live pod's alias away on an UpdatePod
	// translate error).
	podIP, err := r.podIP(ctx, pod)
	if err != nil {
		// Log here (not just return) so the failure reaches server.log — VK's own
		// create-error log does not, so a pod stuck Pending is otherwise invisible.
		r.log.Error("CreatePod: allocate podIP", "namespace", pod.Namespace, "name", pod.Name, "err", err)
		return fmt.Errorf("create pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	// The interconnect attach (k3sm.io/interconnects) runs once per pod, here
	// at create and before translation, so the box carries its env. Under
	// fallback none, or before this node's desired annotation is known, it holds
	// the create; the slot of a held or refused create is freed with the /32 by
	// releasePodNetwork.
	if err := r.interconnect.attach(ctx, pod); err != nil {
		r.log.Error("CreatePod: interconnect attach", "namespace", pod.Namespace, "name", pod.Name, "err", err)
		return fmt.Errorf("create pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	box, err := r.buildBox(ctx, pod, podIP)
	if err != nil {
		r.log.Error("CreatePod: translate/buildBox", "namespace", pod.Namespace, "name", pod.Name, "err", err)
		r.recordPodHostnameRefusal(pod, err)
		return fmt.Errorf("translate pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	// Refuse a pod this node cannot honestly run BEFORE the RPC, and before any
	// bookkeeping — a pod refused here leaves no track and no prober, exactly as if
	// it had never been created. Each preflight logs and records its own Warning
	// Event; the error comes back already wrapped.
	//
	// The emptyDir-medium and projected-source checks run first because they are
	// pure spec inspection, while the platform check may cost a node-capability RPC.
	if err := r.preflightEmptyDirMedium(pod, box); err != nil {
		return err
	}
	if err := r.preflightProjectedSources(pod); err != nil {
		return err
	}
	if err := r.preflightImagePlatform(ctx, pod, box); err != nil {
		return err
	}
	// A pod that asked for the developer toolchain and got none still runs; say so
	// on the pod, once, at create. Degrade-not-fail, unlike the preflight above.
	r.warnXcodeToolchainUngranted(ctx, pod, box)

	// The GPU memory fit and the slot cap are sized BEFORE the lock, because the
	// node's GPU facts and each held pod's phase cost an RPC and a blocking call
	// inside r.mu would stall every other pod operation on this node. Only the
	// comparison and the insert need to be atomic, and they are.
	//
	// The two asks differ on purpose. wantsGPU is the grant, limits only, and it
	// alone drives the memory fit. gpuUnits is the count, which falls back to
	// requests, and it drives the cap.
	wantsGPU := podRequestsGPU(pod)
	gpuUnits := gpucapacity.PodUnits(pod)
	var gpuCeiling, gpuWant, gpuSlots int64
	var gpuFinished map[string]bool
	if wantsGPU || gpuUnits > 0 {
		gpuFacts, known := r.gpuFacts(ctx)
		gpuCeiling = gpucapacity.GPUCeilingBytes(gpuFacts)
		if known {
			gpuSlots = gpucapacity.GPUSlots(gpuFacts)
		}
		gpuWant = podMemoryLimitBytes(pod)
		gpuFinished = r.finishedGPUPods(ctx)
	}

	r.mu.Lock()
	old := r.track[id]
	_, deleted := r.deleteOwed[id]
	if deleted || (old != nil && old.evictedStatus() != nil) {
		// The pod was refused at admission, evicted or deleted while this create
		// ran. A terminal status is already the apiserver's; a live track here
		// would run a pod the apiserver reports Failed or no longer holds.
		// Admission's in-flight count keeps a refusal from landing between an
		// admitted create's decision and this point, so for a refusal this is the
		// fence behind it, in defence in depth.
		//
		// A refused pod holds nothing, and its delete (forgetRejected) frees
		// nothing, so what this create acquired is released on its way out
		// (createDone), where the last in-flight call of the pod decides under
		// r.mu. An evicted track keeps it: its DeletePod tears it down.
		r.mu.Unlock()
		r.log.Warn("CreatePod: the pod became terminal on this node while it was being created; not creating it",
			"namespace", pod.Namespace, "name", pod.Name, "uid", id, "deleted", deleted)
		return nil
	}
	if wantsGPU {
		// CHECK AND INSERT IN ONE CRITICAL SECTION. Two concurrent GPU creates that
		// each read the admitted total before either wrote its own track would both
		// see room and both be admitted — the node would then run a pair that does
		// not fit, which is exactly the outcome this check exists to prevent.
		//
		// The total is DERIVED from r.track on every call rather than carried in a
		// counter, so a deleted pod releases its share with no bookkeeping of its own
		// and no counter to drift. An idempotent re-create excludes this pod's own
		// old entry (by id), or the pod would be refused for the memory it already
		// holds.
		admitted := r.admittedGPUMemoryLocked(id)
		if err := gpucapacity.GPUFits(gpuCeiling, admitted, gpuWant); err != nil {
			r.mu.Unlock()
			r.log.Error("CreatePod: the pod does not fit in this node's GPU memory beside the pods already admitted",
				"namespace", pod.Namespace, "name", pod.Name,
				"want_bytes", gpuWant, "admitted_bytes", admitted, "ceiling_bytes", gpuCeiling,
				"err", err)
			// One reason, two messages: a pod with no memory limit at all is the
			// same refusal from the operator's side, but the three byte counts
			// would be misleading when the missing number is the pod's own.
			msg := msgFailedGPUFit(gpuWant, admitted, gpuCeiling)
			if errors.Is(err, gpucapacity.ErrGPUMemoryUnbounded) {
				msg = msgFailedGPUUnbounded(gpucapacity.GrantResource(pod), gpuCeiling)
			}
			r.recorder.Event(pod, corev1.EventTypeWarning, reasonFailedGPUFit, msg)
			return fmt.Errorf("create pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	// The cap over both names, in the same critical section, and after the memory
	// fit so a pod that is too big hears about its memory. The scheduler counts
	// each name on its own and a pod with spec.nodeName skips it altogether, so this
	// is the one place the node's real slot count is held. gpuSlots is 0 only when
	// the probe failed, which says nothing about the count: admit, as the fit does.
	if gpuUnits > 0 && gpuSlots > 0 {
		held := r.heldGPUUnitsLocked(id, gpuFinished)
		if err := gpucapacity.GPUSlotsFit(gpuSlots, held, gpuUnits); err != nil {
			r.mu.Unlock()
			r.log.Error("CreatePod: the pod does not fit in this node's GPU slots beside the pods already admitted",
				"namespace", pod.Namespace, "name", pod.Name,
				"want_units", gpuUnits, "held_units", held, "slots", gpuSlots,
				"err", err)
			r.recorder.Event(pod, corev1.EventTypeWarning, reasonFailedGPUFit, msgFailedGPUSlots(gpuUnits, held, gpuSlots))
			return fmt.Errorf("create pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	if old != nil {
		start = old.startTime // idempotent: keep the original start time
	}
	t := &podTrack{pod: pod.DeepCopy(), startTime: start}
	if old != nil {
		// The replay reports the instances the replaced track already recorded
		// Created and Started for; they are not new.
		t.inheritLifecycle(old)
	}
	r.track[id] = t
	r.mu.Unlock()
	if old != nil {
		// The replaced track's pending re-execs must not fire against the new
		// track's bookkeeping (their goroutines would clear nothing and could
		// double-restart a container the fresh CreatePod just spawned), and its
		// in-flight postStart hooks belong to the containers being replaced.
		old.cancelRestarts()
		old.cancelPulls()
		old.cancelPostStart()
	}

	// Announce the attempt before it is made: every container whose image the
	// runtime has to resolve gets the kubelet's Pulling Event, and the window its
	// Pulled Event closes opens here (runtimed_pull.go). A host-binary route gets
	// none — nothing is fetched for it.
	for _, e := range r.notePullDispatch(t, pullableContainers(pod, "")) {
		r.recordPodEvent(id, e)
	}

	resp, err := r.rt.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		// No guest to compensate for: r.rt is the runtime in process, and its one
		// error return comes before it builds (TestCreateRPCHasNoTransportToLoseAGuest).
		r.log.Error("CreatePod: runtimed RPC", "namespace", pod.Namespace, "name", pod.Name, "err", err)
		return fmt.Errorf("runtimed create pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		// A CONTAINER-class image failure failed the WHOLE create, which is the vm
		// spine's shape: one guest per pod, so an image that will not resolve
		// leaves nothing to hold a per-container waiting state. Returning it lands
		// the pod ProviderFailed — terminal — for a condition upstream reports as
		// a retryable ImagePullBackOff, and a controller then churns replacement
		// Pods at whatever is broken. So the pod is PARKED instead: kept tracked,
		// reported Pending with the kubelet's waiting reason, and re-created on
		// the same schedule a started pod's failed pull gets (createFailure).
		if isContainerClassFailure(resp.GetFailureReason()) {
			r.log.Warn("CreatePod: runtimed could not resolve an image; the pod is kept and retried",
				"namespace", pod.Namespace, "name", pod.Name,
				"message", e.GetMessage(), "reason", resp.GetFailureReason().String())
			r.parkCreate(pod, t, resp.GetFailureReason(), e.GetMessage())
			return nil
		}
		r.log.Error("CreatePod: runtimed rejected the pod", "namespace", pod.Namespace, "name", pod.Name,
			"message", e.GetMessage(), "reason", resp.GetFailureReason().String())
		// A pod-level refusal goes back to VK as the create's error; VK records
		// ProviderFailed and retries on its back-off. That retry reaches
		// CreatePod only if this pod is no longer tracked: VK asks GetPod first
		// and takes the UpdatePod path for a pod the provider still lists, and a
		// tracked pod the runtime does not hold answers GetPodStatus with a
		// synthesized ContainerCreating that overwrites the ProviderFailed VK
		// just wrote — a pod stuck creating, never re-created. Runtimed has said
		// it holds nothing, so the track goes the way a preflight refusal's does.
		//
		// On an idempotent re-create (old != nil) the refusal alone does not say
		// whether runtimed holds the pod: its CreatePod validates the box before
		// it looks the pod up, so a refusal can come from validation while the
		// old track's pod is still held, or from creation because it was not. The
		// runtime is asked. A pod it holds keeps its track, since forgetting it
		// would release the /32 and log tree of a pod that is running; a pod it
		// does not hold goes the way a first create's refusal does.
		if old == nil || !r.runtimeHoldsPod(ctx, id) {
			r.untrackRejectedCreate(pod, t)
		}
		return fmt.Errorf("runtimed create pod %s/%s rejected: %s (%s)", pod.Namespace, pod.Name, e.GetMessage(), resp.GetFailureReason().String())
	}
	if r.createBehindDelete(id, t) {
		// runtimed registers a pod only when its create finishes, and its DeletePod
		// answers success for an id it has not registered, so a delete inside this
		// RPC stopped nothing and the guest is running. The delete has the rest of
		// the pod: the release and the track are createDone's.
		r.compensateLateCreate(pod)
		return nil
	}
	r.completeCreate(pod, t, resp.GetStatus())
	return nil
}

// createBehindDelete reports whether a delete of pod id has begun, which is what a
// create that has just landed has to answer: quiesce marks the track before the
// delete's RPC, so unmarked means that RPC is still to come and will reach what the
// create built. A delete that began on a replacement of t marks only the replacement.
// Deleting again when the first delete did reach it is a no-op.
//
// A refusal owed is no delete: the create that landed keeps its guest, and the refusal
// is withdrawn in the same decision.
//
// A delete inside its RPC is read by the UID as well as by the track, because the mark
// can be on no track this create can see: the delete found none, or a refused create
// took the marked one, whereupon GetPod answers NotFound and Virtual Kubelet's requeue
// is another CreatePod. Its queue keeps its own delete of the pod out of a create
// (TestPodControllerRunsOneCallPerPodKey, vkadapter), so what reaches this is the
// orphan reaper's delete, off that queue. A same-name successor is another UID.
func (r *runtimedRuntime) createBehindDelete(id string, t *podTrack) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if del := r.deleteOwed[id]; (del != nil && !del.refusal) || trackDeleting(t) || r.deleteInRPC[id] != 0 {
		return true
	}
	if live := r.track[id]; live != nil && trackDeleting(live) {
		return true
	}
	r.withdrawRefusalLocked(id, t)
	return false
}

// untrackRejectedCreate forgets a pod runtimed refused to create at the pod
// level. It is the CreatePod-side mirror of DeletePod's bookkeeping for a pod
// that never existed in the runtime: the track is removed so VK's retry reaches
// CreatePod again, the goroutines the track could own are cancelled, and the
// pod's /32 and log tree are released.
//
// A track replaced since (a concurrent re-create of the UID) is left alone, with all
// the UID holds: the address, the references and the log tree are keyed by the UID,
// so they are the replacement's now, and its own attempt decides what becomes of them.
// Only this create's workers go.
//
// A delete owed already has the release, and has removed the log tree. So does an
// UpdatePod in flight, which can still acquire by the pod's UID: it reads the refusal
// as a delete owed and stops, and the last call out frees what the pod holds, its log
// tree too, and forgets the track. A claim worker's create can land here beside one,
// since it runs off VK's queue, and another create that lands first withdraws this
// refusal (withdrawRefusalLocked).
//
// Another create in its RPC is not read here, as none can be beside this removal:
// a create in its RPC holds a track GetPod answers with, so Virtual Kubelet's next
// call is UpdatePod, and a parked pod's retry counts as an update
// (TestRefusedRecreateBesideCreateKeepsTheAddress). Still open: a create that begins
// behind this removal and allocates before the release below runs.
func (r *runtimedRuntime) untrackRejectedCreate(pod *corev1.Pod, t *podTrack) {
	id := string(pod.UID)
	r.mu.Lock()
	live := r.track[id]
	replaced := live != nil && live != t
	removed := live == t
	_, owed := r.deleteOwed[id]
	left := owed || r.updating[id] != 0
	switch {
	case replaced || owed:
	case left:
		r.oweRefusalLocked(id, t)
	case removed:
		delete(r.track, id)
	}
	r.mu.Unlock()
	if removed && !left {
		r.refs.UnregisterPod(pod.UID)
	}
	t.cancelRestarts()
	t.cancelPulls()
	t.cancelPostStart()
	if replaced || left {
		return
	}
	r.releasePodNetwork(pod)
	r.removePodLogs(pod)
}

// runtimeHoldsPod reports whether runtimed knows the pod, the question a refused
// re-create leaves open. A transport failure answers true: forgetting a pod the
// runtime may hold is the one irreversible outcome here, and the status sync
// re-asks on its own cadence.
func (r *runtimedRuntime) runtimeHoldsPod(ctx context.Context, id string) bool {
	resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: id})
	if err != nil {
		return true
	}
	e := resp.GetError()
	return e == nil || e.GetCode() == 0
}

// gpuFacts reads this node's GPU facts, reporting false when the probe failed. The
// usable ceiling is 0 on those nil facts, the number the cumulative admission fit
// compares against when it is not known.
//
// It reads the facts off the SAME GetRuntimeInfo RPC every other node fact comes
// from, freshly, rather than caching a copy: the ceiling moves with the host's
// iogpu configuration and with which sandbox backend the daemon selected, and a
// cached value would keep admitting pods against a ceiling the node no longer has.
// The interpretation of the fact fields is gpucapacity's, never re-derived here: the
// node advertiser sizes its slot count with the same functions, and a second reading
// would let the advertised count and the admission check disagree.
//
// A failed probe ADMITS: 0 is the unknown-ceiling sentinel, and refusing every GPU
// pod because one RPC did not answer would turn a transient daemon hiccup into an
// unschedulable node. The pod still faces every other preflight, and runtimed still
// enforces the pod's own memory limit.
func (r *runtimedRuntime) gpuFacts(ctx context.Context) (*runtimev1.GPUFacts, bool) {
	info, err := r.rt.GetRuntimeInfo(ctx, &runtimev1.GetRuntimeInfoRequest{})
	if err != nil {
		r.log.Warn("GPU probe failed; admitting the pod against an unknown ceiling and slot count", "err", err)
		return nil, false
	}
	return info.GetGpu(), true
}

// finishedGPUPods names the tracked pods holding GPU units whose phase is Succeeded
// or Failed. A finished pod stays tracked until its object is deleted, and the
// scheduler released its slot when it ended, so counting it would refuse a pod the
// scheduler rightly bound. It runs OUTSIDE r.mu, since each phase costs an RPC; a
// pod finishing after this read is still counted, which errs toward the refusal.
func (r *runtimedRuntime) finishedGPUPods(ctx context.Context) map[string]bool {
	type gpuTrack struct {
		id string
		t  *podTrack
		p  *corev1.Pod
	}
	var tracks []gpuTrack
	r.mu.Lock()
	for id, t := range r.track {
		if t != nil && t.pod != nil && gpucapacity.PodUnits(t.pod) > 0 {
			tracks = append(tracks, gpuTrack{id: id, t: t, p: t.pod})
		}
	}
	r.mu.Unlock()

	finished := map[string]bool{}
	for _, g := range tracks {
		switch r.podWithStatus(ctx, g.p, g.t).Status.Phase {
		case corev1.PodSucceeded, corev1.PodFailed:
			finished[g.id] = true
		}
	}
	return finished
}

// heldGPUUnitsLocked sums the GPU units of every tracked pod that still holds them,
// under either name, except excludeID. r.mu MUST be held.
//
// Like the memory total it is derived from r.track on every call, so a deleted pod
// releases its share with no counter to drift, and excludeID keeps an idempotent
// re-create from being charged for its own units. A pod refused at admission,
// evicted, or named in finished holds nothing.
func (r *runtimedRuntime) heldGPUUnitsLocked(excludeID string, finished map[string]bool) (held int64) {
	for trackedID, t := range r.track {
		if trackedID == excludeID || t == nil || t.pod == nil || t.rejected || finished[trackedID] || t.evictedStatus() != nil {
			continue
		}
		units := gpucapacity.PodUnits(t.pod)
		if units <= 0 {
			continue
		}
		held = gpucapacity.AddUnits(held, units)
	}
	return held
}

// admittedGPUMemoryLocked sums the memory limits of every tracked GPU pod except
// excludeID, the bytes already committed on this node's GPU. r.mu MUST be held.
//
// excludeID is the pod being admitted: an idempotent re-create of an
// already-tracked pod must not be measured against its own previous entry, or a
// pod that fits perfectly would be refused the second time VK sends it.
//
// Non-GPU pods are not counted. They use the same unified memory, but they are
// budgeted by the node's ordinary memory Allocatable (which already carries the
// control-plane reserve); counting them here would charge them twice and refuse
// GPU pods on account of workloads that never touch the GPU.
//
// A pod whose containers do not all set a memory limit contributes 0
// (podMemoryLimitBytes's "no enforceable ceiling"). That is the honest reading:
// the provider has no number for it, and substituting a guess would refuse pods
// against a total nothing measured.
func (r *runtimedRuntime) admittedGPUMemoryLocked(excludeID string) int64 {
	var sum int64
	for trackedID, t := range r.track {
		// A pod refused at admission holds no GPU memory.
		if trackedID == excludeID || t == nil || t.pod == nil || t.rejected {
			continue
		}
		if !podRequestsGPU(t.pod) {
			continue
		}
		// SATURATING, never wrapping. Limits come off pod specs, which are
		// operator-authored and validated only for shape, so a pathological pair
		// of them can carry the running sum past MaxInt64 — and a wrapped sum is
		// NEGATIVE, which turns every subsequent fit comparison into a pass. That
		// failure is silent and permanent: the check would admit everything on
		// exactly the node whose bookkeeping had overflowed. Saturating fails the
		// other way, refusing, which is the direction a capacity check must fail.
		v := podMemoryLimitBytes(t.pod)
		if v > math.MaxInt64-sum {
			return math.MaxInt64
		}
		sum += v
	}
	return sum
}

// completeCreate performs the wiring a successful create owes, whether it was
// the first attempt or a parked pod's retry: the provider-served probe runner
// (the VK provider replaces the kubelet, so it executes the pod's probes
// itself — a no-op for a probe-free pod and idempotent for a repeated create),
// each container's postStart hook (the container is held NotReady until the hook
// completes, a failure kills it per its restart policy, and the hook's lifetime
// is the pod's; each runs in its own goroutine so no create blocks on one), and
// the immediate status dispatch so VK sees the new state without waiting for the
// stream.
func (r *runtimedRuntime) completeCreate(pod *corev1.Pod, t *podTrack, rs *runtimev1.PodStatus) {
	// The flat /var/log/containers symlinks, now that the containers have started
	// and their log files exist. Best effort — see linkContainerLogs.
	r.linkContainerLogs(pod, rs)
	r.startProber(pod, rs.GetPodIp())
	r.runPostStart(t, pod, rs.GetPodIp())
	r.dispatch(string(pod.UID), rs)
}

// UpdatePod forwards labels/annotations changes and appended ephemeral
// containers (the only changes runtimed applies in place); other changes need a
// recreate and are reported by the runtime as a typed precondition failure,
// surfaced here as an error. A refused ephemeral append is the exception: it is
// reported on the debug container, never as the pod's failure. A changed image on
// a pod the runtime holds is not refused and not applied: runtimed answers OK and
// the container stays on its image. A vm pod reports that as a Warning Event
// (imageEditsNotApplied), and a native pod does not report it.
//
// A pod refused at admission or evicted is terminal and gets no update, as it
// gets no create: nothing is registered, allocated or sent to the runtime. That
// holds for a terminal track and, with no track, for a pod whose apiserver
// object is terminal (CreatePod's fence), which a restarted node no longer
// tracks.
//
// Virtual Kubelet orders calls per pod, and this does not depend on it. An update
// overlapping an admission waits for the verdict (awaitUpdateVerdictLocked); a
// refusal landing behind one past its check is judged again before the runtime
// call, and what the update took is released when it returns (updateDone). So is
// a delete landing behind one: the update stops, and the last call out finishes
// the delete (teardownPod, claimFenceReleaseLocked).
func (r *runtimedRuntime) UpdatePod(ctx context.Context, pod *corev1.Pod) error {
	// Identity binding kept for the SAME in-process seam CreatePod uses, but
	// UpdatePod itself never mints a token or re-reads a ConfigMap/Secret
	// through it: runtimed's UpdatePod applies labels/annotations only (its
	// updatableOnly check refuses a change of identity or container count as
	// NOT_UPDATABLE, and answers OK to a changed image without applying it;
	// pinned there by TestUpdatePodNeverMaterializes in pkg/runtime) and never
	// materializes. Projected data is re-resolved on a separate path: the
	// provider's 60 s refresh loop (projectedrefresh.go) calls the runtime's
	// RefreshProjectedVolumes for every running native pod, which re-renders
	// configMap / secret / downwardAPI / projected volumes with an atomic ..data
	// flip and re-mints a projected ServiceAccount token under 20% of its
	// lifetime, binding the pod identity on its own context. The binding here
	// stays because env-source resolution in buildBox (resolvePodBoxEnv →
	// ConfigMap/Secret key refs) legitimately re-runs on every box build, and
	// this seam is kept uniform for CreatePod and UpdatePod rather than split.
	ctx = withPodIdentity(ctx, pod)
	id := string(pod.UID)
	// Counted before the wait, so a delete landing during it leaves the release
	// to this update, which would otherwise wake to an untracked pod and allocate.
	r.beginUpdate(id)
	// updateDone takes r.mu, so this defer has to run with r.mu released, a panic
	// included: checkUpdate holds the lock only inside its own frame.
	defer r.updateDone(pod)
	t, previous, proceed, err := r.checkUpdate(ctx, pod)
	if err != nil {
		return fmt.Errorf("update pod %s/%s: wait for the admission verdict: %w", pod.Namespace, pod.Name, err)
	}
	if !proceed {
		return nil
	}
	tracked := t != nil
	guestHeld := false
	if hook := r.updateCheckedHook; hook != nil {
		hook(id)
	}
	// A refusal or a delete that landed since the check holds: nothing more is
	// acquired, and updateDone releases what this update took.
	if r.updateStoppedNow(id) {
		return nil
	}
	if tracked {
		// A container whose image reference changed is a different pull: retire
		// the old reference's schedule and attempt the new one now. This is the
		// only recovery an InvalidImageName container has (runtimed_pull.go). A
		// guest the runtime holds has no such recovery to run: it pulls nothing for
		// the edit, and the attempt would only record a Pulling and a Pulled for
		// an image that was not fetched.
		guestHeld = guestHoldsImages(t, pod)
		if !guestHeld {
			r.retryPullsForChangedImages(t, previous, pod)
		}
		if t.claimWaiting() {
			// A pod held for its claims has nothing in the runtime to update,
			// exactly as a parked one: the replaced spec above is the update,
			// and the held create builds the pod from it.
			return nil
		}
		if t.parkedFailure() != nil {
			// A parked pod exists on the provider side only: runtimed refused its
			// create, so there is no guest to update in place and the RPC would be
			// a guaranteed NotFound returned to virtual-kubelet. Replacing the
			// tracked spec above IS the update, and the re-key just pointed the
			// schedule at whatever image the new spec names; the next retry builds
			// the pod from it. This is what makes `kubectl set image` the recovery
			// an InvalidImageName pod actually has.
			return nil
		}
	}

	// Same allocate-before-translate ordering as CreatePod; Setup is idempotent
	// per podID, so an update re-reads the pod's existing /32 (one authority).
	podIP, err := r.podIP(ctx, pod)
	if err != nil {
		return fmt.Errorf("update pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	box, err := r.buildBox(ctx, pod, podIP)
	if err != nil {
		return fmt.Errorf("translate pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	// Judged again, as the allocation and the translation can take a while. One
	// landing after this read costs an RPC runtimed answers NotFound; the release
	// still runs.
	if r.updateStoppedNow(id) {
		return nil
	}
	resp, err := r.rt.UpdatePod(ctx, &runtimev1.UpdatePodRequest{Pod: box})
	if err != nil {
		return fmt.Errorf("runtimed update pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		// A refusal of an update that only APPENDED ephemeral containers is the
		// debug container's failure, not the pod's. Returning it would let
		// virtual-kubelet mark the running pod ProviderFailed, and Failed outright
		// under restartPolicy: Never. The refusal is reported on the container
		// instead: the status reads ContainerCreating for it (ephemeral.go) and
		// the Event carries runtimed's own text.
		//
		// UNSUPPORTED on a pod that lists ephemeral containers is the backstop
		// for the same case: runtimed answers it only for an ephemeral append it
		// cannot start, which the provider no longer sends for a vm pod. Any
		// other UNSUPPORTED is returned as before.
		ephemeralUnsupported := resp.GetFailureReason() == runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED &&
			len(pod.Spec.EphemeralContainers) > 0
		if !ephemeralOnlyDelta(previous, pod) && !ephemeralUnsupported {
			return fmt.Errorf("runtimed update pod %s/%s: %s", pod.Namespace, pod.Name, e.GetMessage())
		}
		r.log.Warn("UpdatePod: runtimed refused the ephemeral container append; reported on the container",
			"namespace", pod.Namespace, "name", pod.Name,
			"message", e.GetMessage(), "reason", resp.GetFailureReason().String())
		r.recordEphemeralRejections(previous, pod, e.GetMessage())
		r.dispatchCurrent(ctx, id)
		return nil
	}
	r.recordEphemeralRejections(previous, pod, "")
	if guestHeld {
		for _, e := range imageEditsNotApplied(previous, pod, resp.GetStatus()) {
			r.recorder.Event(pod, e.eventtype, e.reason, e.message)
		}
	}
	r.dispatch(id, resp.GetStatus())
	return nil
}

// guestHoldsImages reports whether pod is a vm pod the runtime holds a guest for,
// so one whose containers cannot change image: not one parked or waiting on its
// claims, whose next create is built from the edited spec.
func guestHoldsImages(t *podTrack, pod *corev1.Pod) bool {
	backend, err := podSandboxBackend(pod)
	return err == nil && backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM &&
		t.parkedFailure() == nil && !t.claimWaiting()
}

// imageEditsNotApplied returns one Warning per container this update moved to an
// image other than the one it stays on. The old image is read from the runtime's
// status and not from previous, so a second edit names what runs rather than what
// the first edit asked for, and an edit back to what runs warns about nothing. A
// container the status does not report yet is on the image it was last given.
//
// The edit is reported and not refused: an error here is what virtual-kubelet
// turns into a ProviderFailed pod, Failed outright under restartPolicy Never, for
// a pod that is running fine. The tracked spec keeps the edit, as virtual-kubelet
// would otherwise send it again on every sync.
func imageEditsNotApplied(previous, pod *corev1.Pod, rs *runtimev1.PodStatus) []podEvent {
	was := imagesByContainer(previous)
	running := make(map[string]string, len(was))
	for _, css := range [][]*runtimev1.ContainerStatus{rs.GetInitContainerStatuses(), rs.GetContainerStatuses()} {
		for _, cs := range css {
			running[cs.GetName()] = cs.GetImage()
		}
	}
	var out []podEvent
	for _, cs := range [][]corev1.Container{pod.Spec.InitContainers, pod.Spec.Containers} {
		for i := range cs {
			c := &cs[i]
			old, known := was[c.Name]
			if !known || old == c.Image {
				continue
			}
			runs := running[c.Name]
			if runs == "" {
				runs = old
			}
			if runs != c.Image {
				out = append(out, podEvent{corev1.EventTypeWarning, reasonImageEditNotApplied,
					msgImageEditNotApplied(c.Name, runs, c.Image)})
			}
		}
	}
	return out
}

// beginUpdate counts one UpdatePod in flight for pod id; updateDone ends the count.
func (r *runtimedRuntime) beginUpdate(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.beginUpdateLocked(id)
}

// beginUpdateLocked is beginUpdate for a caller holding r.mu.
func (r *runtimedRuntime) beginUpdateLocked(id string) {
	if r.updating == nil {
		r.updating = map[string]int{}
	}
	r.updating[id]++
}

// checkUpdate is the part of UpdatePod under r.mu: it waits for the admission
// verdict, judges whether the pod takes an update, and if so registers its
// references and replaces the tracked spec. It reports the pod's track (nil when
// untracked), the spec it replaced, and whether the update goes on. A panic here
// unlocks on its way out, so it reaches UpdatePod's caller.
func (r *runtimedRuntime) checkUpdate(ctx context.Context, pod *corev1.Pod) (t *podTrack, previous *corev1.Pod, proceed bool, err error) {
	id := string(pod.UID)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.awaitUpdateVerdictLocked(ctx, pod); err != nil {
		return nil, nil, false, err
	}
	t, tracked := r.track[id]
	// A pod whose delete has begun gets no update either: anything acquired behind
	// the delete's release has no owner. With no track, the deletion stamp and the
	// tombstone are the only signs an update that arrives after the delete has of it.
	terminal := isEvictedPod(pod) || isBudgetRejectedPod(pod) || pod.DeletionTimestamp != nil ||
		r.tombstones.has(id)
	if tracked {
		terminal = t.rejected || t.evictedStatus() != nil || trackDeleting(t)
	}
	if _, deleted := r.deleteOwed[id]; deleted {
		terminal = true
	}
	if terminal {
		// Virtual Kubelet reaches here when a refused or evicted pod's labels,
		// annotations, images or tolerations change. A refused pod holds nothing
		// and its delete (forgetRejected) frees nothing, so anything acquired
		// below would stay held until the daemon restarts; runtimed has already
		// forgotten an evicted pod, so the RPC could only fail. The tracked spec
		// stays too: an eviction whose teardown fails is rolled back, and the
		// difference brings the update back for the pod that is still running.
		return nil, nil, false, nil
	}
	// A spec change (an ephemeral container added) can add references; the
	// registration is replaced, so a removed reference stops being fetchable.
	r.noteHeldLocked(pod)
	r.refs.RegisterPod(pod)
	if tracked {
		previous = t.pod
		t.pod = pod.DeepCopy()
	}
	return t, previous, true, nil
}

// dispatchCurrent reads the pod's current status from the runtime and publishes
// it, for a mutating call whose refusal carried no status of its own. A failed
// read publishes nothing; the watch stream and the backstop still converge.
func (r *runtimedRuntime) dispatchCurrent(ctx context.Context, id string) {
	resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: id})
	if err != nil || (resp.GetError() != nil && resp.GetError().GetCode() != 0) {
		return
	}
	r.dispatch(id, resp.GetStatus())
}

// DeletePod runs the pod's preStop hooks, then stops the pod's processes and
// forgets the bookkeeping. Idempotent. The SIGTERM→SIGKILL grace window is the pod's
// termination budget (deletion/termination grace, k8s 30s default) MINUS the preStop
// wall-time, floored at minimumGracePeriodSeconds (2s) the way the kubelet floors
// it, since in the apis contract a 0 grace is an immediate kill.
func (r *runtimedRuntime) DeletePod(ctx context.Context, pod *corev1.Pod) error {
	id := string(pod.UID)
	r.forgetRetained(id)
	// Cancel every in-flight provider worker FIRST, BEFORE the RPC. A postStart
	// hook must not outlive the pod and termination must not wait on one —
	// upstream tears the pod worker's context down on delete, which aborts a
	// running hook — and the same is true of the two retry authorities: a pending
	// re-exec or pull re-attempt that fires while runtimed is tearing the pod
	// down is a StartContainer against a pod being deleted. runtimed refuses that
	// with a typed precondition failure, but the window is closed from BOTH sides
	// rather than either leaning on the other.
	t := r.trackByID(id)
	if t != nil {
		t.quiesce()
		// quiesce waited out a held pod's create worker, which may have
		// installed the pod's real track meanwhile; that one is quiesced too,
		// so nothing the create started outlives the delete.
		if live := r.trackByID(id); live != nil && live != t {
			live.quiesce()
			t = live
		}
	}
	// A pod refused at admission never reached the runtime: forget it.
	if t != nil && t.rejected {
		r.forgetRejected(ctx, pod, t)
		return nil
	}
	// An evicted pod's processes are already gone (evictPod stopped them), so
	// there is nothing for a preStop hook to run in: finish the teardown it left
	// for this call (the /32, the log tree, the track, the apiserver object).
	// The grace is the floor, not 0: runtimed already forgot the pod, and wire 0
	// is reserved for evictPod's immediate kill.
	if t != nil && t.evictedStatus() != nil {
		return r.teardownPod(ctx, pod, minimumGracePeriodSeconds, nil)
	}
	// The kubelet's killContainer records Killing for each container it stops
	// before the preStop hook and the stop itself: one per container last
	// observed running, none for one that already exited.
	if t != nil {
		for _, name := range t.runningContainersToKill(pod) {
			recordContainerEvent(r.recorder, pod, killingEvent(name, ""))
		}
	}
	// Serve preStop hooks BEFORE termination: runtimed sends SIGTERM
	// synchronously inside DeletePod, so the provider runs preStop first and passes
	// the RESIDUAL grace (the budget minus the hook's wall-time, floored at
	// minimumGracePeriodSeconds, 2s).
	// best-effort — a failed hook is logged inside runPreStop, the delete proceeds.
	//
	// A vm pod's probes end first, so a hook that starts draining cannot fail them.
	// Its override freezes with them: an httpGet hook dials the published address, and
	// only the relay answers there.
	r.stopVMProbes(pod)
	r.transport.beginStop(id)
	grace := r.runPreStop(ctx, pod)
	return r.teardownPod(ctx, pod, grace, nil)
}

// evictPod is the node-pressure eviction manager's termination path (the
// evictionTarget half the manager calls). It is NOT DeletePod: the kubelet
// leaves an evicted pod in the apiserver for its controller and the pod GC to
// handle, so evictPod stops the pod's processes and records the eviction, and
// leaves the rest of the teardown (the pod's /32, its log tree, its track, the
// apiserver object) to the DeletePod that follows when the pod is deleted.
//
// In order:
//
//  1. Mark the track evicted, with the full terminal status, BEFORE anything is
//     stopped, so every status built from here on (stream, backstop, direct
//     reads) reports the eviction and the restart engine never observes the
//     teardown's exits as crashes. A second eviction of the same pod is a no-op.
//  2. Emit the pod's Warning Evicted Event (the kubelet records it before the
//     kill).
//  3. Quiesce the track (cancel pending re-execs, pulls, postStart), so no
//     restart can bring an evicted restartPolicy: Always container back.
//  4. DeletePod by pod id with grace 0 and no preStop. If it FAILS, the
//     eviction is rolled back: the evicted mark is removed (the processes are
//     still running, so the pod reports its live status and stays a
//     candidate), and the error is returned; the manager does not count it.
//  5. Stop the prober and drop the pod's transport override (a stopped guest's
//     lease must not keep routing).
//  6. Persist the status to the apiserver (synchronously, UID-checked, retried
//     with a bounded backoff) and push it through the watch callback.
//
// GRACE. Upstream's hard eviction passes gracePeriodOverride 0, and killContainer
// (pkg/kubelet/kuberuntime/kuberuntime_container.go, v1.36.2) then skips the
// preStop hook (it runs only when the grace budget is above 0) and floors the
// grace it hands the runtime at minimumGracePeriodInSeconds (2 s): upstream sends
// SIGTERM and SIGKILLs two seconds later. k3sm sends grace 0, the apis
// contract's immediate kill (DeletePodRequest.grace_period_seconds: 0 means
// immediate SIGKILL). evictPod is the only sender of 0: every other DeletePod
// floors its grace at minimumGracePeriodSeconds (floorGrace). The skipped
// preStop matches upstream; the missing 2 s SIGTERM window is a deliberate k3sm
// divergence: the pod is
// evicted because the node is about to run out of memory, and two more seconds
// of an incompressible fill on a Mac can carry the compressor from the trip
// value to the kernel's own kill point.
//
// NO PID IS EVER SIGNALLED HERE. The only kill is runtimed's DeletePod, keyed by
// pod id. runtimed signals only the process groups of containers it has not
// observed terminate (liveContainersLocked), and a container's leader is reaped
// before its state reads terminated, so a group the kernel already killed (and
// whose pgid number could be recycled) is not signalled.
func (r *runtimedRuntime) evictPod(ctx context.Context, pod *corev1.Pod, n evictionNotice) error {
	id := string(pod.UID)
	t := r.trackByID(id)
	if t == nil {
		return fmt.Errorf("evict pod %s/%s: not tracked on this node", pod.Namespace, pod.Name)
	}
	r.mu.Lock()
	tracked := t.pod
	r.mu.Unlock()
	prior := r.podWithStatus(ctx, tracked, t)
	st := evictedPodStatus(prior.Status, n.message, metav1.Now())
	if !t.markEvicted(st) {
		return nil
	}
	r.recorder.Event(tracked, corev1.EventTypeWarning, reasonEvicted, n.message)

	t.quiesceForEviction()
	// The intent write is time-boxed: a stalled disk must not hold back the
	// kill that keeps the node from running out of memory.
	intent := r.recordStopIntentWithin(tracked, "", budgetIntentWriteBound)
	if _, err := r.rt.DeletePod(ctx, &runtimev1.DeletePodRequest{PodId: id, GracePeriodSeconds: 0}); err != nil {
		// Only a definitive refusal proves the kill did not happen; after a
		// deadline or a lost transport it may have, so the intent stays.
		if stopNotIssued(err) {
			r.history.dropIntent(intent)
		}
		t.unmarkEvicted(st)
		return fmt.Errorf("runtimed delete pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	r.recordBudgetEvent(tracked, budgetv1alpha1.CounterEviction)
	r.stopProber(id)
	r.transport.drop(id)

	if err := r.persistEvictedStatus(ctx, tracked, st); err != nil {
		r.log.Error("eviction: could not persist the evicted status to the apiserver",
			"pod", podKey(pod.Namespace, pod.Name), "err", err)
	}
	if cb := r.callback(); cb != nil {
		out := tracked.DeepCopy()
		out.Status = *st.DeepCopy()
		cb(out)
	}
	return nil
}

// quiesce closes t to a late create and cancels every in-flight provider worker
// it owns — the step both teardown entries (DeletePod and the orphan reaper)
// take BEFORE the runtime RPC.
func (t *podTrack) quiesce() {
	// Close the track to a late create BEFORE cancelling anything. A parked
	// pod's retry may already be inside its CreatePod RPC, and cancelling its
	// context does not un-build a guest the runtime has accepted; marking
	// first is what makes "the delete won" decidable by the create rather
	// than by whichever goroutine happens to run next. The create then
	// compensates itself (retryParkedCreate).
	t.markDeleting()
	// A held pod's claim worker is stopped and WAITED for: a create it already
	// began must land before the delete's own RPC, or the runtime could build
	// the pod after the delete removed it.
	t.stopClaimWait()
	t.cancelPostStart()
	t.cancelRestarts()
	t.cancelPulls()
}

// teardownPod is the delete path after preStop: a vm pod's probes, the runtime RPC
// with grace, the pod's transport override, the remaining probe runner, the pod's /32
// (see releasePodNetwork), its log tree, the track, and the apiserver object.
// DeletePod and the orphan reaper (orphanreap.go) share it, so a reaped pod is torn
// down exactly as a deleted one is.
//
// THE OVERRIDE IS FROZEN UNTIL THE RPC ANSWERS. It keeps the relay up, so connections
// drain and new dials land while the guest works through its grace, as a terminating
// pod serves until its process exits. Its answer decides what follows:
//   - success: the guest is gone, so the override drops, once. The release mark goes
//     on with the drop, because the runtime's DELETED event still carries the lease,
//     and the lease can go to another guest. It holds until releasePodNetwork clears
//     it, which on the in-flight branch below is the last call out.
//   - a definitive refusal: the guest is still serving, so the override stays and
//     observation resumes.
//   - any other failure: the stop may have happened. The override stays, since the
//     failure alone does not show the guest stopped, and the mark goes on, so nothing
//     installs a lease that may have no guest behind it. A report that the runtime no
//     longer holds the pod drops it. The caller retries, as the track is still
//     installed.
//
// owned selects how the track is forgotten. nil forgets whatever track the pod
// id holds (DeletePod's contract). Non-nil forgets the track only if it is still
// owned — identity, not presence, as untrackRejectedCreate does — so a track an
// idempotent re-create installed meanwhile is left alone.
//
// With a create or an UpdatePod in flight the pod is stopped and removed from the
// apiserver here, and the release and the track delete wait for the last call out,
// as it can still acquire by the pod's UID (claimFenceReleaseLocked). Virtual Kubelet
// runs one call per pod, so what reaches this overlap is the orphan reaper and a held
// pod's claim worker. An update stops at its next check, and a create at its fence,
// since owing the delete is what they read.
func (r *runtimedRuntime) teardownPod(ctx context.Context, pod *corev1.Pod, grace int64, owned *podTrack) error {
	id := string(pod.UID)
	r.stopVMProbes(pod)
	r.transport.beginStop(id)
	intent := r.recordStopIntent(pod, "")
	t := r.trackByID(id)
	t.beginRuntimeStop()
	r.mu.Lock()
	r.beginDeleteRPCLocked(id)
	r.mu.Unlock()
	_, err := r.rt.DeletePod(ctx, &runtimev1.DeletePodRequest{PodId: id, GracePeriodSeconds: grace})
	t.endRuntimeStop(err)
	if err != nil {
		r.mu.Lock()
		r.endDeleteRPCLocked(id)
		r.mu.Unlock()
		// Only a definitive refusal proves the stop did not happen.
		if stopNotIssued(err) {
			r.history.dropIntent(intent)
			r.transport.stopRefused(id)
		} else {
			r.transport.stopUncertain(id)
		}
		return fmt.Errorf("runtimed delete pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	r.transport.stopSucceeded(id)
	// Stop the probe runner before forgetting the pod (stopProber waits for the
	// loops outside the lock, so no probe goroutine outlives the pod).
	r.stopProber(id)
	r.mu.Lock()
	// In one section with the tombstone: a create landing from here on is either
	// counted, so the delete is owed and it reads that, or stale.
	r.endDeleteRPCLocked(id)
	r.tombstones.add(id)
	r.tornDown.add(id)
	if r.inFlightLocked(id) {
		r.oweDeleteLocked(id, owned)
		r.mu.Unlock()
		r.removePodLogs(pod)
		r.forceDeleteFromAPI(ctx, pod)
		return nil
	}
	r.mu.Unlock()
	// Release the pod's /32 (log-and-continue; idempotent after runtimed's own
	// delete-path teardown) so pod churn never leaks a node pool address. The override
	// went down with the stop's success, which closed the pod's relay before the alias it listens on
	// goes (see releasePodNetwork's doc). An override that outlives its guest points
	// at a lease macOS is free to hand to the NEXT guest — a cross-pod misdelivery,
	// not a failed dial (see transportFeed).
	r.releasePodNetwork(pod)
	// Remove the pod's log tree, now that runtimed has confirmed every container
	// is gone (the RPC above is synchronous). Deleting it while a container still
	// held the file open would strand the output on an unlinked inode, which is
	// the one way this node can lose logs without saying so.
	r.removePodLogs(pod)
	r.forgetTorndown(pod, owned)
	// Force-delete the pod from the apiserver now that runtimed has torn its
	// containers down (r.rt.DeletePod is synchronous). Virtual Kubelet would
	// otherwise leave a running-then-deleted pod in the API for the FULL
	// deletionGracePeriodSeconds — see the r.client field doc for why its prompt
	// path is unreachable via status. grace 0 = immediate; best-effort and
	// NotFound-tolerant (VK may have force-deleted it first; either order is fine).
	r.forceDeleteFromAPI(ctx, pod)
	return nil
}

// beginDeleteRPCLocked counts a teardown of pod id entering the runtime's DeletePod.
// The caller holds r.mu.
func (r *runtimedRuntime) beginDeleteRPCLocked(id string) {
	if r.deleteInRPC == nil {
		r.deleteInRPC = map[string]int{}
	}
	r.deleteInRPC[id]++
}

// endDeleteRPCLocked ends that count. The caller holds r.mu.
func (r *runtimedRuntime) endDeleteRPCLocked(id string) {
	if r.deleteInRPC[id] <= 1 {
		delete(r.deleteInRPC, id)
		return
	}
	r.deleteInRPC[id]--
}

// forgetTorndown is the end of a teardown: the track goes (owned selects which, as
// in teardownPod) with the references, and the track's workers are cancelled again.
func (r *runtimedRuntime) forgetTorndown(pod *corev1.Pod, owned *podTrack) {
	id := string(pod.UID)
	r.mu.Lock()
	t := r.track[id]
	forget := false
	switch {
	case owned == nil, t == owned:
		delete(r.track, id)
		forget = true
	default:
		// A track replaced since the reaper claimed its own is someone
		// else's to forget (see owned above).
		t = nil
	}
	r.mu.Unlock()
	if forget {
		// runtimed has torn the pod down, so nothing reads for it again.
		r.refs.UnregisterPod(pod.UID)
	}
	if t != nil {
		// Again, now that the track is unreachable: a status observation landing
		// while the RPC was in flight can file a fresh re-exec or re-attempt, and
		// nothing else would ever cancel it. No restart goroutine may outlive the
		// pod, and a deleted pod must never be re-spawned; a StartContainer
		// against a pod runtimed has already torn down is at best a NotFound and
		// at worst a resurrection.
		t.cancelRestarts()
		t.cancelPulls()
	}
}

// forceDeleteFromAPI removes pod from the apiserver with grace 0 so a
// terminated-then-deleted pod disappears promptly instead of lingering the whole
// deletionGracePeriodSeconds under VK's delayed-delete fallback. Best-effort: a nil
// client (unit tests) or a NotFound (already gone) is a no-op; any other error is
// logged and swallowed so the delete path never blocks on the API.
//
// The delete is pinned to this pod's UID, as the kubelet's is: a pod name is
// reused the moment its predecessor is gone, and Virtual Kubelet can drive
// DeletePod for the predecessor after that moment, so an unpinned delete took
// the replacement. A 409 for another UID is swallowed like NotFound: the pod
// that is there is not the one being removed.
func (r *runtimedRuntime) forceDeleteFromAPI(ctx context.Context, pod *corev1.Pod) {
	if r.client == nil {
		return
	}
	zero := int64(0)
	err := r.client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{
		GracePeriodSeconds: &zero,
		Preconditions:      metav1.NewUIDPreconditions(string(pod.UID)),
	})
	if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		r.log.Warn("force-delete pod from apiserver after teardown",
			"namespace", pod.Namespace, "name", pod.Name, "err", err)
	}
}

// GetPodStatus returns the named pod's status, NotFound if it is unknown.
func (r *runtimedRuntime) GetPodStatus(ctx context.Context, namespace, name string) (*corev1.PodStatus, error) {
	id, _, pod, ok := r.lookup(namespace, name)
	if !ok {
		return nil, vkadapter.NotFoundf("pod %q not found", namespace+"/"+name)
	}
	// An evicted pod reports its eviction without asking the runtime, which has
	// already forgotten it.
	if t := r.trackByID(id); t != nil {
		if st := t.evictedStatus(); st != nil {
			return st, nil
		}
	}
	resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: id})
	if err != nil {
		return nil, fmt.Errorf("runtimed get pod status %s/%s: %w", namespace, name, err)
	}
	t := r.trackByID(id)
	if t == nil {
		return nil, vkadapter.NotFoundf("pod %q not found", namespace+"/"+name)
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		// The provider tracks this pod but the runtime does not know it: either the
		// CreatePod RPC is still in flight (the track is installed before the
		// call), or the create was refused for an image failure and the pod is
		// parked. NotFound here would report a pod being created — or waiting on
		// a registry — as a pod that does not exist, which VK surfaces as a
		// disappearing Pod; the truthful answer is the kubelet's own surface,
		// every container Waiting with ContainerCreating or with the refusal's
		// reason. NotFound stays for a pod the PROVIDER does not track — the one
		// case where nothing is being created.
		st := r.buildStatus(pod.DeepCopy(), t, r.synthesizedStatus(pod, t), r.proberFor(id))
		return &st, nil
	}
	st := r.buildStatus(pod.DeepCopy(), t, resp.GetStatus(), r.proberFor(id))
	return &st, nil
}

// GetPods returns every tracked pod with its current status applied.
func (r *runtimedRuntime) GetPods(ctx context.Context) ([]*corev1.Pod, error) {
	// The pod POINTER is snapshotted inside the critical section, not just the
	// track. r.mu guards the t.pod field itself — UpdatePod reassigns it
	// under this same lock — so reading t.pod out in the loop below was a
	// data race, reported by -race against the 10s backstop's GetPods running
	// concurrently with a VK pod worker's UpdatePod. It is the one mutable field
	// of podTrack that r.mu guards: readyMu, restartMu and hookMu exist
	// precisely because the status reconstruction below runs OUTSIDE r.mu, and
	// startTime is write-once.
	//
	// Only the pointer is taken here. The DeepCopy stays outside the lock, where
	// it belongs — it is the expensive part, it is per-pod, and the pointee is
	// never mutated after publication, so a snapshotted pointer is safe to copy
	// at leisure.
	r.mu.Lock()
	tracks := make([]*podTrack, 0, len(r.track))
	pods := make([]*corev1.Pod, 0, len(r.track))
	for _, t := range r.track {
		tracks = append(tracks, t)
		pods = append(pods, t.pod)
	}
	r.mu.Unlock()

	out := make([]*corev1.Pod, 0, len(tracks))
	for i, t := range tracks {
		out = append(out, r.podWithStatus(ctx, pods[i], t))
	}
	return out, nil
}

// podWithStatus returns a DeepCopy of tracked (t's pod pointer, snapshotted by
// the caller under r.mu) carrying its reconstructed status. It runs OUTSIDE r.mu.
func (r *runtimedRuntime) podWithStatus(ctx context.Context, tracked *corev1.Pod, t *podTrack) *corev1.Pod {
	pod := tracked.DeepCopy()
	if st := t.evictedStatus(); st != nil {
		pod.Status = *st
		return pod
	}
	resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: string(pod.UID)})
	switch {
	case err != nil:
		// A transport failure says nothing about the pod; leave the status it
		// already carries rather than replacing it with a guess.
	case resp.GetError() != nil && resp.GetError().GetCode() != 0:
		// The same synthesis GetPodStatus does for a pod the runtime does not
		// know — the create window, or a parked create. Leaving the status
		// empty here would publish a phase-less Pod on every backstop tick for
		// a pod that is legitimately waiting.
		pod.Status = r.buildStatus(pod, t, r.synthesizedStatus(pod, t), r.proberFor(string(pod.UID)))
	default:
		pod.Status = r.buildStatus(pod, t, resp.GetStatus(), r.proberFor(string(pod.UID)))
	}
	return pod
}

// buildStatus reconstructs the pod's corev1 status via toPodStatus, threading the
// track's last computed PodReady so PodReady.LastTransitionTime flips ONLY on a real
// status change — not every resync tick.
//
// pod here is a DeepCopy of t.pod, the IMMUTABLE desired-spec object (CreatePod /
// UpdatePod replace the pointer, and it never carries the computed PodReady). Without
// this seed, readyTransitionTime would never find a prior PodReady on the runtimed
// path and would reset LastTransitionTime to Now() on every backstop/watch tick —
// churning pod status (a kine write per resync per pod) and, worse, resetting the
// minReadySeconds availability window every ~10s so a Deployment never marks the pod
// available: a rolling-update stall. The HostProcess
// path is exempt (it persists computed status back onto rec.pod, a stable prior).
//
// Locking: t.readyMu guards lastReady because GetPods reconstructs status OUTSIDE
// r.mu (it snapshots tracks under the lock, then builds each unlocked), so concurrent
// GetPods/emit for the same track must not race on lastReady. The lock is held ONLY
// around the lastReady read and write — never across toPodStatus or the prober.
//
// buildStatus is also the restart-bookkeeping convergence point: every runtime status
// observation (stream emit, backstop GetPods, direct GetPodStatus, probe-driven
// publish) flows through here, so observeExits sees each container termination
// regardless of which path delivered it (idempotent per termination), and
// applyRestartOverlay renders the CrashLoopBackOff surface + Running phase hold
// on every published status while a re-exec is pending. The postStart readiness
// gate rides the same convergence, so no publish path can leak a Ready container
// whose postStart hook has not completed.
func (r *runtimedRuntime) buildStatus(pod *corev1.Pod, t *podTrack, rs *runtimev1.PodStatus, ps probeState) corev1.PodStatus {
	// FIRST, before any observation: an evicted pod's status is final, and its
	// teardown's exits must reach neither the restart engine nor the overlays.
	if st := t.evictedStatus(); st != nil {
		return *st
	}
	r.observeExits(pod, t, rs)
	// The prober follows container instances on the same convergence, so a
	// liveness restart's hold lifts only once the replacement is observed.
	observeProbeInstances(ps, rs)
	// The pull-failure twin of observeExits: a container runtimed could not start
	// gets (or keeps) its retry schedule on the same convergence, so every status
	// path — stream, backstop, direct GetPodStatus — paces the retries identically.
	r.observePulls(pod, t, rs)
	// The container lifecycle Events (Created, Started, and a host binary's
	// Pulled), once per container instance. After observePulls, so a fetched
	// image's Pulled precedes the Created it led to.
	r.observeLifecycle(pod, t, rs)
	// Feed the Service proxy this pod's live transport address, on the
	// same convergence the exit observation rides. It reads the status and the
	// node's own guest record; it contributes NOTHING to the corev1 status being
	// built, because the live address must never reach status.podIP, the
	// EndpointSlice or DNS (see observeTransport).
	r.observeTransport(pod, rs)
	// A restricted main process lost the pod shim; runtimed says so with the
	// k3sm.io/shim-inactive condition and the node turns it into one Warning
	// Event per pod per reason, on whichever status path delivers it first.
	r.observeShimInactive(pod, t, rs)
	// AFTER the observation above, never before: the gate is a read of the very
	// lease map that call just updated, so PodReady reflects THIS status rather
	// than trailing it by one. A vm pod whose override is not installed is
	// undialable at the address its EndpointSlice carries, so its POD-LEVEL
	// PodReady is withheld (its ContainersReady and container Ready flags are
	// untouched — see transportGate).
	transport := r.transportGateFor(pod)
	t.readyMu.Lock()
	prior := t.lastReady
	priorToStart := t.lastReadyToStart
	t.readyMu.Unlock()
	if prior.Type == corev1.PodReady {
		// Seed the desired-spec copy's conditions with the last PodReady so
		// readyTransitionTime finds its prior status+LTT. PodReady is provider-owned,
		// so toPodStatus's carry-forward excludes it — no duplication.
		pod.Status.Conditions = append(pod.Status.Conditions, prior)
	}
	if priorToStart.Type == corev1.PodReadyToStartContainers {
		// The same seed for PodReadyToStartContainers (also provider-owned).
		pod.Status.Conditions = append(pod.Status.Conditions, priorToStart)
	}
	st := toPodStatus(pod, rs, r.nodeIP, t.startTime, ps, transport)
	// The node-owned interconnect attach condition, from the create-time
	// outcome (excluded from the carry-forward, so it is never duplicated).
	r.interconnect.applyCondition(string(pod.UID), st)
	// terminationMessagePolicy: FallbackToLogsOnError, from the terminated
	// instance's own log file. First, so every overlay below sees the final
	// message the way a kubelet's status assembly does.
	r.applyTerminationMessageOverlay(pod, rs, st)
	r.applyRestartOverlay(pod, t, st)
	// The restart overlay may lift a terminal phase back to Running; the sandbox
	// condition follows the phase actually published.
	refreshReadyToStartContainers(pod, rs, st)
	// The ErrImagePull ↔ ImagePullBackOff flip, which only the provider's own
	// schedule can decide (translate.go maps the typed cause and nothing else).
	r.applyPullOverlay(pod, t, st)
	// LAST, so its readiness re-derivation sees every other overlay's verdict: a
	// container whose postStart has not completed is NotReady, and the pod's
	// ContainersReady/PodReady follow.
	r.applyPostStartOverlay(pod, t, st, transport)
	t.readyMu.Lock()
	if c := findPodCondition(st.Conditions, corev1.PodReady); c != nil {
		t.lastReady = *c
	}
	if c := findPodCondition(st.Conditions, corev1.PodReadyToStartContainers); c != nil {
		t.lastReadyToStart = *c
	}
	t.readyMu.Unlock()
	return *st
}

// trackByID returns the track for pod id under r.mu, or nil if the pod was deleted.
func (r *runtimedRuntime) trackByID(id string) *podTrack {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.track[id]
}

// Watch drives the VK status callback off the runtime's streaming
// WatchPodStatus, with resync-on-stream-break plus a periodic GetPodStatus
// backstop, and starts the slower orphan reaper (orphanreap.go) and the
// projected-volume refresh (projectedrefresh.go). Every goroutine's lifetime is
// bounded by ctx.
func (r *runtimedRuntime) Watch(ctx context.Context, cb func(*corev1.Pod)) {
	r.mu.Lock()
	r.notify = cb
	r.mu.Unlock()

	// The budget history's one writer, for the provider's run lifetime.
	r.history.start(ctx)
	go r.runWatch(ctx)
	go r.runBackstop(ctx)
	go r.runOrphanReaper(ctx)
	go r.runProjectedRefresh(ctx)
	// ctx is the provider's run lifetime: when it ends, so does this provider.
	// The workers with a pod behind them are cancelled by that pod's own delete;
	// this is what ends the one that has no pod left (runtimed_pull.go's
	// compensating delete).
	go func() {
		<-ctx.Done()
		r.shutdown()
	}()
}

// runWatch consumes the runtime's WatchPodStatus stream, reconnecting whenever it
// breaks (the runtime re-sends current snapshots on every reconnect, so no event
// is lost across a break). It runs until ctx is cancelled.
func (r *runtimedRuntime) runWatch(ctx context.Context) {
	for ctx.Err() == nil {
		stream := newWatchStream(ctx)
		done := make(chan error, 1)
		go func() {
			done <- r.rt.WatchPodStatus(&runtimev1.WatchPodStatusRequest{}, stream)
		}()
		r.consume(ctx, stream, done)
		if ctx.Err() != nil {
			return
		}
		// Stream broke; brief backoff before resync to avoid a hot loop.
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// consume reads events off one stream until it ends or ctx is cancelled,
// dispatching each to the VK callback.
func (r *runtimedRuntime) consume(ctx context.Context, stream *watchStream, done <-chan error) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case ev := <-stream.ch:
			if ev == nil {
				continue
			}
			r.emit(ev.GetStatus())
		}
	}
}

// runBackstop periodically reconciles every tracked pod via GetPodStatus,
// recovering any event the streaming watch dropped. It runs until ctx ends.
func (r *runtimedRuntime) runBackstop(ctx context.Context) {
	t := time.NewTicker(resyncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// A slot-1 pod restored before this node's desired annotation was
			// readable is verified here, before the status it feeds is built.
			r.interconnect.recheck(ctx)
			pods, err := r.GetPods(ctx)
			if err != nil {
				continue
			}
			cb := r.callback()
			if cb == nil {
				continue
			}
			for _, p := range pods {
				cb(p.DeepCopy())
			}
		}
	}
}

// emit reconstructs the full Pod for a status event (by pod id) and runs the VK
// callback. An event for an untracked pod (already deleted) is dropped.
func (r *runtimedRuntime) emit(rs *runtimev1.PodStatus) {
	if rs == nil {
		return
	}
	id := rs.GetPodId()
	r.mu.Lock()
	t, ok := r.track[id]
	cb := r.notify
	pr := r.probers[id]
	var pod *corev1.Pod
	if ok {
		pod = t.pod.DeepCopy()
	}
	r.mu.Unlock()
	if !ok || cb == nil {
		return
	}
	var ps probeState
	if pr != nil {
		ps = pr
	}
	pod.Status = r.buildStatus(pod, t, rs, ps)
	cb(pod)
}

// dispatch runs the callback for a status returned synchronously by a mutating
// RPC (so VK sees the new state immediately, not only via the stream).
func (r *runtimedRuntime) dispatch(id string, rs *runtimev1.PodStatus) {
	if rs == nil {
		return
	}
	go r.emit(rs)
}

// callback returns the current VK callback under the lock.
func (r *runtimedRuntime) callback() func(*corev1.Pod) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.notify
}

// lookup resolves a (namespace, name) to a pod id, its stable start time, and the
// tracked Pod object. The Pod is returned so the pod-less GetPodStatus path can
// carry forward / derive Status.QOSClass in toPodStatus; callers that need
// only the id discard it. The returned *corev1.Pod is the tracked object, which is
// immutable once stored (CreatePod/UpdatePod replace the pointer under r.mu, never
// mutate the object in place), so reading it after the lock is released is safe.
//
// Two tracks can share a (namespace, name) during same-name churn — a
// StatefulSet replica or a delete-and-recreate whose successor is created before
// the predecessor's DeletePod finishes. The name alone cannot say which is meant
// and no caller has a UID to offer, so the choice is lookupTrackLocked's
// deterministic one (see preferTrack), never map order.
func (r *runtimedRuntime) lookup(namespace, name string) (string, metav1.Time, *corev1.Pod, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, t := r.lookupTrackLocked(namespace, name)
	if t == nil {
		return "", metav1.Time{}, nil, false
	}
	return id, t.startTime, t.pod, true
}

// lookupTrackLocked returns the id and track a (namespace, name) read resolves
// to, or ("", nil) when no track carries that name. Every same-name candidate is
// weighed through preferTrack, so the answer is independent of map iteration
// order. The caller holds r.mu.
//
// A track whose delete is owed answers for no name, and a refusal owed is no delete.
// The pod is stopped and gone from the apiserver, and the track stays only for the
// call still out of the pod, which reads it by UID (claimFenceReleaseLocked). Answering
// would make Virtual Kubelet's GetPod send
// a same-name successor down UpdatePod instead of CreatePod (createOrUpdatePod,
// node/pod.go). A delete only begun still answers: its RPC can fail, and the retry
// rests on GetPod finding the pod.
func (r *runtimedRuntime) lookupTrackLocked(namespace, name string) (string, *podTrack) {
	var (
		bestID string
		best   *podTrack
	)
	for id, t := range r.track {
		if t.pod.Namespace != namespace || t.pod.Name != name {
			continue
		}
		if del := r.deleteOwed[id]; del != nil && !del.refusal && (del.owned == nil || del.owned == t) {
			continue
		}
		if best == nil || preferTrack(t, best) == t {
			bestID, best = id, t
		}
	}
	return bestID, best
}

// preferTrack picks which of two same-name tracks a name-keyed read resolves to:
//
//  1. the track that is NOT being deleted (t.deleting) — the terminating one is
//     the predecessor whose DeletePod is in flight, and a read aimed at it would
//     exec into, attach to, or report a pod the apiserver has already replaced;
//  2. among two with the same terminating state, the YOUNGEST by the
//     apiserver-stamped CreationTimestamp — the successor of a churn;
//  3. on identical timestamps, the lexicographically smaller UID, so even a full
//     tie has one answer.
//
// t.deleting is the signal, not pod.DeletionTimestamp: DeletePod sets the flag
// the instant it begins, and the tracked object is not refreshed with the
// apiserver's deletion stamp on that path.
//
// LOCKING: the caller holds r.mu (t.pod is read). Each candidate's restartMu is
// taken briefly and in turn, INSIDE r.mu — the documented r.mu → restartMu order
// (podTrack.restartMu), never the reverse — and two restartMu are never held at
// once, since no order is defined between tracks.
func preferTrack(a, b *podTrack) *podTrack {
	if ad, bd := trackDeleting(a), trackDeleting(b); ad != bd {
		if ad {
			return b
		}
		return a
	}
	ac, bc := a.pod.CreationTimestamp, b.pod.CreationTimestamp
	if !ac.Equal(&bc) {
		if ac.After(bc.Time) {
			return a
		}
		return b
	}
	if b.pod.UID < a.pod.UID {
		return b
	}
	return a
}

// trackDeleting reads t.deleting under its guard, restartMu. See preferTrack for
// the lock order it is called under.
func trackDeleting(t *podTrack) bool {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	return t.deleting
}

// GetPod returns the pod a (namespace, name) read resolves to — the same
// discriminated choice lookup makes — with its status reconstructed as GetPods
// would, or NotFound. It is the PodGetter capability VKProvider.GetPod prefers
// over walking GetPods, which could only return whichever same-name pod the
// map yielded first.
func (r *runtimedRuntime) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	r.mu.Lock()
	_, t := r.lookupTrackLocked(namespace, name)
	var pod *corev1.Pod
	if t != nil {
		pod = t.pod // the pointer only, under r.mu; see GetPods
	}
	r.mu.Unlock()
	if t == nil {
		return nil, vkadapter.NotFoundf("pod %q not found", namespace+"/"+name)
	}
	return r.podWithStatus(ctx, pod, t), nil
}

// StatsSummary builds the kubelet Summary API snapshot kubectl top reads,
// consuming the runtime's typed ListPodStats RPC. Each PodStats sample
// carries the proc_pid_rusage working-set footprint runtimed meters
// (ri_phys_footprint, NOT RSS), per-container; the provider maps it to the kubelet
// Summary shape and fills the stable per-pod StartTime from its own bookkeeping
// (the runtime sample carries only the sample timestamp). runtimed meters every
// running pod (the memory limit selects OOM enforcement, not metering); a pod is
// absent from the response, and so from the summary, only when it has no sample
// to give (a host-process pod whose sampler was never armed, or a vm pod whose
// guest agent answered with none).
func (r *runtimedRuntime) StatsSummary(ctx context.Context) (*statsv1alpha1.Summary, error) {
	summary := &statsv1alpha1.Summary{Node: nodeStats(r.nodeSampler, r.nodeName, time.Now())}
	resp, err := r.rt.ListPodStats(ctx, &runtimev1.ListPodStatsRequest{})
	if err != nil {
		return nil, fmt.Errorf("runtimed list pod stats: %w", err)
	}
	for _, ps := range resp.GetPodStats() {
		if ps == nil {
			continue
		}
		summary.Pods = append(summary.Pods, toPodStats(ps, r.startTimeFor(ps.GetPodId())))
	}
	return summary, nil
}

// startTimeFor returns the stable StartTime the provider recorded for the pod id
// at CreatePod, or the zero time for an untracked pod (the runtime does not retain
// it). The Summary API reports the pod start, not the per-sample timestamp.
func (r *runtimedRuntime) startTimeFor(id string) metav1.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.track[id]; ok {
		return t.startTime
	}
	return metav1.Time{}
}

// toPodStats maps a runtime PodStats sample (the ListPodStats wire form) to the
// kubelet Summary API PodStats the VK summary handler serves. startTime is the
// provider's stable per-pod value; the working-set footprint flows through verbatim.
func toPodStats(ps *runtimev1.PodStats, startTime metav1.Time) statsv1alpha1.PodStats {
	out := statsv1alpha1.PodStats{
		PodRef:    statsv1alpha1.PodReference{Name: ps.GetName(), Namespace: ps.GetNamespace(), UID: ps.GetPodId()},
		StartTime: startTime,
		CPU:       toCPUStats(ps.GetCpu()),
		Memory:    toMemoryStats(ps.GetMemory()),
	}
	for _, c := range ps.GetContainers() {
		if c == nil {
			continue
		}
		out.Containers = append(out.Containers, statsv1alpha1.ContainerStats{
			Name:      c.GetName(),
			StartTime: startTime,
			CPU:       toCPUStats(c.GetCpu()),
			Memory:    toMemoryStats(c.GetMemory()),
		})
	}
	return out
}

// toMemoryStats maps a runtime MemoryStats to the kubelet Summary MemoryStats.
// working_set_bytes (ri_phys_footprint) is what kubectl top reports; usage/rss are
// carried when non-zero. A nil sample maps to nil so the field stays absent rather
// than reporting a spurious zero working set.
func toMemoryStats(m *runtimev1.MemoryStats) *statsv1alpha1.MemoryStats {
	if m == nil {
		return nil
	}
	ws := m.GetWorkingSetBytes()
	out := &statsv1alpha1.MemoryStats{Time: protoTime(m.GetTimestamp()), WorkingSetBytes: &ws}
	if u := m.GetUsageBytes(); u != 0 {
		out.UsageBytes = &u
	}
	if rss := m.GetRssBytes(); rss != 0 {
		out.RSSBytes = &rss
	}
	return out
}

// toCPUStats maps a runtime CPUStats to the kubelet Summary CPUStats (best-effort
// CPU accounting; k3sm enforces no CFS millicores). A nil sample maps to nil.
func toCPUStats(c *runtimev1.CPUStats) *statsv1alpha1.CPUStats {
	if c == nil {
		return nil
	}
	out := &statsv1alpha1.CPUStats{Time: protoTime(c.GetTimestamp())}
	if n := c.GetUsageNanoCores(); n != 0 {
		out.UsageNanoCores = &n
	}
	if t := c.GetUsageCoreNanoSeconds(); t != 0 {
		out.UsageCoreNanoSeconds = &t
	}
	return out
}

// podRoot returns the per-pod rootfs parent passed to the PodBox sandbox profile.
// The empty-Root fallback is the runtime's own default work-dir const, the SAME
// one baseSocketDenies derives the work-dir-relative socket spelling from —
// two literals here would let the pod dir and the deny path disagree about where
// the runtime root is.
func (r *runtimedRuntime) podRoot(id string) string {
	root := r.rootfs
	if root == "" {
		root = sandbox.DefaultWorkDir
	}
	return root + "/pods/" + id
}
