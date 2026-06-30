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
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/virtual-kubelet/virtual-kubelet/errdefs"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
	"k8s.io/utils/clock"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/mount"
	runtimed "k3sm.io/runtimed/pkg/runtime"
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
	rt       runtimev1.RuntimeServer
	nodeName string
	nodeIP   string
	rootfs   string
	dyldShim string
	// deniedSocks are AF_UNIX socket paths every pod's SBPL must deny connect()
	// to — notably the root k3sm-netd helper socket, so a same-uid (_k3sm) pod
	// cannot drive the privileged helper. Threaded onto each PodBox's
	// SandboxProfile (apis SandboxProfile.denied_unix_socket_paths).
	deniedSocks []string
	log         *slog.Logger

	// resolver supplies ConfigMap/Secret data for the M2.1 env resolution the
	// provider performs before sending the box to runtimed (runtimed reads only
	// literal env). It is the SAME resolver wired into runtimed's Deps for volume
	// materialization. nil ⇒ data-backed env/volumes fail closed.
	resolver mount.Resolver

	// clk, dial, and probeTransport are the provider-served probe seams (M2.2):
	// the clock that schedules probe loops and the http/tcp I/O the checks use.
	// Production defaults are wired in newRuntimedWith; tests inject fakes.
	clk            clock.Clock
	dial           dialFunc
	probeTransport http.RoundTripper

	mu      sync.Mutex
	track   map[string]*podTrack  // pod id -> bookkeeping
	probers map[string]*podProber // pod id -> provider-served probe runner (M2.2)
	notify  func(*corev1.Pod)
}

// podTrack is the provider-side bookkeeping the runtime does not retain: a stable
// StartTime (set once at CreatePod, never regenerated) and the last Pod object
// (for namespace/name lookup and status reconstruction by pod id).
type podTrack struct {
	pod       *corev1.Pod
	startTime metav1.Time
}

// RuntimedConfig configures a runtimedRuntime.
type RuntimedConfig struct {
	// NodeName is the registering node's name.
	NodeName string
	// NodeIP is the node InternalIP stamped as HostIP on every pod status.
	NodeIP string
	// Root is runtimed's on-disk root (image cache + pod dirs); empty uses the
	// runtimed default (/var/lib/k3sm).
	Root string
	// DyldShim, when set, is the getaddrinfo DNS shim dylib injected into each
	// pod via the PodBox annotation runtimed maps to DYLD_INSERT_LIBRARIES.
	DyldShim string
	// ResolverVIP is the cluster DNS Service VIP (10.43.0.10) the per-pod Seatbelt
	// egress allow-list is scoped to (threaded into runtimed's sandbox.Posture), so
	// a confined pod's DNS reaches the node-local resolver. Empty leaves runtimed's
	// built-in default (sandbox.DefaultResolverVIP), which is NOT the k3sm VIP — the
	// commands always set it from the cluster DNS VIP.
	ResolverVIP string
	// APIServerVIP is the in-cluster Kubernetes API Service VIP (the kubernetes
	// ClusterIP, 10.43.0.1) the per-pod Seatbelt egress is ADDITIONALLY scoped to,
	// so a confined pod's in-cluster client-go (in-pod kubectl) can reach the API
	// VIP. Empty emits no API-server egress rule.
	APIServerVIP string
	// DeniedUnixSocketPaths are AF_UNIX socket paths every pod's SBPL denies
	// connect() to (the root k3sm-netd helper socket): pods run as the same _k3sm
	// uid as the legitimate helper client, so the socket must be denied at the
	// sandbox so a pod cannot drive the privileged daemon. Threaded as data
	// because runtimed cannot import darwin-net.
	DeniedUnixSocketPaths []string
	// Client is the apiserver client the provider resolves ConfigMap/Secret data,
	// SA tokens (M2.1 volumes/env), and imagePullSecret credentials (M2.6) with —
	// runtimed never talks to the apiserver. nil disables data-backed
	// volumes/env/credentials (they fail closed / pull anonymously).
	Client kubernetes.Interface
	// Logger is the structured logger; a discard logger is used if nil.
	Logger *slog.Logger
}

// NewRuntimed builds a runtimedRuntime, constructing the in-process runtime with
// production defaults (real image puller/signer, the exec-shim Seatbelt backend,
// posix_spawn/kqueue supervisor). It returns an error if the runtime cannot be
// constructed (e.g. its cache dir).
func NewRuntimed(cfg RuntimedConfig) (*runtimedRuntime, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// runtimed never talks to the apiserver: the provider (which holds the client)
	// supplies the volume Resolver + imagePullSecret CredentialResolver. nil client
	// ⇒ nil seams ⇒ data-backed volumes fail closed, pulls are anonymous.
	var resolver mount.Resolver
	var creds runtimed.CredentialResolver
	if cfg.Client != nil {
		resolver = newKubeResolver(cfg.Client)
		creds = newKubeCredentials(cfg.Client)
	}
	rt, err := runtimed.New(runtimed.Config{
		Root:           cfg.Root,
		RuntimeVersion: "k3sm-m1",
		Logger:         log,
		// Scope each pod's Seatbelt egress to the cluster DNS + API VIPs so a
		// confined pod's DNS and in-pod client-go reach the node-local resolver /
		// API VIP (M3.3). runtimed threads these into its per-pod sandbox.Posture.
		ResolverVIP:  cfg.ResolverVIP,
		APIServerVIP: cfg.APIServerVIP,
	}, runtimed.Deps{
		Resolver:    resolver,
		Credentials: creds,
	})
	if err != nil {
		return nil, fmt.Errorf("init runtimed: %w", err)
	}
	return newRuntimedWith(rt, cfg, resolver, log), nil
}

// newRuntimedWith wraps an existing runtime server (tests inject a fake) with the
// volume/env Resolver. The Summary API (kubectl top) is served off the runtime's
// typed ListPodStats RPC, so no per-pod-metrics capability is captured here.
func newRuntimedWith(rt runtimev1.RuntimeServer, cfg RuntimedConfig, resolver mount.Resolver, log *slog.Logger) *runtimedRuntime {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &runtimedRuntime{
		rt:             rt,
		nodeName:       cfg.NodeName,
		nodeIP:         cfg.NodeIP,
		rootfs:         cfg.Root,
		dyldShim:       cfg.DyldShim,
		deniedSocks:    cfg.DeniedUnixSocketPaths,
		resolver:       resolver,
		log:            log,
		clk:            clock.RealClock{},
		dial:           (&net.Dialer{}).DialContext,
		probeTransport: newProbeTransport(),
		track:          map[string]*podTrack{},
		probers:        map[string]*podProber{},
	}
}

// Compile-time check that runtimedRuntime satisfies the Runtime seam and the
// optional StatsSource capability (the Summary API surface, M2.3).
var (
	_ Runtime     = (*runtimedRuntime)(nil)
	_ StatsSource = (*runtimedRuntime)(nil)
)

// buildBox translates pod to a PodBox and resolves its env into LITERAL values —
// runtimed reads only EnvVar.value and never talks to the apiserver, so the
// provider resolves configMap/secret/envFrom (via its Resolver) and downward-API
// (via the node identity) here, before the box crosses the runtime boundary.
func (r *runtimedRuntime) buildBox(ctx context.Context, pod *corev1.Pod) (*runtimev1.PodBox, error) {
	box, err := toPodBox(pod, r.nodeIP, r.podRoot(string(pod.UID)), r.dyldShim)
	if err != nil {
		return nil, err
	}
	// Deny every pod the root helper socket: pods share the _k3sm uid with the
	// legitimate helper client, so the sandbox is where the privileged daemon is
	// fenced off from the workload.
	if len(r.deniedSocks) > 0 && box.SandboxProfile != nil {
		box.SandboxProfile.DeniedUnixSocketPaths = r.deniedSocks
	}
	if err := resolvePodBoxEnv(ctx, box, r.nodeName, r.nodeIP, r.resolver); err != nil {
		return nil, err
	}
	return box, nil
}

// CreatePod translates the pod to a PodBox and asks the runtime to start it. The
// runtime returns a typed failure inside the response (the RPC itself returns
// nil) when the fail-closed gate rejects the pod; CreatePod surfaces that as an
// error so VK marks the pod failed.
func (r *runtimedRuntime) CreatePod(ctx context.Context, pod *corev1.Pod) error {
	// Bind the pod's ServiceAccount to the request context so the shared volume
	// Resolver mints the in-pod-API token (projected SA-token volume) against the
	// RIGHT SA — runtimed threads this ctx to mount.Materialize in-process (M2.4).
	ctx = withServiceAccount(ctx, podServiceAccount(pod))
	id := string(pod.UID)
	start := metav1.Now()
	box, err := r.buildBox(ctx, pod)
	if err != nil {
		return fmt.Errorf("translate pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	r.mu.Lock()
	if t, ok := r.track[id]; ok {
		start = t.startTime // idempotent: keep the original start time
	}
	r.track[id] = &podTrack{pod: pod.DeepCopy(), startTime: start}
	r.mu.Unlock()

	resp, err := r.rt.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		return fmt.Errorf("runtimed create pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		return fmt.Errorf("runtimed create pod %s/%s rejected: %s (%s)", pod.Namespace, pod.Name, e.GetMessage(), resp.GetFailureReason().String())
	}
	// Start the provider-served probe runner (M2.2): the VK provider replaces the
	// kubelet, so it must execute the pod's probes itself. No-op for a probe-free
	// pod; idempotent for a repeated CreatePod.
	r.startProber(pod, resp.GetStatus().GetPodIp())
	r.dispatch(id, resp.GetStatus())
	return nil
}

// UpdatePod forwards labels/annotations changes (the only fields runtimed
// updates in place); other changes need a recreate and are reported by the
// runtime as a typed precondition failure, surfaced here as an error.
func (r *runtimedRuntime) UpdatePod(ctx context.Context, pod *corev1.Pod) error {
	// Same SA binding as CreatePod, in case the runtime re-materializes volumes on
	// an in-place update (M2.4).
	ctx = withServiceAccount(ctx, podServiceAccount(pod))
	id := string(pod.UID)
	r.mu.Lock()
	if t, ok := r.track[id]; ok {
		t.pod = pod.DeepCopy()
	}
	r.mu.Unlock()

	box, err := r.buildBox(ctx, pod)
	if err != nil {
		return fmt.Errorf("translate pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	resp, err := r.rt.UpdatePod(ctx, &runtimev1.UpdatePodRequest{Pod: box})
	if err != nil {
		return fmt.Errorf("runtimed update pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		return fmt.Errorf("runtimed update pod %s/%s: %s", pod.Namespace, pod.Name, e.GetMessage())
	}
	r.dispatch(id, resp.GetStatus())
	return nil
}

// DeletePod stops the pod's processes and forgets the bookkeeping. Idempotent. The
// SIGTERM→SIGKILL grace window is derived from the pod (deletion/termination grace,
// k8s 30s default), since runtimed treats a 0 grace as immediate-kill (M2.3).
func (r *runtimedRuntime) DeletePod(ctx context.Context, pod *corev1.Pod) error {
	id := string(pod.UID)
	_, err := r.rt.DeletePod(ctx, &runtimev1.DeletePodRequest{PodId: id, GracePeriodSeconds: graceSeconds(pod)})
	if err != nil {
		return fmt.Errorf("runtimed delete pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	// Stop the probe runner before forgetting the pod (stopProber waits for the
	// loops outside the lock, so no probe goroutine outlives the pod).
	r.stopProber(id)
	r.mu.Lock()
	delete(r.track, id)
	r.mu.Unlock()
	return nil
}

// GetPodStatus returns the named pod's status, NotFound if it is unknown.
func (r *runtimedRuntime) GetPodStatus(ctx context.Context, namespace, name string) (*corev1.PodStatus, error) {
	id, start, pod, ok := r.lookup(namespace, name)
	if !ok {
		return nil, errdefs.NotFoundf("pod %q not found", namespace+"/"+name)
	}
	resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: id})
	if err != nil {
		return nil, fmt.Errorf("runtimed get pod status %s/%s: %w", namespace, name, err)
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		return nil, errdefs.NotFoundf("pod %q not found in runtime", namespace+"/"+name)
	}
	return toPodStatus(pod, resp.GetStatus(), r.nodeIP, start, r.proberFor(id)), nil
}

// GetPods returns every tracked pod with its current status applied.
func (r *runtimedRuntime) GetPods(ctx context.Context) ([]*corev1.Pod, error) {
	r.mu.Lock()
	tracks := make([]*podTrack, 0, len(r.track))
	for _, t := range r.track {
		tracks = append(tracks, t)
	}
	r.mu.Unlock()

	out := make([]*corev1.Pod, 0, len(tracks))
	for _, t := range tracks {
		pod := t.pod.DeepCopy()
		resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: string(pod.UID)})
		if err == nil && (resp.GetError() == nil || resp.GetError().GetCode() == 0) {
			pod.Status = *toPodStatus(pod, resp.GetStatus(), r.nodeIP, t.startTime, r.proberFor(string(pod.UID)))
		}
		out = append(out, pod)
	}
	return out, nil
}

// GetContainerLogs streams the container's buffered combined output from the
// runtime into a ReadCloser the VK logs HTTP handler serves. Follow is honored
// only for the non-follow path in M1 (the gate scopes kubectl logs to
// non-follow); a follow request returns the current buffer and closes.
func (r *runtimedRuntime) GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts api.ContainerLogOpts) (io.ReadCloser, error) {
	id, _, _, ok := r.lookup(namespace, podName)
	if !ok {
		return nil, errdefs.NotFoundf("pod %q not found", namespace+"/"+podName)
	}
	sink := newLogSink(ctx)
	req := &runtimev1.GetLogsRequest{
		PodId:     id,
		Container: containerName,
		TailLines: int64(opts.Tail),
	}
	if err := r.rt.GetLogs(req, sink); err != nil {
		return nil, fmt.Errorf("runtimed logs %s/%s/%s: %w", namespace, podName, containerName, err)
	}
	return io.NopCloser(strings.NewReader(sink.String())), nil
}

// Watch drives the VK status callback off the runtime's streaming
// WatchPodStatus, with resync-on-stream-break plus a periodic GetPodStatus
// backstop. The goroutine's lifetime is bounded by ctx.
func (r *runtimedRuntime) Watch(ctx context.Context, cb func(*corev1.Pod)) {
	r.mu.Lock()
	r.notify = cb
	r.mu.Unlock()

	go r.runWatch(ctx)
	go r.runBackstop(ctx)
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
	var start metav1.Time
	if ok {
		pod = t.pod.DeepCopy()
		start = t.startTime
	}
	r.mu.Unlock()
	if !ok || cb == nil {
		return
	}
	var ps probeState
	if pr != nil {
		ps = pr
	}
	pod.Status = *toPodStatus(pod, rs, r.nodeIP, start, ps)
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
// carry forward / derive Status.QOSClass in toPodStatus (B12); callers that need
// only the id discard it. The returned *corev1.Pod is the tracked object, which is
// immutable once stored (CreatePod/UpdatePod replace the pointer under r.mu, never
// mutate the object in place), so reading it after the lock is released is safe.
func (r *runtimedRuntime) lookup(namespace, name string) (string, metav1.Time, *corev1.Pod, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.track {
		if t.pod.Namespace == namespace && t.pod.Name == name {
			return id, t.startTime, t.pod, true
		}
	}
	return "", metav1.Time{}, nil, false
}

// StatsSummary builds the kubelet Summary API snapshot kubectl top reads (M2.3),
// consuming the runtime's typed ListPodStats RPC (apis:M2.2). Each PodStats sample
// carries the proc_pid_rusage working-set footprint runtimed meters
// (ri_phys_footprint, NOT RSS), per-container; the provider maps it to the kubelet
// Summary shape and fills the stable per-pod StartTime from its own bookkeeping
// (the runtime sample carries only the sample timestamp). A pod runtimed does not
// sample (no memory limit ⇒ no metering in M2) is absent from the response and so
// from the summary.
func (r *runtimedRuntime) StatsSummary(ctx context.Context) (*statsv1alpha1.Summary, error) {
	summary := &statsv1alpha1.Summary{Node: statsv1alpha1.NodeStats{NodeName: r.nodeName}}
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
func (r *runtimedRuntime) podRoot(id string) string {
	root := r.rootfs
	if root == "" {
		root = "/var/lib/k3sm"
	}
	return root + "/pods/" + id
}
