package provider

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/virtual-kubelet/virtual-kubelet/errdefs"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"

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
	log      *slog.Logger

	// resolver supplies ConfigMap/Secret data for the M2.1 env resolution the
	// provider performs before sending the box to runtimed (runtimed reads only
	// literal env). It is the SAME resolver wired into runtimed's Deps for volume
	// materialization. nil ⇒ data-backed env/volumes fail closed.
	resolver mount.Resolver
	// metrics, when the wrapped runtime exposes it, is the source of the
	// proc_pid_rusage footprint surfaced to the Summary API (M2.3).
	metrics podMetricsSource

	mu     sync.Mutex
	track  map[string]*podTrack // pod id -> bookkeeping
	notify func(*corev1.Pod)
}

// podMetricsSource is the optional capability of the wrapped runtime that reports
// a per-pod memory footprint (runtimed's *runtime.Runtime satisfies it). The
// provider type-asserts the runtime to this at construction.
type podMetricsSource interface {
	PodMetrics(podID string) (runtimed.PodMetrics, bool)
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
// volume/env Resolver. If rt exposes per-pod metrics (the real *runtime.Runtime
// does), it is captured for the Summary API.
func newRuntimedWith(rt runtimev1.RuntimeServer, cfg RuntimedConfig, resolver mount.Resolver, log *slog.Logger) *runtimedRuntime {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r := &runtimedRuntime{
		rt:       rt,
		nodeName: cfg.NodeName,
		nodeIP:   cfg.NodeIP,
		rootfs:   cfg.Root,
		dyldShim: cfg.DyldShim,
		resolver: resolver,
		log:      log,
		track:    map[string]*podTrack{},
	}
	if m, ok := rt.(podMetricsSource); ok {
		r.metrics = m
	}
	return r
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
	box := toPodBox(pod, r.nodeIP, r.podRoot(string(pod.UID)), r.dyldShim)
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
	r.dispatch(id, resp.GetStatus())
	return nil
}

// UpdatePod forwards labels/annotations changes (the only fields runtimed
// updates in place); other changes need a recreate and are reported by the
// runtime as a typed precondition failure, surfaced here as an error.
func (r *runtimedRuntime) UpdatePod(ctx context.Context, pod *corev1.Pod) error {
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
	r.mu.Lock()
	delete(r.track, id)
	r.mu.Unlock()
	return nil
}

// GetPodStatus returns the named pod's status, NotFound if it is unknown.
func (r *runtimedRuntime) GetPodStatus(ctx context.Context, namespace, name string) (*corev1.PodStatus, error) {
	id, start, ok := r.lookup(namespace, name)
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
	return toPodStatus(resp.GetStatus(), r.nodeIP, start), nil
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
			pod.Status = *toPodStatus(resp.GetStatus(), r.nodeIP, t.startTime)
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
	id, _, ok := r.lookup(namespace, podName)
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
	pod.Status = *toPodStatus(rs, r.nodeIP, start)
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

// lookup resolves a (namespace, name) to a pod id and stable start time.
func (r *runtimedRuntime) lookup(namespace, name string) (string, metav1.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.track {
		if t.pod.Namespace == namespace && t.pod.Name == name {
			return id, t.startTime, true
		}
	}
	return "", metav1.Time{}, false
}

// StatsSummary builds the kubelet Summary API snapshot kubectl top reads (M2.3):
// per tracked pod, the proc_pid_rusage working-set footprint runtimed's sampler
// reports (ri_phys_footprint, NOT RSS). A pod with no sampler (no memory limit ⇒
// no metering in M2) reports no sample and is omitted. runtimed reports a single
// pod-level footprint (summed across container PIDs), so it is attributed to the
// first container — a container-summing consumer (metrics-server) then computes
// the correct pod total without double counting; per-container metering awaits a
// runtimed per-container sampler.
func (r *runtimedRuntime) StatsSummary(ctx context.Context) (*statsv1alpha1.Summary, error) {
	summary := &statsv1alpha1.Summary{Node: statsv1alpha1.NodeStats{NodeName: r.nodeName}}
	if r.metrics == nil {
		return summary, nil
	}

	r.mu.Lock()
	tracks := make([]*podTrack, 0, len(r.track))
	for _, t := range r.track {
		tracks = append(tracks, t)
	}
	r.mu.Unlock()

	for _, t := range tracks {
		m, ok := r.metrics.PodMetrics(string(t.pod.UID))
		if !ok {
			continue
		}
		ws := m.WorkingSetBytes
		ts := metav1.NewTime(m.Timestamp)
		ps := statsv1alpha1.PodStats{
			PodRef:    statsv1alpha1.PodReference{Name: t.pod.Name, Namespace: t.pod.Namespace, UID: string(t.pod.UID)},
			StartTime: t.startTime,
			Memory:    &statsv1alpha1.MemoryStats{Time: ts, WorkingSetBytes: &ws},
		}
		for i := range t.pod.Spec.Containers {
			cws := uint64(0)
			if i == 0 {
				cws = ws
			}
			ps.Containers = append(ps.Containers, statsv1alpha1.ContainerStats{
				Name:      t.pod.Spec.Containers[i].Name,
				StartTime: t.startTime,
				Memory:    &statsv1alpha1.MemoryStats{Time: ts, WorkingSetBytes: &cws},
			})
		}
		summary.Pods = append(summary.Pods, ps)
	}
	return summary, nil
}

// podRoot returns the per-pod rootfs parent passed to the PodBox sandbox profile.
func (r *runtimedRuntime) podRoot(id string) string {
	root := r.rootfs
	if root == "" {
		root = "/var/lib/k3sm"
	}
	return root + "/pods/" + id
}
