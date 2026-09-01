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

// Package provider implements k3sm's Virtual Kubelet providers.
package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"

	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"

	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// HostProcess is the k3sm M0 "HostProcess" Virtual Kubelet provider: it runs each
// pod container as a NATIVE macOS process at host paths — no Linux, no VM, and (for
// now) no isolation. It is the walking-skeleton runtime that proves a Kubernetes Pod
// can execute as a native arm64 process. Seatbelt confinement (see
// runtimed/prototypes/seatbelt-hostpath) and the gRPC runtimed split arrive in M2.
//
// Container argv = container.Command + container.Args; if both are empty the image
// reference is treated as the binary path (M0 convention, since native macOS
// workloads have no image ecosystem yet).
//
// restartPolicy is NOT honored on this provider (M10.2): an exited container is
// reaped once and never re-exec'd, whatever the pod or container restartPolicy
// says. The B26 exit-driven restart authority (restartpolicy.go +
// runtimed_restart.go) is wired only on the runtimed path; the conformance
// register carries this HostProcess ceiling at write-back.
type HostProcess struct {
	nodeName string
	podRoot  string // dir for per-pod logs/state
	nodeIP   string

	// recorder emits pod lifecycle Events (Pulled/Created/Started/Killing) so
	// `kubectl describe pod` shows them. Injected once at construction and never
	// mutated (set before any goroutine starts → race-free without a lock); a nil
	// injection is replaced with a no-op so the hot pod path never nil-panics.
	recorder record.EventRecorder

	mu     sync.Mutex
	pods   map[string]*podRec
	notify func(*corev1.Pod)
}

type podRec struct {
	pod   *corev1.Pod // owns .Status; mutated in place under mu
	procs map[string]*procRec
}

type procRec struct {
	cmd     *exec.Cmd
	logPath string
}

func podKey(ns, name string) string { return ns + "/" + name }

// NewHostProcess returns a HostProcess provider. podRoot is created on demand.
// recorder receives pod lifecycle Events; a nil recorder is replaced with a
// no-op so callers that do not wire an EventRecorder (tests, degraded bring-up)
// never nil-panic on the pod path.
func NewHostProcess(nodeName, podRoot, nodeIP string, recorder record.EventRecorder) *HostProcess {
	if recorder == nil {
		recorder = nopRecorder{}
	}
	return &HostProcess{nodeName: nodeName, podRoot: podRoot, nodeIP: nodeIP, recorder: recorder, pods: map[string]*podRec{}}
}

// Compile-time checks that we satisfy the VK contracts and the Runtime seam.
var (
	_ vkadapter.PodLifecycleHandler = (*HostProcess)(nil)
	_ vkadapter.PodNotifier         = (*HostProcess)(nil)
	_ Runtime                       = (*HostProcess)(nil)
)

// podEvent is a lifecycle Event buffered under p.mu and emitted after the lock is
// released — mirroring dispatch's off-lock callback discipline so a slow/blocking
// EventRecorder sink can never stall a caller holding the provider lock.
type podEvent struct {
	eventtype string
	reason    string
	message   string
}

// CreatePod launches every container of the pod as a native process, then emits
// the Pulled/Created/Started (and, on a start failure, Failed) lifecycle Events
// outside the provider lock.
func (p *HostProcess) CreatePod(ctx context.Context, pod *corev1.Pod) error {
	events, err := p.startPod(pod)
	// Emit outside p.mu (startPod has returned, releasing the lock). The Event's
	// involved object is the Pod, so client-go derives the Pod ObjectReference; the
	// container name is carried in the message.
	for _, ev := range events {
		p.recorder.Event(pod, ev.eventtype, ev.reason, ev.message)
	}
	return err
}

// startPod is the locked body of CreatePod: it launches each container process,
// records status, and returns the lifecycle Events for CreatePod to emit after
// the lock is released.
func (p *HostProcess) startPod(pod *corev1.Pod) ([]podEvent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := podKey(pod.Namespace, pod.Name)
	if _, ok := p.pods[k]; ok {
		return nil, nil // idempotent
	}
	dir := filepath.Join(p.podRoot, string(pod.UID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("pod dir: %w", err)
	}
	rec := &podRec{pod: pod.DeepCopy(), procs: map[string]*procRec{}}
	now := metav1.Now()
	var cstats []corev1.ContainerStatus
	var events []podEvent

	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		argv := append(append([]string{}, c.Command...), c.Args...)
		if len(argv) == 0 {
			argv = []string{c.Image} // M0 convention: image ref == binary path
		}
		// M0 has no registry pull (image == already-present native binary), so the
		// Pulled event uses the kubelet's "already present" phrasing.
		events = append(events, podEvent{corev1.EventTypeNormal, reasonPulled, msgImageAlreadyPresent(c.Image)})
		logPath := filepath.Join(dir, c.Name+".log")
		lf, err := os.Create(logPath)
		if err != nil {
			return events, fmt.Errorf("log file: %w", err)
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdout, cmd.Stderr = lf, lf
		cmd.Env = envSlice(c.Env)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own process group → clean teardown
		events = append(events, podEvent{corev1.EventTypeNormal, reasonCreated, msgCreatedContainer(c.Name)})
		if err := cmd.Start(); err != nil {
			_ = lf.Close()
			events = append(events, podEvent{corev1.EventTypeWarning, reasonFailed, msgFailedStart(c.Name)})
			cstats = append(cstats, waitingStatus(c, "StartError", err.Error()))
			continue
		}
		events = append(events, podEvent{corev1.EventTypeNormal, reasonStarted, msgStartedContainer(c.Name)})
		rec.procs[c.Name] = &procRec{cmd: cmd, logPath: logPath}
		cstats = append(cstats, runningStatus(c, now))
		go p.reap(k, c.Name, cmd, lf)
	}

	// containersReady is the AND of every container's Ready over the statuses just
	// built (a StartError container is not Ready) — NOT a hardcoded True. It gates
	// PodReady through the shared computeReadiness seam so spec.readinessGates are
	// honored (M0/HostProcess is probe-less: a container is Ready when Running).
	containersReady := len(cstats) > 0
	for i := range cstats {
		if !cstats[i].Ready {
			containersReady = false
		}
	}
	crStatus := corev1.ConditionFalse
	if containersReady {
		crStatus = corev1.ConditionTrue
	}
	// Merge-not-replace: the four provider-owned conditions (PodReady via the same
	// computeReadiness authority as toPodStatus), then carry FORWARD any external
	// condition on the incoming pod so a readinessGate condition survives this write.
	conds := []corev1.PodCondition{
		{Type: corev1.PodInitialized, Status: corev1.ConditionTrue},
		computeReadiness(rec.pod, containersReady),
		{Type: corev1.ContainersReady, Status: crStatus},
		{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
	}
	conds = append(conds, carryForwardExternalConditions(rec.pod)...)
	rec.pod.Status = corev1.PodStatus{
		Phase:             corev1.PodRunning,
		HostIP:            p.nodeIP,
		PodIP:             p.nodeIP,
		PodIPs:            []corev1.PodIP{{IP: p.nodeIP}},
		StartTime:         &now,
		Conditions:        conds,
		ContainerStatuses: cstats,
	}
	p.pods[k] = rec
	p.dispatch(rec.pod)
	return events, nil
}

// reap waits for a container process to exit and records its terminal status.
func (p *HostProcess) reap(k, cname string, cmd *exec.Cmd, lf *os.File) {
	werr := cmd.Wait()
	_ = lf.Close()

	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.pods[k]
	if !ok {
		return // pod was deleted
	}
	exitCode, reason := 0, "Completed"
	if werr != nil {
		exitCode, reason = 1, "Error"
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			exitCode = ee.ExitCode()
		}
	}
	now := metav1.Now()
	for i := range rec.pod.Status.ContainerStatuses {
		cs := &rec.pod.Status.ContainerStatuses[i]
		if cs.Name != cname {
			continue
		}
		var startedAt metav1.Time
		if cs.State.Running != nil {
			startedAt = cs.State.Running.StartedAt
		}
		cs.State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			ExitCode: int32(exitCode), Reason: reason, StartedAt: startedAt, FinishedAt: now,
		}}
		cs.Ready = false
		cs.Started = ptr(false)
	}
	rec.pod.Status.Phase = aggregatePhase(rec.pod.Status.ContainerStatuses)
	// Route the failure PodReady through the shared computeReadiness seam
	// (containersReady=false ⇒ False/"ContainersNotReady") so CreatePod, reap, and
	// toPodStatus have a single readiness authority; setPodCondition carries the
	// reason so it surfaces in kubectl describe.
	setPodCondition(&rec.pod.Status, computeReadiness(rec.pod, false))
	setCond(&rec.pod.Status, corev1.ContainersReady, corev1.ConditionFalse)
	p.dispatch(rec.pod)
}

// UpdatePod is a no-op for M0 (we don't restart on spec changes yet).
func (p *HostProcess) UpdatePod(ctx context.Context, pod *corev1.Pod) error { return nil }

// DeletePod kills every container process group and forgets the pod, then emits a
// Killing lifecycle Event per container outside the provider lock.
func (p *HostProcess) DeletePod(ctx context.Context, pod *corev1.Pod) error {
	events := p.stopPod(pod)
	for _, ev := range events {
		p.recorder.Event(pod, ev.eventtype, ev.reason, ev.message)
	}
	return nil
}

// stopPod is the locked body of DeletePod: it kills each container process group,
// marks the pod Succeeded, and returns the Killing Events for DeletePod to emit
// after the lock is released.
func (p *HostProcess) stopPod(pod *corev1.Pod) []podEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := podKey(pod.Namespace, pod.Name)
	rec, ok := p.pods[k]
	if !ok {
		return nil // already gone; DeletePod may be called repeatedly
	}
	var events []podEvent
	for name, pr := range rec.procs {
		events = append(events, podEvent{corev1.EventTypeNormal, reasonKilling, msgStoppingContainer(name)})
		if pr.cmd.Process != nil {
			_ = syscall.Kill(-pr.cmd.Process.Pid, syscall.SIGKILL) // whole process group
		}
	}
	rec.pod.Status.Phase = corev1.PodSucceeded
	p.dispatch(rec.pod)
	delete(p.pods, k)
	return events
}

// GetPod returns a deep copy of the tracked pod, or a NotFound error when this
// provider has no record of it.
func (p *HostProcess) GetPod(ctx context.Context, ns, name string) (*corev1.Pod, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.pods[podKey(ns, name)]
	if !ok {
		return nil, vkadapter.NotFoundf("pod %q not found", podKey(ns, name))
	}
	return rec.pod.DeepCopy(), nil
}

// GetPodStatus returns a deep copy of the tracked pod's status, or a NotFound
// error when this provider has no record of it.
func (p *HostProcess) GetPodStatus(ctx context.Context, ns, name string) (*corev1.PodStatus, error) {
	pod, err := p.GetPod(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	return pod.Status.DeepCopy(), nil
}

// GetPods returns deep copies of every pod this provider tracks — the reconcile
// view VK syncs against, so it must never hand out the live records.
func (p *HostProcess) GetPods(ctx context.Context) ([]*corev1.Pod, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*corev1.Pod, 0, len(p.pods))
	for _, rec := range p.pods {
		out = append(out, rec.pod.DeepCopy())
	}
	return out, nil
}

// NotifyPods registers the async status callback (PodNotifier).
func (p *HostProcess) NotifyPods(ctx context.Context, cb func(*corev1.Pod)) {
	p.mu.Lock()
	p.notify = cb
	p.mu.Unlock()
}

// Watch registers cb as the status-change callback so HostProcess satisfies the
// Runtime seam. For the in-process HostProcess there is no stream to break, so
// Watch is just NotifyPods under the Runtime name; dispatch already runs cb
// outside the provider lock.
func (p *HostProcess) Watch(ctx context.Context, cb func(*corev1.Pod)) {
	p.NotifyPods(ctx, cb)
}

// dispatch pushes a status update to VK. Called under p.mu; runs the callback
// asynchronously on a copy to avoid re-entrancy/deadlock.
func (p *HostProcess) dispatch(pod *corev1.Pod) {
	if p.notify != nil {
		cp := pod.DeepCopy()
		go p.notify(cp)
	}
}

// GetContainerLogs returns the container's combined stdout/stderr log file.
func (p *HostProcess) GetContainerLogs(ctx context.Context, ns, podName, containerName string, opts vkadapter.ContainerLogOpts) (io.ReadCloser, error) {
	p.mu.Lock()
	rec, ok := p.pods[podKey(ns, podName)]
	p.mu.Unlock()
	if !ok {
		return nil, vkadapter.NotFoundf("pod %q not found", podKey(ns, podName))
	}
	pr, ok := rec.procs[containerName]
	if !ok {
		return nil, vkadapter.NotFoundf("container %q not found", containerName)
	}
	return os.Open(pr.logPath)
}

// GetStatsSummary returns the kubelet stats Summary for this node. It IS
// implemented — the summary is what GetMetricsResource transcodes — but the M0
// HostProcess provider meters nothing, so it carries the node identity and no CPU
// or memory sample.
func (p *HostProcess) GetStatsSummary(ctx context.Context) (*statsv1alpha1.Summary, error) {
	return &statsv1alpha1.Summary{Node: statsv1alpha1.NodeStats{NodeName: p.nodeName}}, nil
}

// --- not implemented in M0 ---

// RunInContainer is not implemented by the M0 HostProcess provider: it returns a
// NotFound error so `kubectl exec` fails with a clear reason rather than hanging.
func (p *HostProcess) RunInContainer(ctx context.Context, ns, podName, c string, cmd []string, a vkadapter.AttachIO) error {
	return vkadapter.NotFound("exec is not implemented in the M0 HostProcess provider")
}

// AttachToContainer is not implemented by the M0 HostProcess provider: it returns
// a NotFound error so `kubectl attach` fails with a clear reason.
func (p *HostProcess) AttachToContainer(ctx context.Context, ns, podName, c string, a vkadapter.AttachIO) error {
	return vkadapter.NotFound("attach is not implemented in the M0 HostProcess provider")
}

// PortForward is not implemented by the M0 HostProcess provider: it returns a
// NotFound error so `kubectl port-forward` fails with a clear reason.
func (p *HostProcess) PortForward(ctx context.Context, ns, podName string, port int32, s io.ReadWriteCloser) error {
	return vkadapter.NotFound("port-forward is not implemented in the M0 HostProcess provider")
}

// GetMetricsResource transcodes this provider's Summary into the kubelet
// resource-metrics families. The M0 HostProcess provider meters nothing, so its
// node-only Summary carries no CPU or memory sample and the transcode yields an
// EMPTY scrape target — the same honest answer the old stub gave, now produced by
// the one shared builder rather than a second hard-coded nil (so a future
// HostProcess that does meter lights up without touching this method).
func (p *HostProcess) GetMetricsResource(ctx context.Context) ([]*dto.MetricFamily, error) {
	summary, err := p.GetStatsSummary(ctx)
	if err != nil {
		return nil, err
	}
	return buildResourceMetrics(summary), nil
}

// --- helpers ---

func envSlice(env []corev1.EnvVar) []string {
	out := os.Environ()
	for _, e := range env {
		out = append(out, e.Name+"="+e.Value)
	}
	return out
}

func runningStatus(c *corev1.Container, now metav1.Time) corev1.ContainerStatus {
	return corev1.ContainerStatus{
		Name: c.Name, Image: c.Image, ImageID: c.Image, Ready: true, Started: ptr(true),
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: now}},
	}
}

func waitingStatus(c *corev1.Container, reason, msg string) corev1.ContainerStatus {
	return corev1.ContainerStatus{
		Name: c.Name, Image: c.Image,
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: msg}},
	}
}

func aggregatePhase(css []corev1.ContainerStatus) corev1.PodPhase {
	anyRunning, anyFailed := false, false
	for _, cs := range css {
		if cs.State.Running != nil {
			anyRunning = true
		}
		if t := cs.State.Terminated; t != nil && t.ExitCode != 0 {
			anyFailed = true
		}
	}
	switch {
	case anyRunning:
		return corev1.PodRunning
	case anyFailed:
		return corev1.PodFailed
	default:
		return corev1.PodSucceeded
	}
}

func setCond(s *corev1.PodStatus, t corev1.PodConditionType, st corev1.ConditionStatus) {
	for i := range s.Conditions {
		if s.Conditions[i].Type == t {
			s.Conditions[i].Status = st
			return
		}
	}
	s.Conditions = append(s.Conditions, corev1.PodCondition{Type: t, Status: st})
}

// setPodCondition upserts a FULL PodCondition by Type — replacing Status, Reason,
// Message, and LastTransitionTime (setCond carries only Status). This is how a
// blocked PodReady's "ReadinessGatesNotReady"/"ContainersNotReady" reason surfaces
// in kubectl describe. An absent Type is appended.
func setPodCondition(s *corev1.PodStatus, cond corev1.PodCondition) {
	for i := range s.Conditions {
		if s.Conditions[i].Type == cond.Type {
			s.Conditions[i] = cond
			return
		}
	}
	s.Conditions = append(s.Conditions, cond)
}

func ptr[T any](v T) *T { return &v }
