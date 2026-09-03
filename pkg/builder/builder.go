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

package builder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// State is where the engine sits in its bring-up. It is derived on every Status
// call from the live Pod phase plus a worker probe — never cached, so a Status is
// always current.
type State string

const (
	// StateAbsent means no engine Pod exists — the legible-absence case.
	StateAbsent State = "Absent"
	// StatePending means the Pod exists but is not yet Running.
	StatePending State = "Pending"
	// StateStarting means the Pod is Running but no buildkit worker has
	// registered yet (buildkitd binds its listener before the OCI worker is up).
	StateStarting State = "Starting"
	// StateReady means a buildkit worker is registered and the engine accepts
	// builds.
	StateReady State = "Ready"
	// StateFailed means the Pod reached a terminal non-Ready phase.
	StateFailed State = "Failed"
)

// ErrAbsent is returned by Endpoint when the builder stack is not deployed. It
// carries the legible-absence contract: the fix is named, not left to an opaque
// dial error downstream.
var ErrAbsent = errors.New("builder engine is not running — run `k3sm builder up`")

// readinessCommand is the exec the host runs IN the Pod to probe readiness. It
// polls the daemon's own socket for a REGISTERED WORKER, which is the true ready
// signal — the tcp listener the Service fronts is bound earlier, before the
// worker exists.
var readinessCommand = []string{"buildctl", "--addr", "unix:///run/buildkit/buildkitd.sock", "debug", "workers"}

// Status is a point-in-time report of the engine.
type Status struct {
	// State is the derived lifecycle state.
	State State
	// PodPhase is the raw Pod phase, or "" when absent.
	PodPhase corev1.PodPhase
	// Workers is the count of registered buildkit workers (0 unless Ready).
	Workers int
	// Endpoint is the tcp address a buildx remote driver dials, or "" when it is
	// not yet resolvable (no Service, or no ClusterIP allocated yet).
	Endpoint string
	// Message is a human-readable elaboration, most importantly for Absent and
	// Failed.
	Message string
}

// Execer runs a command inside a Pod container and returns its output. It is the
// consumer-owned seam that lets the readiness probe be driven by a fake in tests
// — a real remotecommand executor is a heavyweight, cluster-only dependency the
// state machine must not hard-require.
type Execer interface {
	Exec(ctx context.Context, namespace, pod, container string, command []string) (stdout, stderr string, err error)
}

// Manager drives the builder stack's lifecycle over a kube client and an Execer.
type Manager struct {
	cfg  Config
	kube kubernetes.Interface
	exec Execer
	log  *slog.Logger

	// pollInterval is how often Up re-checks readiness. A field so a test can
	// drive Up to completion without real sleeps.
	pollInterval time.Duration
}

// NewManager builds a Manager for cfg (normalized here, so callers pass a partial
// Config). exec may be nil for read-only Status/Endpoint use, but Up then cannot
// probe readiness.
func NewManager(kube kubernetes.Interface, exec Execer, cfg Config, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		cfg:          cfg.Normalize(),
		kube:         kube,
		exec:         exec,
		log:          log,
		pollInterval: 2 * time.Second,
	}
}

// Up ensures the PVC, Service and Pod exist and then blocks until a buildkit
// worker registers, ctx is cancelled, or the Pod fails. It is idempotent: an
// existing object is left as-is, so a second Up against a running engine just
// waits for readiness.
func (m *Manager) Up(ctx context.Context) (Status, error) {
	if err := m.cfg.Validate(); err != nil {
		return Status{}, err
	}
	if m.exec == nil {
		return Status{}, fmt.Errorf("builder up: no exec seam configured for the readiness probe")
	}
	// The namespace FIRST: the PVC/Pod/Service all target it, and a create into
	// an absent namespace fails ("namespaces %q not found"), observed live. This
	// is the pkg/rbac provisioning pattern — one step owns the namespace next to
	// the objects that are meaningless without it.
	if err := m.ensureNamespace(ctx); err != nil {
		return Status{}, err
	}
	if err := m.ensurePVC(ctx); err != nil {
		return Status{}, err
	}
	if err := m.ensureService(ctx); err != nil {
		return Status{}, err
	}
	if err := m.ensurePod(ctx); err != nil {
		return Status{}, err
	}
	m.log.Info("builder engine applied; waiting for a registered worker",
		"namespace", m.cfg.Namespace, "name", m.cfg.Name)
	return m.waitReady(ctx)
}

// waitReady polls Status until Ready/Failed/ctx-done.
func (m *Manager) waitReady(ctx context.Context) (Status, error) {
	t := time.NewTicker(m.pollInterval)
	defer t.Stop()
	for {
		st, err := m.Status(ctx)
		if err != nil {
			return st, err
		}
		switch st.State {
		case StateReady:
			m.log.Info("builder engine ready", "workers", st.Workers, "endpoint", st.Endpoint)
			return st, nil
		case StateFailed:
			return st, fmt.Errorf("builder engine failed to become ready: %s", st.Message)
		}
		select {
		case <-ctx.Done():
			return st, fmt.Errorf("builder engine not ready (state %s): %w", st.State, ctx.Err())
		case <-t.C:
		}
	}
}

// Down deletes the Pod and Service and KEEPS the cache PVC, so a rebuilt engine
// finds a warm layer cache. It is idempotent — a not-found delete is success.
func (m *Manager) Down(ctx context.Context) error {
	var errs []error
	if err := m.kube.CoreV1().Pods(m.cfg.Namespace).Delete(ctx, m.cfg.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete pod: %w", err))
	}
	if err := m.kube.CoreV1().Services(m.cfg.Namespace).Delete(ctx, m.cfg.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete service: %w", err))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	m.log.Info("builder engine torn down; cache claim kept",
		"namespace", m.cfg.Namespace, "name", m.cfg.Name)
	return nil
}

// Delete is the full reset: it removes the Pod, Service and the cache PVC, then
// the builder namespace last (which reaps anything left). Down keeps the cache
// for a warm rebuild; Delete is the full reset — the next `up` rebuilds the cache
// from scratch. It is idempotent, the same posture as Down — a not-found delete
// is success. The named objects are deleted explicitly first for a fast, legible
// teardown; the namespace delete then cascades over any remainder.
func (m *Manager) Delete(ctx context.Context) error {
	var errs []error
	if err := m.kube.CoreV1().Pods(m.cfg.Namespace).Delete(ctx, m.cfg.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete pod: %w", err))
	}
	if err := m.kube.CoreV1().Services(m.cfg.Namespace).Delete(ctx, m.cfg.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete service: %w", err))
	}
	if err := m.kube.CoreV1().PersistentVolumeClaims(m.cfg.Namespace).Delete(ctx, m.cfg.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete pvc: %w", err))
	}
	if err := m.kube.CoreV1().Namespaces().Delete(ctx, m.cfg.Namespace, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete namespace: %w", err))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	m.log.Info("builder engine deleted; cache claim removed",
		"namespace", m.cfg.Namespace, "name", m.cfg.Name)
	return nil
}

// Status derives the current engine state from the live Pod and, when Running, a
// worker probe. An absent Pod is StateAbsent with the legible fix in Message.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	endpoint, _ := m.resolveEndpoint(ctx)

	pod, err := m.kube.CoreV1().Pods(m.cfg.Namespace).Get(ctx, m.cfg.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return Status{State: StateAbsent, Endpoint: endpoint, Message: ErrAbsent.Error()}, nil
	}
	if err != nil {
		return Status{}, fmt.Errorf("get builder pod: %w", err)
	}

	st := Status{PodPhase: pod.Status.Phase, Endpoint: endpoint}
	switch pod.Status.Phase {
	case corev1.PodRunning:
		workers := m.probeWorkers(ctx)
		st.Workers = workers
		if workers > 0 {
			st.State = StateReady
		} else {
			st.State = StateStarting
			st.Message = "pod running; waiting for buildkitd to register a worker"
		}
	case corev1.PodFailed, corev1.PodSucceeded:
		st.State = StateFailed
		st.Message = fmt.Sprintf("pod terminated in phase %s", pod.Status.Phase)
	default:
		st.State = StatePending
		st.Message = "pod not yet running"
	}
	return st, nil
}

// probeWorkers execs the readiness command in the Pod and counts registered
// workers. Any exec error (daemon not up yet, container not started) reads as
// zero workers — a not-ready signal, not a hard failure.
func (m *Manager) probeWorkers(ctx context.Context) int {
	if m.exec == nil {
		return 0
	}
	out, _, err := m.exec.Exec(ctx, m.cfg.Namespace, m.cfg.Name, containerName, readinessCommand)
	if err != nil {
		return 0
	}
	return countWorkers(out)
}

// Endpoint returns the tcp address a buildx remote driver dials, or ErrAbsent
// when the stack is not deployed. This is the seam `k3sm build`'s full path (a
// follow-up) consumes: it will run buildx with `--driver remote <Endpoint()>`.
func (m *Manager) Endpoint(ctx context.Context) (string, error) {
	ep, err := m.resolveEndpoint(ctx)
	if err != nil {
		return "", err
	}
	if ep == "" {
		return "", fmt.Errorf("builder engine has no endpoint yet — its Service has no ClusterIP allocated; retry after `k3sm builder up` reports Ready")
	}
	return ep, nil
}

// resolveEndpoint reads the Service's ClusterIP and composes the tcp endpoint. A
// missing Service is ErrAbsent; a Service without an allocated ClusterIP yields
// "" and no error (a transient bring-up state).
func (m *Manager) resolveEndpoint(ctx context.Context) (string, error) {
	svc, err := m.kube.CoreV1().Services(m.cfg.Namespace).Get(ctx, m.cfg.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", ErrAbsent
	}
	if err != nil {
		return "", fmt.Errorf("get builder service: %w", err)
	}
	ip := svc.Spec.ClusterIP
	if ip == "" || ip == corev1.ClusterIPNone {
		return "", nil
	}
	return fmt.Sprintf("tcp://%s:%d", ip, m.cfg.TCPPort), nil
}

// ---- ensure helpers (Get-then-Create; idempotent) --------------------------

func (m *Manager) ensureNamespace(ctx context.Context) error {
	cli := m.kube.CoreV1().Namespaces()
	if _, err := cli.Get(ctx, m.cfg.Namespace, metav1.GetOptions{}); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get builder namespace: %w", err)
	}
	if _, err := cli.Create(ctx, m.cfg.NamespaceObject(), metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create builder namespace: %w", err)
	}
	return nil
}

func (m *Manager) ensurePVC(ctx context.Context) error {
	cli := m.kube.CoreV1().PersistentVolumeClaims(m.cfg.Namespace)
	if _, err := cli.Get(ctx, m.cfg.Name, metav1.GetOptions{}); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get builder pvc: %w", err)
	}
	if _, err := cli.Create(ctx, m.cfg.PersistentVolumeClaim(), metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create builder pvc: %w", err)
	}
	return nil
}

func (m *Manager) ensureService(ctx context.Context) error {
	cli := m.kube.CoreV1().Services(m.cfg.Namespace)
	if _, err := cli.Get(ctx, m.cfg.Name, metav1.GetOptions{}); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get builder service: %w", err)
	}
	if _, err := cli.Create(ctx, m.cfg.Service(), metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create builder service: %w", err)
	}
	return nil
}

func (m *Manager) ensurePod(ctx context.Context) error {
	cli := m.kube.CoreV1().Pods(m.cfg.Namespace)
	if _, err := cli.Get(ctx, m.cfg.Name, metav1.GetOptions{}); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get builder pod: %w", err)
	}
	if _, err := cli.Create(ctx, m.cfg.Pod(), metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create builder pod: %w", err)
	}
	return nil
}

// countWorkers parses `buildctl debug workers` output. The first non-empty line
// is the "ID PLATFORMS ..." header; each subsequent non-empty line is one
// registered worker.
func countWorkers(out string) int {
	n := 0
	seenHeader := false
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !seenHeader {
			seenHeader = true
			continue
		}
		n++
	}
	return n
}
