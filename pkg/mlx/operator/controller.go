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

package operator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	crdconfig "k3sm.io/apis/config/crd"
	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/crdensure"
	"k3sm.io/k3sm/pkg/mlx"
)

// FieldManager is the server-side-apply field manager every serving object this
// operator writes is owned by.
//
// It is its own name, distinct from both pkg/addons' "k3sm-addons" and the bare
// "k3sm" the CRD ensure uses. Sharing a manager between independent appliers
// makes each one take ownership of the other's fields and fight over them on
// every pass; a distinct name is what lets forced apply converge THIS
// controller's drift without touching anything else's.
const FieldManager = "k3sm-mlx"

// DefaultPullSecretName is the conventional name of the image-pull Secret the
// rendered serving pod uses, looked up in the MLXModel's OWN namespace.
//
// A convention rather than a spec field on purpose: the serving image is a
// digest the release pins, so which registry credential opens it is an operator
// deployment fact and not something a model author should have to restate on
// every MLXModel. Config.PullSecretName overrides it for a deployment that
// already has a differently-named credential.
const DefaultPullSecretName = "mlx-pull-secret"

// resyncPeriod re-delivers every MLXModel periodically, so a reconcile that
// failed for a reason no watch event will repeat — a transient apply rejection,
// a probe that could not run — is retried without waiting for the spec to
// change.
const resyncPeriod = 10 * time.Minute

// probeTimeout bounds ONE serving-surface probe. It is short because the probe
// only distinguishes "downloading" from "loading" for the status message, and a
// slow probe would hold the single worker away from every other model.
const probeTimeout = 2 * time.Second

// mlxModelResource is the GroupVersionResource the MLXModel informer and every
// read and status write address. The plural is taken from the CRD name apis
// publishes rather than spelled here, so a rename cannot leave this watching a
// path the API server does not serve.
var mlxModelResource = mlxv1alpha1.SchemeGroupVersion.WithResource("mlxmodels")

// Config is everything the controller needs from its caller.
type Config struct {
	// Client is the typed clientset used to apply the serving objects, read the
	// pull Secret, and observe pods. Required.
	Client kubernetes.Interface
	// Dynamic is the dynamic client the MLXModel informer, reads, and status
	// writes go through. MLXModel has no generated clientset — apis publishes the
	// types and nothing more — so the dynamic client IS the typed path here.
	// Required.
	Dynamic dynamic.Interface
	// CRD applies and establishes the MLXModel CustomResourceDefinition before
	// the informer starts. nil skips the ensure, which is only correct when
	// something else has already established the CRD.
	CRD crdensure.CRDClient
	// GPU supplies the node GPU facts the pre-render fit check reads. nil skips
	// the fit check — see GPUSource.
	GPU GPUSource
	// Options are the operator-level render defaults (the pinned serving image
	// and port) an MLXModel spec does not have to state. They are also what the
	// published status endpoint resolves its port through, so the endpoint cannot
	// name a port the rendered Service does not expose.
	Options mlx.Options
	// ClusterDomain is the cluster DNS suffix the published endpoint is built
	// from. Empty means the darwin-net default.
	ClusterDomain string
	// PullSecretName overrides DefaultPullSecretName.
	PullSecretName string
	// ProbeTransport is the HTTP transport serving-surface probes use. nil means
	// mlx.NewProbeTransport().
	ProbeTransport http.RoundTripper
	// Log is the structured logger. nil means slog.Default().
	Log *slog.Logger
}

// Controller reconciles MLXModels into the objects that serve them.
//
// Concurrency: two informers feed ONE workqueue drained by a SINGLE worker, so
// every reconcile is serialized by model key and no field below needs a lock. No
// Context is stored — the one Run receives is threaded down.
type Controller struct {
	client    kubernetes.Interface
	dyn       dynamic.Interface
	crd       crdensure.CRDClient
	gpu       GPUSource
	opts      mlx.Options
	domain    string
	pullName  string
	transport http.RoundTripper
	queue     workqueue.TypedRateLimitingInterface[string]
	log       *slog.Logger
	// now is the clock status derivation reads. It is a field so a test can pin
	// condition timestamps; production leaves it at time.Now.
	now func() time.Time
}

// New builds a Controller from cfg. Call Run to start it.
func New(cfg Config) (*Controller, error) {
	if cfg.Client == nil {
		return nil, errors.New("mlx operator: no kubernetes client")
	}
	if cfg.Dynamic == nil {
		return nil, errors.New("mlx operator: no dynamic client")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	transport := cfg.ProbeTransport
	if transport == nil {
		transport = mlx.NewProbeTransport()
	}
	pullName := cfg.PullSecretName
	if pullName == "" {
		pullName = DefaultPullSecretName
	}
	return &Controller{
		client:    cfg.Client,
		dyn:       cfg.Dynamic,
		crd:       cfg.CRD,
		gpu:       cfg.GPU,
		opts:      cfg.Options,
		domain:    cfg.ClusterDomain,
		pullName:  pullName,
		transport: transport,
		queue:     workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		log:       log,
		now:       time.Now,
	}, nil
}

// Run ensures the MLXModel CRD, then reconciles MLXModels until ctx is
// cancelled.
//
// Like pkg/provisioner's, it must be started only AFTER the apiserver is healthy
// and drained (ctx cancelled and Run returned) BEFORE the control plane is torn
// down, so it never issues a write against a draining apiserver. The informers'
// initial sync re-delivers every existing MLXModel as an Add, so a control-plane
// restart re-reconciles each one and strands nothing.
func (c *Controller) Run(ctx context.Context) error {
	if c.crd != nil {
		// Establishment is awaited inside Ensure. Starting the informer before the
		// API server has built the custom resource's REST handler would 404 and
		// retry forever, which reads as a controller that started and sees nothing.
		if _, err := crdensure.Ensure(ctx, c.crd, crdconfig.MLXModelCRD(), crdensure.Options{Log: c.log}); err != nil {
			if ctx.Err() != nil {
				return nil // cancelled mid-ensure: a clean shutdown, not a failure
			}
			return fmt.Errorf("mlx operator: ensure mlxmodel crd: %w", err)
		}
	}

	modelFactory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(c.dyn, resyncPeriod, metav1.NamespaceAll, nil)
	modelInformer := modelFactory.ForResource(mlxModelResource).Informer()
	if _, err := modelInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.enqueue(obj) },
		UpdateFunc: func(_, obj any) { c.enqueue(obj) },
		// No DeleteFunc: the serving objects carry controller ownerReferences, so
		// a deleted MLXModel is cleaned up by garbage collection. A reconcile of a
		// gone object has nothing to do and could only race that collection.
	}); err != nil {
		return fmt.Errorf("mlx operator: add mlxmodel handler: %w", err)
	}

	// The pod informer is what makes readiness visible promptly. Without it the
	// status would only catch up on the resync, so a model that became ready
	// would report Downloading for up to a full resync period.
	podFactory := informers.NewSharedInformerFactoryWithOptions(c.client, resyncPeriod,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = managedPodSelector() }))
	podInformer := podFactory.Core().V1().Pods().Informer()
	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.enqueueOwningModel(obj) },
		UpdateFunc: func(_, obj any) { c.enqueueOwningModel(obj) },
		DeleteFunc: func(obj any) { c.enqueueOwningModel(obj) },
	}); err != nil {
		return fmt.Errorf("mlx operator: add pod handler: %w", err)
	}

	modelFactory.Start(ctx.Done())
	podFactory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), modelInformer.HasSynced, podInformer.HasSynced) {
		if ctx.Err() != nil {
			return nil // ctx cancelled mid-sync — a clean shutdown, not a failure
		}
		return errors.New("mlx operator: informer cache sync failed")
	}

	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for c.processNext(ctx) {
		}
	}()

	<-ctx.Done()
	c.queue.ShutDown() // unblocks the worker's Get
	<-workerDone       // drain the in-flight reconcile before returning
	return nil
}

// managedPodSelector is the label selector narrowing the pod informer to pods
// this operator's own render produced. Watching every pod in the cluster to find
// the handful serving models would make a Mac-sized control plane cache the whole
// pod population for nothing.
func managedPodSelector() string {
	sel := labels.Set{"app.kubernetes.io/name": "mlx-model", "app.kubernetes.io/managed-by": "k3sm"}
	return labels.SelectorFromSet(sel).String()
}

// enqueue adds an object's namespace/name key to the workqueue.
func (c *Controller) enqueue(obj any) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		c.log.Error("mlx operator: derive mlxmodel key", "err", err)
		return
	}
	c.queue.Add(key)
}

// enqueueOwningModel maps a serving pod back to the MLXModel that owns it and
// enqueues THAT.
//
// The mapping goes through the render's own instance label rather than through
// the pod's ownerReferences, because a pod's owner is its StatefulSet, not the
// model — walking to the model would need a second lookup on every pod event.
// A DeletedFinalStateUnknown tombstone is unwrapped: dropping it would lose the
// last event about a replica going away.
func (c *Controller) enqueueOwningModel(obj any) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	instance := pod.Labels["app.kubernetes.io/instance"]
	if instance == "" {
		return
	}
	c.queue.Add(pod.Namespace + "/" + instance)
}

// processNext dequeues one model key and reconciles it, re-queueing with
// rate-limited backoff on a transient error. It returns false only once the
// queue has shut down.
func (c *Controller) processNext(ctx context.Context) bool {
	key, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(key)

	if err := c.Reconcile(ctx, key); err != nil {
		c.log.Error("mlx operator: reconcile mlxmodel", "mlxmodel", key, "err", err)
		c.queue.AddRateLimited(key)
		return true
	}
	c.queue.Forget(key)
	return true
}

// Reconcile brings one MLXModel's serving objects and status into line with its
// spec. It is exported so the whole loop body is testable without starting an
// informer.
//
// A returned error means TRANSIENT: the key is requeued with backoff. A spec
// that cannot be served is NOT an error — it is a status — because requeueing it
// would retry a decision that cannot change until the spec does.
func (c *Controller) Reconcile(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("split mlxmodel key %q: %w", key, err)
	}

	// A direct Get, not a lister read: the status write below is a full update of
	// the object read here, so a stale watch-cache copy would write back a status
	// derived from a spec that has already changed.
	raw, err := c.dyn.Resource(mlxModelResource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil // gone; the owned objects are garbage-collected
	}
	if err != nil {
		return fmt.Errorf("get mlxmodel %s: %w", key, err)
	}
	model, err := toModel(raw)
	if err != nil {
		return fmt.Errorf("decode mlxmodel %s: %w", key, err)
	}
	if model.DeletionTimestamp != nil {
		// Deletion is the garbage collector's job through the ownerReferences.
		// Applying to a terminating object would only recreate what it is removing.
		return nil
	}

	// 1. Fit first. A spec that cannot be funded gets a status and NO objects:
	// applying anyway produces a pod that dies at load time, restarts, and
	// re-downloads from zero, with "never becomes ready" as the only symptom.
	if fit := ValidateFit(model.Spec.Memory, c.gpuFacts(ctx)); fit.Blocks() {
		c.log.Warn("mlxmodel does not fit this node's gpu; no objects applied",
			"mlxmodel", key, "reason", fit.Reason, "message", fit.Message)
		return c.writeStatus(ctx, raw, model, blockedStatus(model, fit, c.now()))
	}

	// 2. Render. A render error is a bad spec, not a busy cluster, so it is
	// reported and not requeued.
	objs, err := mlx.Render(model, c.opts)
	if err != nil {
		c.log.Warn("mlxmodel spec cannot be rendered; no objects applied", "mlxmodel", key, "err", err)
		return c.writeStatus(ctx, raw, model, invalidSpecStatus(model, err, c.now()))
	}

	// 3. Pull secret, only if it exists (see the package doc).
	c.stampPullSecret(ctx, objs, model.Namespace)

	// 4. Apply.
	if err := c.apply(ctx, objs); err != nil {
		return err
	}

	// 5. Observe and report.
	obs, err := c.observe(ctx, model)
	if err != nil {
		return err
	}
	status := mlx.DeriveStatus(model, obs, mlx.StatusOptions{Options: c.opts, ClusterDomain: c.domain}, c.now())
	return c.writeStatus(ctx, raw, model, status)
}

// gpuFacts reads the node GPU facts, tolerating an unconfigured source.
func (c *Controller) gpuFacts(ctx context.Context) *runtimev1.GPUFacts {
	if c.gpu == nil {
		return nil
	}
	return c.gpu.GPUFacts(ctx)
}

// observe builds the status derivation's input from the pods the render's
// selector matches, probing every replica that is running but not yet ready.
//
// Only not-ready replicas are probed, and that is the contract: readiness is what
// gates a replica's address into the ClusterIP Service, so a probe can only
// refine WHY a replica is not ready (still fetching weights versus loading them)
// and must never promote one. Probing ready replicas would spend a round trip per
// reconcile to learn nothing.
func (c *Controller) observe(ctx context.Context, m *mlxv1alpha1.MLXModel) (mlx.Observation, error) {
	pods, err := c.client.CoreV1().Pods(m.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(mlx.Labels(m.Name)).String(),
	})
	if err != nil {
		return mlx.Observation{}, fmt.Errorf("list pods for mlxmodel %s/%s: %w", m.Namespace, m.Name, err)
	}

	obs := mlx.Observation{Pods: make([]mlx.PodState, 0, len(pods.Items))}
	for i := range pods.Items {
		pod := &pods.Items[i]
		state := mlx.PodState{
			Name:  pod.Name,
			Phase: pod.Status.Phase,
			Ready: podReady(pod),
		}
		if !state.Ready && state.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			state.Probe = c.probe(ctx, m, pod.Status.PodIP)
		}
		obs.Pods = append(obs.Pods, state)
	}
	return obs, nil
}

// probe takes one replica's serving-surface verdict. A probe failure is a
// verdict, never an error: the whole point of the probe is that an unreachable
// surface MEANS something (the weights are still coming down).
func (c *Controller) probe(ctx context.Context, m *mlxv1alpha1.MLXModel, podIP string) mlx.ProbeVerdict {
	port := c.opts.DefaultPort
	if m.Spec.Port != 0 {
		port = m.Spec.Port
	}
	if port == 0 {
		return mlx.ProbeUnknown
	}
	base := fmt.Sprintf("http://%s", hostPort(podIP, port))
	return mlx.ProbeOpenAISurface(ctx, c.transport, base, m.Spec.Model, probeTimeout)
}

// podReady reads a pod's Ready condition.
func podReady(pod *corev1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// writeStatus persists status through the status subresource, skipping the write
// when nothing changed.
//
// The skip is not an optimization: every resync re-derives the status of every
// model, so writing unconditionally would generate one apiserver write per model
// per resync forever, and each write is a watch event that re-enqueues the model
// that produced it.
func (c *Controller) writeStatus(ctx context.Context, raw *unstructured.Unstructured, m *mlxv1alpha1.MLXModel, status mlxv1alpha1.MLXModelStatus) error {
	if statusEqual(m.Status, status) {
		return nil
	}
	next := m.DeepCopy()
	next.Status = status
	obj, err := toUnstructured(next)
	if err != nil {
		return fmt.Errorf("encode mlxmodel %s/%s status: %w", m.Namespace, m.Name, err)
	}
	// The resourceVersion is carried from the object that was read, so a
	// concurrent spec change loses the write rather than clobbering it; the
	// resulting conflict is requeued.
	obj.SetResourceVersion(raw.GetResourceVersion())
	if _, err := c.dyn.Resource(mlxModelResource).Namespace(m.Namespace).
		UpdateStatus(ctx, obj, metav1.UpdateOptions{FieldManager: FieldManager}); err != nil {
		return fmt.Errorf("write mlxmodel %s/%s status: %w", m.Namespace, m.Name, err)
	}
	c.log.Debug("wrote mlxmodel status",
		"mlxmodel", m.Namespace+"/"+m.Name, "phase", status.Phase, "observedGeneration", status.ObservedGeneration)
	return nil
}

// blockedStatus is the status of a model the pre-render fit check refused.
//
// Phase is set here rather than derived by mlx.PhaseFromConditions, which maps
// only the pod-derived reasons it owns and would return an empty phase for
// these. Setting it explicitly keeps the printer column truthful without teaching
// the pure package about a decision taken before any pod exists.
func blockedStatus(m *mlxv1alpha1.MLXModel, fit Fit, now time.Time) mlxv1alpha1.MLXModelStatus {
	status := *m.Status.DeepCopy()
	status.ObservedGeneration = m.Generation
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               mlxv1alpha1.MLXModelConditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             fit.Reason,
		Message:            fit.Message,
		ObservedGeneration: m.Generation,
		LastTransitionTime: metav1.NewTime(now),
	})
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               ConditionDegraded,
		Status:             metav1.ConditionTrue,
		Reason:             fit.Reason,
		Message:            fit.Message,
		ObservedGeneration: m.Generation,
		LastTransitionTime: metav1.NewTime(now),
	})
	status.Phase = mlxv1alpha1.MLXModelPhaseFailed
	// An endpoint on a model with no pods is an address a client connects to and
	// hangs on.
	status.Endpoint = ""
	return status
}

// invalidSpecStatus is the status of a model whose spec cannot be rendered.
func invalidSpecStatus(m *mlxv1alpha1.MLXModel, err error, now time.Time) mlxv1alpha1.MLXModelStatus {
	return blockedStatus(m, Fit{
		Level:   FitFailed,
		Reason:  ReasonInvalidSpec,
		Message: err.Error(),
	}, now)
}

// ReasonInvalidSpec means the spec could not be rendered into serving objects at
// all. It is terminal in the same way a fit failure is: nothing changes until the
// spec does.
const ReasonInvalidSpec = "InvalidSpec"

// hostPort joins an IP and port for a URL, bracketing an IPv6 literal.
func hostPort(ip string, port int32) string {
	if isIPv6Literal(ip) {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// isIPv6Literal reports whether ip is an IPv6 address in literal form, which a
// URL must bracket.
func isIPv6Literal(ip string) bool {
	for i := 0; i < len(ip); i++ {
		if ip[i] == ':' {
			return true
		}
	}
	return false
}
