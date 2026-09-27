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

package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	crdconfig "k3sm.io/apis/config/crd"
	helmv1 "k3sm.io/apis/helm/v1"
	"k3sm.io/k3sm/pkg/crdensure"
	"k3sm.io/k3sm/pkg/helmchart"
	"k3sm.io/k3sm/pkg/rbac"
)

// FieldManager is the field manager on every write this controller makes (the
// finalizer and status updates). Its own name, like pkg/mlx/operator's, so it
// never shares ownership with another k3sm writer.
const FieldManager = "k3sm-helm"

// LeaseName and LeaseNamespace name the coordination.k8s.io Lease the
// controller is leader-elected on. Only the holder reconciles: the controller
// deletes Jobs and clears finalizers, which two servers of an HA pair must not
// do at once (pkg/addons' converge-only reconcilers need no election; this one
// is not converge-only).
const (
	LeaseName      = "k3sm-helm-controller"
	LeaseNamespace = "kube-system"
)

// Warning Event reasons recorded on the HelmChart.
const (
	// EventReasonInstallFailed: the install Job failed, or the chart was
	// refused before any Job (InsecureRepo, InvalidChartContent).
	EventReasonInstallFailed = "HelmChartInstallFailed"
	// EventReasonUninstallFailed: the delete Job failed or ran out of time, and
	// the finalizer was cleared anyway.
	EventReasonUninstallFailed = "HelmChartUninstallFailed"
)

// Leader-election timings: the kube-controller-manager defaults. A server that
// dies holding the lease hands it over within LeaseDuration; a clean shutdown
// releases it at once (ReleaseOnCancel).
const (
	defaultLeaseDuration = 15 * time.Second
	defaultRenewDeadline = 10 * time.Second
	defaultRetryPeriod   = 2 * time.Second
)

// resyncPeriod re-delivers every HelmChart periodically, so a reconcile that
// failed for a reason no watch event repeats is retried.
const resyncPeriod = 10 * time.Minute

var (
	helmChartResource       = helmv1.SchemeGroupVersion.WithResource("helmcharts")
	helmChartConfigResource = helmv1.SchemeGroupVersion.WithResource("helmchartconfigs")
)

// Config is everything the controller needs from its caller.
type Config struct {
	// Client is the typed clientset: Jobs, ConfigMaps, the Job identity, the
	// Lease and Events. Required.
	Client kubernetes.Interface
	// Dynamic reads and writes HelmChart and HelmChartConfig objects (apis
	// publishes the types, not a clientset). Required.
	Dynamic dynamic.Interface
	// CRD applies and establishes both helm.k3sm.io CRDs before anything else.
	// nil skips the ensure (something else established them).
	CRD crdensure.CRDClient
	// HelmPath is the staged helm binary every Job runs as command[0]
	// (helmchart.HelmPath under the work dir's bin). Required.
	HelmPath string
	// Identity is this server's leader-election identity: its node name.
	// Required.
	Identity string
	// Recorder records the Warning Events. nil means Run builds one on Client.
	Recorder record.EventRecorder
	// Log is the structured logger. nil means slog.Default().
	Log *slog.Logger
}

// Controller reconciles HelmCharts into helm Jobs.
//
// Concurrency: while this server holds the lease, three informers feed ONE
// workqueue drained by a SINGLE worker, so every reconcile is serialized and no
// field below is written after Run starts leading except recorder, which Run
// sets before the first election. No Context is stored.
type Controller struct {
	client   kubernetes.Interface
	dyn      dynamic.Interface
	crd      crdensure.CRDClient
	helmPath string
	identity string
	recorder record.EventRecorder
	log      *slog.Logger
	// now is the clock status derivation reads; a test pins it.
	now func() time.Time
	// The election timings are fields so a test can shorten them.
	leaseDuration, renewDeadline, retryPeriod time.Duration
}

// New builds a Controller from cfg. Call Run to start it.
func New(cfg Config) (*Controller, error) {
	switch {
	case cfg.Client == nil:
		return nil, errors.New("helm controller: no kubernetes client")
	case cfg.Dynamic == nil:
		return nil, errors.New("helm controller: no dynamic client")
	case cfg.HelmPath == "":
		return nil, errors.New("helm controller: no helm binary path")
	case cfg.Identity == "":
		return nil, errors.New("helm controller: no leader-election identity")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Controller{
		client:        cfg.Client,
		dyn:           cfg.Dynamic,
		crd:           cfg.CRD,
		helmPath:      cfg.HelmPath,
		identity:      cfg.Identity,
		recorder:      cfg.Recorder,
		log:           log,
		now:           time.Now,
		leaseDuration: defaultLeaseDuration,
		renewDeadline: defaultRenewDeadline,
		retryPeriod:   defaultRetryPeriod,
	}, nil
}

// Run ensures both CRDs, then campaigns for the Lease and reconciles
// HelmCharts while it holds it, until ctx is cancelled.
//
// A CRD that cannot be ensured is logged and Run returns nil: HelmChart support
// is an optional surface, and a failure here must not look like a control-plane
// failure to the caller. Like pkg/mlx/operator's Run it is started only after
// the apiserver is healthy and must be drained (ctx cancelled, Run returned)
// before the control plane stops. It returns only after the leading term's
// worker has finished its in-flight reconcile and the Lease is released.
func (c *Controller) Run(ctx context.Context) error {
	if c.crd != nil {
		for _, manifest := range [][]byte{crdconfig.HelmChartCRD(), crdconfig.HelmChartConfigCRD()} {
			if _, err := crdensure.Ensure(ctx, c.crd, manifest, crdensure.Options{Log: c.log}); err != nil {
				if ctx.Err() == nil {
					c.log.Error("helm controller disabled: ensure the helm.k3sm.io CRDs", "err", err)
				}
				return nil
			}
		}
	}
	if c.recorder == nil {
		b := record.NewBroadcaster()
		b.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: c.client.CoreV1().Events("")})
		defer b.Shutdown()
		c.recorder = b.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "k3sm-helm-controller"})
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta:  metav1.ObjectMeta{Name: LeaseName, Namespace: LeaseNamespace},
		Client:     c.client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{Identity: c.identity},
	}
	// A lost lease ends one term; campaign again until shutdown.
	for ctx.Err() == nil {
		if err := c.campaign(ctx, lock); err != nil {
			return err
		}
	}
	return nil
}

// campaign runs one leader-election term: acquire the Lease, lead until it is
// lost or ctx ends, and return only once the leading work has drained.
//
// leaderelection starts OnStartedLeading in its own goroutine and does not wait
// for it, so the drain is done here: started/stopped under mu decide whether
// there is a term to wait for, and a callback that starts after the elector has
// already returned does nothing.
func (c *Controller) campaign(ctx context.Context, lock resourcelock.Interface) error {
	var (
		mu      sync.Mutex
		started bool
		stopped bool
		done    = make(chan struct{})
	)
	le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            lock,
		Name:            LeaseName,
		LeaseDuration:   c.leaseDuration,
		RenewDeadline:   c.renewDeadline,
		RetryPeriod:     c.retryPeriod,
		ReleaseOnCancel: true,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(lctx context.Context) {
				mu.Lock()
				if stopped {
					mu.Unlock()
					return
				}
				started = true
				mu.Unlock()
				defer close(done)
				c.log.Info("helm controller: leading", "lease", LeaseNamespace+"/"+LeaseName, "identity", c.identity)
				if err := c.lead(lctx); err != nil && lctx.Err() == nil {
					c.log.Error("helm controller", "err", err)
				}
			},
			OnStoppedLeading: func() {},
		},
	})
	if err != nil {
		return fmt.Errorf("helm controller: leader election: %w", err)
	}
	le.Run(ctx)
	mu.Lock()
	stopped = true
	wait := started
	mu.Unlock()
	if wait {
		<-done
	}
	return nil
}

// lead runs the informers and the single worker until ctx ends. The
// informer/workqueue scaffold is copied from pkg/mlx/operator, the second
// instance of it; extract a shared one when a third appears.
func (c *Controller) lead(ctx context.Context) error {
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())

	helmFactory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(c.dyn, resyncPeriod, metav1.NamespaceAll, nil)
	chartInformer := helmFactory.ForResource(helmChartResource).Informer()
	if _, err := chartInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { enqueue(queue, obj, c.log) },
		UpdateFunc: func(_, obj any) { enqueue(queue, obj, c.log) },
		// No DeleteFunc: a HelmChart is held by the finalizer until this
		// controller has uninstalled it, so its removal is never news.
	}); err != nil {
		return fmt.Errorf("add helmchart handler: %w", err)
	}
	// A HelmChartConfig overlays the HelmChart of the same name, so its events
	// enqueue that chart's key (a key with no chart no-ops in Reconcile).
	configInformer := helmFactory.ForResource(helmChartConfigResource).Informer()
	if _, err := configInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { enqueue(queue, obj, c.log) },
		UpdateFunc: func(_, obj any) { enqueue(queue, obj, c.log) },
		DeleteFunc: func(obj any) { enqueue(queue, obj, c.log) },
	}); err != nil {
		return fmt.Errorf("add helmchartconfig handler: %w", err)
	}

	// The Job informer is what makes a Job's completion, failure and removal
	// prompt; it watches only Jobs carrying the chart label.
	kubeFactory := informers.NewSharedInformerFactoryWithOptions(c.client, resyncPeriod,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = helmchart.LabelChart }))
	jobInformer := kubeFactory.Batch().V1().Jobs().Informer()
	if _, err := jobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, obj any) { enqueueJobChart(queue, obj) },
		DeleteFunc: func(obj any) { enqueueJobChart(queue, obj) },
	}); err != nil {
		return fmt.Errorf("add job handler: %w", err)
	}

	helmFactory.Start(ctx.Done())
	kubeFactory.Start(ctx.Done())
	defer helmFactory.Shutdown()
	defer kubeFactory.Shutdown()
	if !cache.WaitForCacheSync(ctx.Done(), chartInformer.HasSynced, configInformer.HasSynced, jobInformer.HasSynced) {
		queue.ShutDown()
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("informer cache sync failed")
	}

	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for c.processNext(ctx, queue) {
		}
	}()
	<-ctx.Done()
	queue.ShutDown()
	<-workerDone
	return nil
}

// enqueue adds an object's namespace/name key.
func enqueue(q workqueue.TypedRateLimitingInterface[string], obj any, log *slog.Logger) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		log.Error("helm controller: derive key", "err", err)
		return
	}
	q.Add(key)
}

// enqueueJobChart maps a Job back to its HelmChart through the chart label.
// The label is caller-writable, which is harmless: a key only schedules a
// reconcile that re-reads the chart and no-ops when there is none.
func enqueueJobChart(q workqueue.TypedRateLimitingInterface[string], obj any) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	job, ok := obj.(*batchv1.Job)
	if !ok {
		return
	}
	if name := job.Labels[helmchart.LabelChart]; name != "" {
		q.Add(job.Namespace + "/" + name)
	}
}

// processNext reconciles one key, requeueing with backoff on an error. It
// returns false once the queue has shut down.
func (c *Controller) processNext(ctx context.Context, q workqueue.TypedRateLimitingInterface[string]) bool {
	key, shutdown := q.Get()
	if shutdown {
		return false
	}
	defer q.Done(key)
	if err := c.Reconcile(ctx, key); err != nil {
		c.log.Error("helm controller: reconcile helmchart", "helmchart", key, "err", err)
		q.AddRateLimited(key)
		return true
	}
	q.Forget(key)
	return true
}

// Reconcile brings one HelmChart's Job, ConfigMaps, identity and status in line
// with its spec, or, for a deleted chart, uninstalls it and releases the
// finalizer. It is exported so the loop body is testable without an informer or
// a Lease.
//
// A returned error is transient and requeued. A spec that cannot be installed
// (InsecureRepo, InvalidChartContent) is a status, not an error. A wait (a Job
// still running or still being deleted) returns nil: the Job informer's next
// event for that Job enqueues the chart again.
func (c *Controller) Reconcile(ctx context.Context, key string) error {
	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("split helmchart key %q: %w", key, err)
	}
	raw, err := c.dyn.Resource(helmChartResource).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get helmchart %s: %w", key, err)
	}
	chart, err := toChart(raw)
	if err != nil {
		return fmt.Errorf("decode helmchart %s: %w", key, err)
	}
	if chart.DeletionTimestamp != nil {
		return c.finalize(ctx, raw, chart)
	}
	if !slices.Contains(chart.Finalizers, helmchart.Finalizer) {
		if raw, chart, err = c.addFinalizer(ctx, raw); err != nil {
			return err
		}
	}

	if err := helmchart.ValidateSource(chart.Spec); err != nil {
		return c.refuse(ctx, raw, chart, helmchart.ReasonInsecureRepo, err.Error())
	}
	cfg, err := c.config(ctx, ns, name)
	if err != nil {
		return err
	}
	values, content, err := helmchart.RenderConfigMaps(chart, cfg)
	if errors.Is(err, helmchart.ErrInvalidChartContent) {
		return c.refuse(ctx, raw, chart, helmchart.ReasonInvalidChartContent, err.Error())
	}
	if err != nil {
		return fmt.Errorf("render configmaps for helmchart %s: %w", key, err)
	}
	for _, cm := range []*corev1.ConfigMap{values, content} {
		if cm == nil {
			continue
		}
		if err := c.ensureConfigMap(ctx, cm); err != nil {
			return err
		}
	}
	if err := rbac.ProvisionHelmJobIdentity(ctx, c.client, ns, name); err != nil {
		return err
	}

	job, err := c.ensureInstallJob(ctx, chart, cfg, helmchart.ConfigHash(chart.Spec, cfg))
	if err != nil || job == nil {
		return err
	}
	state := helmchart.StateOf(job)
	status := helmchart.InstallStatus(chart, job, state, c.now())
	if state == helmchart.JobFailed && !failedFor(chart.Status, helmchart.ReasonJobFailed, "") {
		c.warn(raw, EventReasonInstallFailed, fmt.Sprintf(
			"install Job %s/%s failed (backoffLimit or activeDeadlineSeconds reached); failurePolicy %s; see `kubectl logs -n %s job/%s`",
			job.Namespace, job.Name, helmchart.EffectiveFailurePolicy(chart.Spec), job.Namespace, job.Name))
	}
	if err := c.writeStatus(ctx, raw, chart, status); err != nil {
		return err
	}
	if helmchart.ShouldReinstall(chart.Spec, state) {
		// The status above records the failure first; the next reconcile, driven
		// by this Job's delete event, runs the install again.
		return c.deleteJob(ctx, job)
	}
	return nil
}

// refuse records a chart that will not be installed: a Warning Event on the
// transition, and a Failed status with no Job.
func (c *Controller) refuse(ctx context.Context, raw *unstructured.Unstructured, chart *helmv1.HelmChart, reason, message string) error {
	if !failedFor(chart.Status, reason, message) {
		c.warn(raw, EventReasonInstallFailed, message)
	}
	c.log.Warn("helmchart refused; no Job created", "helmchart", chart.Namespace+"/"+chart.Name, "reason", reason, "message", message)
	return c.writeStatus(ctx, raw, chart, helmchart.RefusedStatus(chart, reason, message, c.now()))
}

// failedFor reports whether status already records Failed True with reason
// (and message, when non-empty), so a repeated reconcile of the same failure
// does not repeat its Event.
func failedFor(status helmv1.HelmChartStatus, reason, message string) bool {
	f := helmchart.FindCondition(status.Conditions, helmv1.HelmChartFailed)
	return f != nil && f.Status == metav1.ConditionTrue && f.Reason == reason && (message == "" || f.Message == message)
}

// config reads the HelmChartConfig of the chart's name, or nil without one.
func (c *Controller) config(ctx context.Context, ns, name string) (*helmv1.HelmChartConfig, error) {
	raw, err := c.dyn.Resource(helmChartConfigResource).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get helmchartconfig %s/%s: %w", ns, name, err)
	}
	cfg, err := toConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("decode helmchartconfig %s/%s: %w", ns, name, err)
	}
	return cfg, nil
}

// ensureConfigMap creates want, or updates the existing one when its data,
// labels or owner differ.
func (c *Controller) ensureConfigMap(ctx context.Context, want *corev1.ConfigMap) error {
	api := c.client.CoreV1().ConfigMaps(want.Namespace)
	got, err := api.Get(ctx, want.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, err := api.Create(ctx, want, metav1.CreateOptions{FieldManager: FieldManager}); err != nil {
			return fmt.Errorf("create configmap %s/%s: %w", want.Namespace, want.Name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get configmap %s/%s: %w", want.Namespace, want.Name, err)
	}
	if equality.Semantic.DeepEqual(got.Data, want.Data) && equality.Semantic.DeepEqual(got.BinaryData, want.BinaryData) &&
		equality.Semantic.DeepEqual(got.OwnerReferences, want.OwnerReferences) {
		return nil
	}
	next := got.DeepCopy()
	next.Data, next.BinaryData, next.OwnerReferences = want.Data, want.BinaryData, want.OwnerReferences
	if next.Labels == nil {
		next.Labels = map[string]string{}
	}
	for k, v := range want.Labels {
		next.Labels[k] = v
	}
	if _, err := api.Update(ctx, next, metav1.UpdateOptions{FieldManager: FieldManager}); err != nil {
		return fmt.Errorf("update configmap %s/%s: %w", want.Namespace, want.Name, err)
	}
	return nil
}

// ensureInstallJob returns the chart's current install Job, creating it when
// absent and replacing it when it carries another config hash or belongs to an
// earlier HelmChart of the same name. It returns (nil, nil) while an old Job is
// still being deleted: the Job informer's delete event brings the chart back.
func (c *Controller) ensureInstallJob(ctx context.Context, chart *helmv1.HelmChart, cfg *helmv1.HelmChartConfig, hash string) (*batchv1.Job, error) {
	want := helmchart.RenderJob(chart, cfg, c.helmPath, hash)
	existing, err := c.getJob(ctx, want.Namespace, want.Name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if existing.DeletionTimestamp != nil {
			return nil, nil
		}
		if ownedBy(existing, chart.UID) && existing.Annotations[helmchart.AnnotationConfigHash] == hash {
			return existing, nil
		}
		c.log.Info("replacing helm install Job", "job", existing.Namespace+"/"+existing.Name,
			"hash", existing.Annotations[helmchart.AnnotationConfigHash], "want", hash)
		if err := c.deleteJob(ctx, existing); err != nil {
			return nil, err
		}
		if existing, err = c.getJob(ctx, want.Namespace, want.Name); err != nil || existing != nil {
			return nil, err // still going; wait for its delete event
		}
	}
	created, err := c.client.BatchV1().Jobs(want.Namespace).Create(ctx, want, metav1.CreateOptions{FieldManager: FieldManager})
	if err != nil {
		return nil, fmt.Errorf("create job %s/%s: %w", want.Namespace, want.Name, err)
	}
	c.log.Info("created helm install Job", "job", created.Namespace+"/"+created.Name, "hash", hash)
	return created, nil
}

// ownedBy reports whether job's controller ownerReference is the chart with uid.
func ownedBy(job *batchv1.Job, uid types.UID) bool {
	o := metav1.GetControllerOfNoCopy(job)
	return o != nil && o.UID == uid
}

// getJob returns the named Job, or nil when it does not exist.
func (c *Controller) getJob(ctx context.Context, ns, name string) (*batchv1.Job, error) {
	job, err := c.client.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get job %s/%s: %w", ns, name, err)
	}
	return job, nil
}

// deleteJob deletes job with Foreground propagation, so it disappears only once
// its pods are gone and a replacement never runs beside the old helm. The UID
// precondition keeps a stale read from deleting a newer Job of the same name.
func (c *Controller) deleteJob(ctx context.Context, job *batchv1.Job) error {
	fg := metav1.DeletePropagationForeground
	err := c.client.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
		PropagationPolicy: &fg,
		Preconditions:     &metav1.Preconditions{UID: &job.UID},
	})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete job %s/%s: %w", job.Namespace, job.Name, err)
	}
	return nil
}

// finalize uninstalls a deleted chart's release and releases the finalizer.
//
// Order: the install Job goes first (an uninstall must not race a running
// install), then the delete Job runs as the chart's identity. Complete: the
// identity is removed and the finalizer cleared. Failed or out of time: the
// same, plus a Warning Event naming the manual remedy, because a HelmChart that
// can never be deleted is worse than a release left behind that `helm
// uninstall` removes by hand.
func (c *Controller) finalize(ctx context.Context, raw *unstructured.Unstructured, chart *helmv1.HelmChart) error {
	if !slices.Contains(chart.Finalizers, helmchart.Finalizer) {
		return nil
	}
	ns := chart.Namespace
	install, err := c.getJob(ctx, ns, helmchart.InstallJobName(chart.Name))
	if err != nil {
		return err
	}
	if install != nil {
		if install.DeletionTimestamp == nil {
			if err := c.deleteJob(ctx, install); err != nil {
				return err
			}
		}
		if install, err = c.getJob(ctx, ns, install.Name); err != nil || install != nil {
			return err // wait for its delete event
		}
	}
	if err := rbac.ProvisionHelmJobIdentity(ctx, c.client, ns, chart.Name); err != nil {
		return err
	}

	want := helmchart.RenderJob(chart, nil, c.helmPath, "")
	del, err := c.getJob(ctx, ns, want.Name)
	if err != nil {
		return err
	}
	if del != nil && del.Annotations[helmchart.AnnotationChartUID] != string(chart.UID) {
		// A delete Job an earlier HelmChart of this name left behind: its result
		// says nothing about this chart's release.
		if del.DeletionTimestamp == nil {
			if err := c.deleteJob(ctx, del); err != nil {
				return err
			}
		}
		if del, err = c.getJob(ctx, ns, want.Name); err != nil || del != nil {
			return err
		}
	}
	if del == nil {
		if _, err := c.client.BatchV1().Jobs(ns).Create(ctx, want, metav1.CreateOptions{FieldManager: FieldManager}); err != nil {
			return fmt.Errorf("create job %s/%s: %w", ns, want.Name, err)
		}
		c.log.Info("created helm delete Job", "job", ns+"/"+want.Name)
		return nil
	}
	if del.DeletionTimestamp != nil {
		return nil
	}
	switch helmchart.StateOf(del) {
	case helmchart.JobRunning:
		return nil
	case helmchart.JobFailed:
		release, target := chart.Name, helmchart.TargetNamespace(chart)
		c.warn(raw, EventReasonUninstallFailed, fmt.Sprintf(
			"delete Job %s/%s failed (backoffLimit or activeDeadlineSeconds reached); the finalizer is cleared so the HelmChart goes away, but release %s may remain in namespace %s: remove it with `helm uninstall %s -n %s`",
			ns, del.Name, release, target, release, target))
		c.log.Warn("helm uninstall failed; finalizer force-cleared", "helmchart", ns+"/"+chart.Name, "job", del.Name)
	}
	if err := rbac.DeleteHelmJobIdentity(ctx, c.client, ns, chart.Name); err != nil {
		return err
	}
	return c.removeFinalizer(ctx, raw)
}

// addFinalizer adds helmchart.Finalizer and returns the updated object.
func (c *Controller) addFinalizer(ctx context.Context, raw *unstructured.Unstructured) (*unstructured.Unstructured, *helmv1.HelmChart, error) {
	next := raw.DeepCopy()
	next.SetFinalizers(append(next.GetFinalizers(), helmchart.Finalizer))
	updated, err := c.dyn.Resource(helmChartResource).Namespace(next.GetNamespace()).
		Update(ctx, next, metav1.UpdateOptions{FieldManager: FieldManager})
	if err != nil {
		return nil, nil, fmt.Errorf("add finalizer to helmchart %s/%s: %w", raw.GetNamespace(), raw.GetName(), err)
	}
	chart, err := toChart(updated)
	if err != nil {
		return nil, nil, fmt.Errorf("decode helmchart %s/%s: %w", raw.GetNamespace(), raw.GetName(), err)
	}
	return updated, chart, nil
}

// removeFinalizer drops helmchart.Finalizer, which lets the apiserver remove
// the chart.
func (c *Controller) removeFinalizer(ctx context.Context, raw *unstructured.Unstructured) error {
	next := raw.DeepCopy()
	next.SetFinalizers(slices.DeleteFunc(next.GetFinalizers(), func(f string) bool { return f == helmchart.Finalizer }))
	if _, err := c.dyn.Resource(helmChartResource).Namespace(next.GetNamespace()).
		Update(ctx, next, metav1.UpdateOptions{FieldManager: FieldManager}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("remove finalizer from helmchart %s/%s: %w", raw.GetNamespace(), raw.GetName(), err)
	}
	return nil
}

// writeStatus persists status through the status subresource, skipping the
// write when nothing changed (every resync re-derives every chart's status).
// The resourceVersion read is carried, so a concurrent change loses this write
// to a conflict that is requeued rather than clobbered.
func (c *Controller) writeStatus(ctx context.Context, raw *unstructured.Unstructured, chart *helmv1.HelmChart, status helmv1.HelmChartStatus) error {
	if equality.Semantic.DeepEqual(chart.Status, status) {
		return nil
	}
	next := chart.DeepCopy()
	next.Status = status
	obj, err := toUnstructured(next)
	if err != nil {
		return fmt.Errorf("encode helmchart %s/%s status: %w", chart.Namespace, chart.Name, err)
	}
	obj.SetResourceVersion(raw.GetResourceVersion())
	if _, err := c.dyn.Resource(helmChartResource).Namespace(chart.Namespace).
		UpdateStatus(ctx, obj, metav1.UpdateOptions{FieldManager: FieldManager}); err != nil {
		return fmt.Errorf("write helmchart %s/%s status: %w", chart.Namespace, chart.Name, err)
	}
	return nil
}

// warn records a Warning Event on the chart. Before Run has built a recorder
// (a direct Reconcile with none configured) it only logs.
func (c *Controller) warn(raw *unstructured.Unstructured, reason, message string) {
	if c.recorder == nil {
		c.log.Warn("helmchart event", "helmchart", raw.GetNamespace()+"/"+raw.GetName(), "reason", reason, "message", message)
		return
	}
	c.recorder.Event(raw, corev1.EventTypeWarning, reason, message)
}
