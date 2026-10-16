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

package updatectl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	crdconfig "k3sm.io/apis/config/crd"
	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/crdensure"
)

// The leader Lease. One server rolls the cluster at a time; the status is the
// whole state, so a new leader resumes the roll where the last one stopped.
const (
	LeaseName      = "k3sm-update-controller"
	LeaseNamespace = "kube-system"
)

// Defaults for the Config durations.
const (
	defaultDrainTimeout = 10 * time.Minute
	defaultNodeTimeout  = 30 * time.Minute
	defaultPoll         = 5 * time.Second
	idleResync          = time.Minute
	errorBackoff        = 10 * time.Second
	crdRetry            = 5 * time.Second
)

// updateResource is the Update GVR the dynamic client reads and writes.
var updateResource = schema.GroupVersionResource{
	Group: updatesv1alpha1.GroupName, Version: updatesv1alpha1.SchemeGroupVersion.Version, Resource: "updates",
}

// Config is everything the controller needs from its caller.
type Config struct {
	// Client is the typed clientset for Nodes, Pods, evictions and the Lease.
	// Required.
	Client kubernetes.Interface
	// Dynamic reads and writes the Update objects (apis publishes the types,
	// no generated clientset). Required.
	Dynamic dynamic.Interface
	// CRD applies and establishes the Update CRD before the controller starts.
	// nil skips the ensure.
	CRD crdensure.CRDClient
	// Resolver resolves the target release. nil means HTTPResolver{}.
	Resolver Resolver
	// ServerNode is the Node this controller runs on. It is updated last.
	// Required.
	ServerNode string
	// Identity names this server in the leader Lease. Empty means ServerNode.
	Identity string
	// DrainTimeout bounds a node's drain, counted from the moment it left
	// Pending. Zero means 10 minutes.
	DrainTimeout time.Duration
	// NodeTimeout bounds a node's whole update, counted from the moment it left
	// Pending. Zero means 30 minutes.
	NodeTimeout time.Duration
	// Poll is how often an in-progress roll is re-read. Zero means 5 seconds.
	Poll time.Duration
	// Now is the clock. nil means time.Now.
	Now func() time.Time
	// Log is the structured logger. nil means slog.Default().
	Log *slog.Logger
}

// Controller reconciles the singleton Update.
//
// Concurrency: one loop goroutine runs every reconcile; the informers only
// signal kick. No field is written after New, so none needs a lock.
type Controller struct {
	cfg  Config
	log  *slog.Logger
	kick chan struct{}
}

// New builds a Controller from cfg. Call Run to start it.
func New(cfg Config) (*Controller, error) {
	if cfg.Client == nil {
		return nil, errors.New("update controller: no kubernetes client")
	}
	if cfg.Dynamic == nil {
		return nil, errors.New("update controller: no dynamic client")
	}
	if cfg.ServerNode == "" {
		return nil, errors.New("update controller: no server node name")
	}
	if cfg.Resolver == nil {
		cfg.Resolver = HTTPResolver{}
	}
	if cfg.Identity == "" {
		cfg.Identity = cfg.ServerNode
	}
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = defaultDrainTimeout
	}
	if cfg.NodeTimeout <= 0 {
		cfg.NodeTimeout = defaultNodeTimeout
	}
	if cfg.Poll <= 0 {
		cfg.Poll = defaultPoll
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Controller{cfg: cfg, log: log, kick: make(chan struct{}, 1)}, nil
}

// Run ensures the Update CRD (retrying until it takes), then campaigns for the
// Lease and reconciles while it leads, until ctx ends. Start it only once the
// apiserver is healthy, and drain it before the control plane stops.
func (c *Controller) Run(ctx context.Context) error {
	if c.cfg.CRD != nil {
		for {
			_, err := crdensure.Ensure(ctx, c.cfg.CRD, crdconfig.UpdateCRD(), crdensure.Options{Log: c.log})
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return nil
			}
			c.log.Error("update controller: ensure the update crd; retrying", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(crdRetry):
			}
		}
	}
	lock := &resourcelock.LeaseLock{
		LeaseMeta:  metav1.ObjectMeta{Name: LeaseName, Namespace: LeaseNamespace},
		Client:     c.cfg.Client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{Identity: c.cfg.Identity},
	}
	for ctx.Err() == nil {
		le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:            lock,
			LeaseDuration:   15 * time.Second,
			RenewDeadline:   10 * time.Second,
			RetryPeriod:     2 * time.Second,
			ReleaseOnCancel: true,
			Name:            LeaseName,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: c.lead,
				OnStoppedLeading: func() {},
			},
		})
		if err != nil {
			return fmt.Errorf("update controller: leader election: %w", err)
		}
		le.Run(ctx) // returns when leadership is lost or ctx ends
	}
	return nil
}

// lead runs the reconcile loop for one leadership term.
func (c *Controller) lead(ctx context.Context) {
	signal := func() {
		select {
		case c.kick <- struct{}{}:
		default:
		}
	}
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { signal() },
		UpdateFunc: func(any, any) { signal() },
		DeleteFunc: func(any) { signal() },
	}
	updFactory := dynamicinformer.NewDynamicSharedInformerFactory(c.cfg.Dynamic, idleResync)
	updInf := updFactory.ForResource(updateResource).Informer()
	kubeFactory := informers.NewSharedInformerFactory(c.cfg.Client, idleResync)
	nodeInf := kubeFactory.Core().V1().Nodes().Informer()
	if _, err := updInf.AddEventHandler(handler); err != nil {
		c.log.Error("update controller: add update handler", "err", err)
	}
	if _, err := nodeInf.AddEventHandler(handler); err != nil {
		c.log.Error("update controller: add node handler", "err", err)
	}
	updFactory.Start(ctx.Done())
	kubeFactory.Start(ctx.Done())
	defer updFactory.Shutdown()
	defer kubeFactory.Shutdown()

	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.kick:
		case <-timer.C:
		}
		next, err := c.reconcile(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Error("update controller: reconcile", "err", err)
			next = errorBackoff
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(next)
	}
}

// reconcile is one pass over every Update. It returns when the next pass is
// due.
func (c *Controller) reconcile(ctx context.Context) (time.Duration, error) {
	list, err := c.cfg.Dynamic.Resource(updateResource).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("list updates: %w", err)
	}
	next := idleResync
	for i := range list.Items {
		u, err := decodeUpdate(&list.Items[i])
		if err != nil {
			c.log.Error("update controller: decode update", "name", list.Items[i].GetName(), "err", err)
			continue
		}
		before := u.Status.DeepCopy()
		if u.Name != updatesv1alpha1.UpdateName {
			c.notTheSingleton(u)
		} else {
			if d := c.roll(ctx, u); d < next {
				next = d
			}
		}
		if apiequality.Semantic.DeepEqual(before, &u.Status) {
			continue
		}
		if err := c.writeStatus(ctx, u); err != nil {
			if apierrors.IsConflict(err) {
				next = 0 // re-read and redo; every step is idempotent
				continue
			}
			return 0, err
		}
	}
	return next, nil
}

// notTheSingleton records that an Update under another name is ignored.
func (c *Controller) notTheSingleton(u *updatesv1alpha1.Update) {
	u.Status.ObservedGeneration = u.Generation
	c.setCondition(u, updatesv1alpha1.UpdateConditionReconciled, metav1.ConditionFalse,
		updatesv1alpha1.UpdateReasonNotTheSingleton,
		fmt.Sprintf("only the Update named %q is reconciled", updatesv1alpha1.UpdateName))
}

// decodeUpdate converts a dynamic object into the typed Update.
func decodeUpdate(obj *unstructured.Unstructured) (*updatesv1alpha1.Update, error) {
	u := &updatesv1alpha1.Update{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, u); err != nil {
		return nil, err
	}
	return u, nil
}

// writeStatus writes u's status through the status subresource.
func (c *Controller) writeStatus(ctx context.Context, u *updatesv1alpha1.Update) error {
	u.APIVersion = updatesv1alpha1.SchemeGroupVersion.String()
	u.Kind = "Update"
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(u)
	if err != nil {
		return fmt.Errorf("encode update %s: %w", u.Name, err)
	}
	if _, err := c.cfg.Dynamic.Resource(updateResource).UpdateStatus(ctx, &unstructured.Unstructured{Object: obj}, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("write update %s status: %w", u.Name, err)
	}
	return nil
}
