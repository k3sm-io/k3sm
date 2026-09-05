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

package provisioner

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagek8s "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	storagev1 "k3sm.io/apis/storage/v1"
)

const (
	// annSelectedNode is the well-known annotation the kube-scheduler stamps on a
	// WaitForFirstConsumer PVC naming the node it placed the consuming pod on. The
	// provisioner pins the PV's nodeAffinity to that node. client-go does not export
	// the key, so it is named here; it is API-stable.
	annSelectedNode = "volume.kubernetes.io/selected-node"
	// annProvisionedBy records which provisioner created a PV (the standard
	// pv.kubernetes.io/provisioned-by key; informational).
	annProvisionedBy = "pv.kubernetes.io/provisioned-by"
	// managedLabel marks the StorageClass and PersistentVolume objects the k3sm
	// provisioner owns.
	managedLabel = "k3sm.io/managed"
	// resyncPeriod re-delivers every PVC periodically so a reconcile that failed
	// transiently (an apiserver hiccup) is retried even absent a new PVC event.
	resyncPeriod = 10 * time.Minute
)

// ClassForRoot returns the k3sm local-path class with its BasePath set to the
// RESOLVED storage root (<runtimeRoot>/storage) — the directory runtimed derives
// its per-PVC dirs against (runtimed/pkg/runtime: filepath.Join(Config.Root,
// "storage")). Passing the resolved runtime root (NOT storagev1.DefaultBasePath,
// which is the root-only /var/lib/k3sm/storage) keeps the advisory PV path aligned
// with where runtimed actually creates the directory under the unprivileged _k3sm
// home.
//
// Install invariant: every node's _k3sm home — hence its runtime root — is the
// SAME absolute path across the cluster, so this single advisory path is valid
// cluster-wide (`k3sm install` enforces the homogeneous-home invariant).
func ClassForRoot(runtimeRoot string) storagev1.LocalPathClass {
	class := storagev1.DefaultLocalPathClass()
	class.BasePath = filepath.Join(runtimeRoot, "storage")
	return class
}

// Controller is the k3sm APFS local-path provisioner: an in-process,
// API-object-only controller (NOT a kube-controller-manager controller) that
// registers the local-path StorageClass and creates a node-pinned, Retain
// PersistentVolume for each PVC the scheduler has placed on a node. It does NO
// filesystem I/O at the PV path — runtimed empty-creates the per-(namespace,
// claim) dir on the consuming node. See the package doc.
//
// Concurrency: the informer and a single workqueue worker serialize reconciles by
// PVC key, so no shared mutable state needs a lock. No Context is stored.
type Controller struct {
	client kubernetes.Interface
	class  storagev1.LocalPathClass
	queue  workqueue.TypedRateLimitingInterface[string]
	log    *slog.Logger
}

// New builds a provisioner Controller over client for class. class.BasePath must
// be the resolved storage root (use ClassForRoot), not storagev1.DefaultBasePath.
// Call Run to start it.
func New(client kubernetes.Interface, class storagev1.LocalPathClass, log *slog.Logger) *Controller {
	if log == nil {
		log = slog.Default()
	}
	return &Controller{
		client: client,
		class:  class.WithDefaults(),
		queue:  workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		log:    log,
	}
}

// Run registers the StorageClass, then watches PVCs and provisions PVs until ctx
// is cancelled. It must be started only AFTER the apiserver is healthy and drained
// (ctx cancelled and Run returned) BEFORE the control plane is torn down, so it
// never issues a PV write against a draining apiserver — see cmd/k3sm/server.go.
// The informer's initial sync re-delivers every existing PVC as an Add, so a
// control-plane restart re-reconciles each one (check-before-create) and strands
// nothing.
func (c *Controller) Run(ctx context.Context) error {
	if err := EnsureStorageClass(ctx, c.client, c.class); err != nil {
		return err
	}

	factory := informers.NewSharedInformerFactory(c.client, resyncPeriod)
	pvcInformer := factory.Core().V1().PersistentVolumeClaims().Informer()
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.enqueue(obj) },
		UpdateFunc: func(_, obj any) { c.enqueue(obj) },
		// No DeleteFunc: under Retain the provisioner never deletes a PV, and a
		// deleted PVC needs no provisioning action.
	}
	if _, err := pvcInformer.AddEventHandler(handler); err != nil {
		return fmt.Errorf("provisioner: add pvc handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), pvcInformer.HasSynced) {
		if ctx.Err() != nil {
			return nil // ctx cancelled mid-sync — a clean shutdown, not a failure
		}
		return fmt.Errorf("provisioner: pvc informer cache sync failed")
	}

	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		c.runWorker(ctx)
	}()

	<-ctx.Done()
	c.queue.ShutDown() // unblocks the worker's Get
	<-workerDone       // drain the in-flight reconcile before returning
	return nil
}

// enqueue adds a PVC's namespace/name key to the workqueue. An object without
// usable metadata is dropped — there is nothing to reconcile.
func (c *Controller) enqueue(obj any) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		c.log.Error("provisioner: derive pvc key", "err", err)
		return
	}
	c.queue.Add(key)
}

// runWorker processes the workqueue until it shuts down.
func (c *Controller) runWorker(ctx context.Context) {
	for c.processNext(ctx) {
	}
}

// processNext dequeues one PVC key and reconciles it, re-queueing with rate-limited
// backoff on a transient error so a flaky Create is retried. It returns false only
// once the queue has shut down.
func (c *Controller) processNext(ctx context.Context) bool {
	key, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(key)

	if err := c.reconcile(ctx, key); err != nil {
		c.log.Error("provisioner: reconcile pvc", "pvc", key, "err", err)
		c.queue.AddRateLimited(key)
		return true
	}
	c.queue.Forget(key)
	return true
}

// reconcile provisions the PV for the PVC named by key when it belongs to the
// local-path class and the scheduler has selected a node. It reads the PVC via a
// direct Get (authoritative regardless of watch-cache staleness); the
// UID-derived PV name keeps the subsequent Create idempotent either way.
func (c *Controller) reconcile(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("split pvc key %q: %w", key, err)
	}
	pvc, err := c.client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil // PVC gone; Retain leaves any PV for manual reclamation
	}
	if err != nil {
		return fmt.Errorf("get pvc %s: %w", key, err)
	}
	return c.provision(ctx, pvc)
}

// provision creates the backing PersistentVolume for pvc when it needs one: it
// belongs to the local-path class, is still unbound, and the scheduler has stamped
// the selected-node annotation (WaitForFirstConsumer). Any other state is a no-op.
func (c *Controller) provision(ctx context.Context, pvc *corev1.PersistentVolumeClaim) error {
	if storageClassOf(pvc) != c.class.Name {
		return nil // not ours
	}
	if pvc.Spec.VolumeName != "" {
		return nil // already bound
	}
	selectedNode := pvc.Annotations[annSelectedNode]
	if selectedNode == "" {
		return nil // WaitForFirstConsumer: wait for the scheduler; an update re-enqueues
	}

	pv, err := buildPV(pvc, c.class, selectedNode)
	if err != nil {
		return err
	}
	if _, err := c.client.CoreV1().PersistentVolumes().Create(ctx, pv, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil // idempotent replay
		}
		return fmt.Errorf("create pv %s for pvc %s/%s: %w", pv.Name, pvc.Namespace, pvc.Name, err)
	}
	c.log.Info("provisioned local-path PersistentVolume",
		"pv", pv.Name, "pvc", pvc.Namespace+"/"+pvc.Name, "node", selectedNode, "path", pv.Spec.Local.Path)
	return nil
}

// storageClassOf returns the PVC's effective StorageClass name (the spec field;
// the deprecated beta annotation is not honored).
func storageClassOf(pvc *corev1.PersistentVolumeClaim) string {
	if pvc.Spec.StorageClassName != nil {
		return *pvc.Spec.StorageClassName
	}
	return ""
}

// buildPV constructs the PersistentVolume object for pvc on selectedNode: the
// UID-derived name (storagev1.PVName), Retain reclaim, the capacity the PVC
// requested, the advisory local path (storagev1.DataDir on the resolved root),
// nodeAffinity pinned to selectedNode (storagev1.NodeTopology), and a ClaimRef
// pre-binding it to THIS PVC incarnation (by UID) so the in-tree binder binds them
// and no other PVC steals the volume. It creates NO directory — runtimed does
// that on the node, keyed by the same (namespace, claim).
func buildPV(pvc *corev1.PersistentVolumeClaim, class storagev1.LocalPathClass, selectedNode string) (*corev1.PersistentVolume, error) {
	pvName, err := storagev1.PVName(string(pvc.UID))
	if err != nil {
		return nil, fmt.Errorf("derive pv name: %w", err)
	}
	dataDir, err := class.DataDir(pvc.Namespace, pvc.Name)
	if err != nil {
		return nil, fmt.Errorf("derive data dir: %w", err)
	}
	topo := storagev1.NodeTopology{NodeName: selectedNode}.WithDefaults()
	if err := topo.Validate(); err != nil {
		return nil, fmt.Errorf("node topology: %w", err)
	}

	accessModes := pvc.Spec.AccessModes
	if len(accessModes) == 0 {
		accessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}
	}

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:        pvName,
			Labels:      map[string]string{managedLabel: "true"},
			Annotations: map[string]string{annProvisionedBy: class.Provisioner},
		},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: pvc.Spec.Resources.Requests[corev1.ResourceStorage],
			},
			AccessModes:                   accessModes,
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimPolicy(class.ReclaimPolicy),
			StorageClassName:              class.Name,
			VolumeMode:                    pvc.Spec.VolumeMode,
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				Local: &corev1.LocalVolumeSource{Path: dataDir},
			},
			NodeAffinity: &corev1.VolumeNodeAffinity{
				Required: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      topo.Key,
							Operator: corev1.NodeSelectorOpIn,
							Values:   []string{topo.NodeName},
						}},
					}},
				},
			},
			ClaimRef: &corev1.ObjectReference{
				Kind:       "PersistentVolumeClaim",
				APIVersion: "v1",
				Namespace:  pvc.Namespace,
				Name:       pvc.Name,
				UID:        pvc.UID,
			},
		},
	}
	return pv, nil
}

// EnsureStorageClass idempotently registers the k3sm local-path StorageClass: the
// provisioner identity, Retain reclaim (k3sm has no volume-delete path, so a
// Delete class would strand Released PVs and leak their dirs onto the APFS volume
// kine's SQLite shares), and WaitForFirstConsumer binding (so the scheduler picks
// the node before the PV is created and node-affinity-pinned). It rejects an
// unsupported class shape fail-fast (LocalPathClass.Validate) and treats
// AlreadyExists as success, so it is safe on every server start.
func EnsureStorageClass(ctx context.Context, cs kubernetes.Interface, class storagev1.LocalPathClass) error {
	class = class.WithDefaults()
	if err := class.Validate(); err != nil {
		return fmt.Errorf("provisioner: %w", err)
	}
	sc := storageClassObject(class)
	if _, err := cs.StorageV1().StorageClasses().Create(ctx, sc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %s storage class: %w", class.Name, err)
	}
	return nil
}

// storageClassObject renders the upstream storage.k8s.io StorageClass from the
// k3sm contract. The class is NOT marked default (no
// storageclass.kubernetes.io/is-default-class): a workload opts in explicitly via
// storageClassName: local-path, so a PVC that did not ask for node-local storage
// is never silently bound to it.
func storageClassObject(class storagev1.LocalPathClass) *storagek8s.StorageClass {
	reclaim := corev1.PersistentVolumeReclaimPolicy(class.ReclaimPolicy)
	binding := storagek8s.VolumeBindingMode(class.VolumeBindingMode)
	return &storagek8s.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:   class.Name,
			Labels: map[string]string{managedLabel: "true"},
		},
		Provisioner:       class.Provisioner,
		ReclaimPolicy:     &reclaim,
		VolumeBindingMode: &binding,
		Parameters:        class.Parameters,
	}
}
