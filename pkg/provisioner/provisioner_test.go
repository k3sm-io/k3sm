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
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagek8s "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	storagev1 "k3sm.io/apis/storage/v1"
)

// M3.2 APFS local-path provisioner. These unit tests prove the controller logic
// and the StorageClass/PV shapes against a fake apiserver (no root, no real FS);
// the live "write data → restart → same data" persistence run is the M3 two-Mac
// lab e2e (the M3.2-a1 acceptance gate).

// testRoot is a RESOLVED storage root under an unprivileged _k3sm home — NOT the
// root-only storagev1.DefaultBasePath — so the tests exercise ClassForRoot's
// derivation rather than the hardcoded /var/lib/k3sm path.
const testRoot = "/Users/_k3sm/storage"

// testClass returns the default local-path class rooted at testRoot.
func testClass() storagev1.LocalPathClass {
	c := storagev1.DefaultLocalPathClass()
	c.BasePath = testRoot
	return c
}

// boundPVC builds a Pending PVC of the local-path class with the scheduler's
// selected-node annotation set to node (the WaitForFirstConsumer trigger).
func boundPVC(ns, name, uid, node string) *corev1.PersistentVolumeClaim {
	scName := storagev1.DefaultStorageClassName
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			UID:       types.UID(uid),
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: &scName,
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")},
			},
		},
	}
	if node != "" {
		pvc.Annotations = map[string]string{annSelectedNode: node}
	}
	return pvc
}

// TestProvisionerCreatesPVForBoundPVC asserts the core M3.2-a1 reconcile: a PVC
// the scheduler has placed yields a PV with a UID-derived name, Retain reclaim,
// the advisory path on the resolved root, nodeAffinity pinned to the selected
// node, the requested capacity, and a ClaimRef pre-binding it to the PVC. It also
// covers the WaitForFirstConsumer defer and the foreign-class skip.
func TestProvisionerCreatesPVForBoundPVC(t *testing.T) {
	ctx := context.Background()

	t.Run("selected node creates a pinned Retain PV named from the PVC UID", func(t *testing.T) {
		pvc := boundPVC("stockkitty", "postgres-data", "uid-1234", "studio-1")
		cs := fake.NewSimpleClientset(pvc)
		c := New(cs, testClass(), nil)

		if err := c.reconcile(ctx, "stockkitty/postgres-data"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}

		pv, err := cs.CoreV1().PersistentVolumes().Get(ctx, "pvc-uid-1234", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("expected PV pvc-uid-1234 to be created: %v", err)
		}
		if pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain {
			t.Errorf("reclaimPolicy = %q, want Retain", pv.Spec.PersistentVolumeReclaimPolicy)
		}
		if pv.Spec.StorageClassName != storagev1.DefaultStorageClassName {
			t.Errorf("storageClassName = %q, want %q", pv.Spec.StorageClassName, storagev1.DefaultStorageClassName)
		}
		// Advisory path is derived from the RESOLVED root, keyed by (ns, claim) —
		// the same derivation runtimed performs on the node.
		wantPath := testRoot + "/stockkitty/postgres-data"
		if pv.Spec.Local == nil || pv.Spec.Local.Path != wantPath {
			t.Errorf("local path = %+v, want %q", pv.Spec.Local, wantPath)
		}
		// nodeAffinity pins the PV (hence the consuming pod) to the selected node.
		aff := pv.Spec.NodeAffinity
		if aff == nil || aff.Required == nil || len(aff.Required.NodeSelectorTerms) != 1 {
			t.Fatalf("missing required nodeAffinity: %+v", aff)
		}
		me := aff.Required.NodeSelectorTerms[0].MatchExpressions
		if len(me) != 1 || me[0].Key != storagev1.TopologyKeyHostname ||
			me[0].Operator != corev1.NodeSelectorOpIn || len(me[0].Values) != 1 || me[0].Values[0] != "studio-1" {
			t.Errorf("nodeAffinity match = %+v, want %s In [studio-1]", me, storagev1.TopologyKeyHostname)
		}
		// Capacity echoes the request (best-effort; not enforced vs free space).
		if got := pv.Spec.Capacity[corev1.ResourceStorage]; got.Cmp(resource.MustParse("1Gi")) != 0 {
			t.Errorf("capacity = %s, want 1Gi", got.String())
		}
		// ClaimRef pre-binds the PV to this exact PVC incarnation (by UID).
		if cr := pv.Spec.ClaimRef; cr == nil || cr.UID != types.UID("uid-1234") || cr.Name != "postgres-data" || cr.Namespace != "stockkitty" {
			t.Errorf("claimRef = %+v, want bound to stockkitty/postgres-data uid-1234", pv.Spec.ClaimRef)
		}
	})

	t.Run("no selected node defers provisioning (WaitForFirstConsumer)", func(t *testing.T) {
		pvc := boundPVC("stockkitty", "redis-data", "uid-5678", "") // no annotation
		cs := fake.NewSimpleClientset(pvc)
		c := New(cs, testClass(), nil)

		if err := c.reconcile(ctx, "stockkitty/redis-data"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		pvs, _ := cs.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
		if len(pvs.Items) != 0 {
			t.Errorf("provisioned %d PVs before the scheduler selected a node, want 0", len(pvs.Items))
		}
	})

	t.Run("foreign storage class is ignored", func(t *testing.T) {
		pvc := boundPVC("stockkitty", "ebs-data", "uid-9999", "studio-1")
		other := "fast-ssd"
		pvc.Spec.StorageClassName = &other
		cs := fake.NewSimpleClientset(pvc)
		c := New(cs, testClass(), nil)

		if err := c.reconcile(ctx, "stockkitty/ebs-data"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		pvs, _ := cs.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
		if len(pvs.Items) != 0 {
			t.Errorf("provisioned %d PVs for a foreign class, want 0", len(pvs.Items))
		}
	})

	t.Run("a deleted PVC is a no-op", func(t *testing.T) {
		cs := fake.NewSimpleClientset() // PVC absent
		c := New(cs, testClass(), nil)
		if err := c.reconcile(ctx, "stockkitty/gone"); err != nil {
			t.Fatalf("reconcile of a missing PVC must be a no-op, got %v", err)
		}
	})
}

// TestProvisionerIdempotentReplay asserts a duplicate reconcile is a no-op, not a
// double-create — the property that makes a stale watch-cache re-delivery (under
// kine's watch-staleness posture) and a control-plane restart safe: the PV name is
// derived from the immutable PVC UID, so the replay's Create is AlreadyExists.
func TestProvisionerIdempotentReplay(t *testing.T) {
	ctx := context.Background()
	pvc := boundPVC("stockkitty", "postgres-data", "uid-1234", "studio-1")
	cs := fake.NewSimpleClientset(pvc)
	c := New(cs, testClass(), nil)

	for i := 0; i < 3; i++ {
		if err := c.reconcile(ctx, "stockkitty/postgres-data"); err != nil {
			t.Fatalf("reconcile #%d: %v", i, err)
		}
	}
	pvs, err := cs.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pvs.Items) != 1 {
		t.Fatalf("idempotent replay created %d PVs, want exactly 1", len(pvs.Items))
	}
	if pvs.Items[0].Name != "pvc-uid-1234" {
		t.Errorf("PV name = %q, want pvc-uid-1234 (UID-derived, replay-stable)", pvs.Items[0].Name)
	}
}

// TestLocalPathStorageClassRetain asserts the registered StorageClass advertises
// the k3sm-mandated policies: the k3sm provisioner identity, reclaimPolicy: Retain
// (NOT the k8s Delete default — k3sm has no volume-delete path), and
// volumeBindingMode: WaitForFirstConsumer (so the scheduler picks the node first).
func TestLocalPathStorageClassRetain(t *testing.T) {
	ctx := context.Background()

	t.Run("advertises Retain + WaitForFirstConsumer + the k3sm provisioner", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		if err := EnsureStorageClass(ctx, cs, testClass()); err != nil {
			t.Fatalf("ensure: %v", err)
		}
		sc, err := cs.StorageV1().StorageClasses().Get(ctx, storagev1.DefaultStorageClassName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get storage class: %v", err)
		}
		if sc.Provisioner != storagev1.ProvisionerName {
			t.Errorf("provisioner = %q, want %q", sc.Provisioner, storagev1.ProvisionerName)
		}
		if sc.ReclaimPolicy == nil || *sc.ReclaimPolicy != corev1.PersistentVolumeReclaimRetain {
			t.Errorf("reclaimPolicy = %v, want Retain (k3sm has no volume-delete path)", sc.ReclaimPolicy)
		}
		if sc.VolumeBindingMode == nil || *sc.VolumeBindingMode != storagek8s.VolumeBindingWaitForFirstConsumer {
			t.Errorf("volumeBindingMode = %v, want WaitForFirstConsumer", sc.VolumeBindingMode)
		}
		// Not marked the cluster default: a workload opts in via storageClassName.
		if sc.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" {
			t.Error("local-path must NOT be the default class (opt-in via storageClassName)")
		}
	})

	t.Run("idempotent on a second ensure", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		if err := EnsureStorageClass(ctx, cs, testClass()); err != nil {
			t.Fatalf("first ensure: %v", err)
		}
		if err := EnsureStorageClass(ctx, cs, testClass()); err != nil {
			t.Fatalf("second ensure must be a no-op (AlreadyExists), got %v", err)
		}
	})

	t.Run("rejects an unsupported (Delete) class fail-fast", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		bad := testClass()
		bad.ReclaimPolicy = storagev1.ReclaimDelete
		err := EnsureStorageClass(ctx, cs, bad)
		if !errors.Is(err, storagev1.ErrInvalid) {
			t.Fatalf("ensure of a Delete class err = %v, want ErrInvalid", err)
		}
		scs, _ := cs.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
		if len(scs.Items) != 0 {
			t.Errorf("a rejected class must create nothing, found %d StorageClasses", len(scs.Items))
		}
	})
}

// TestClassForRoot asserts the resolved-root derivation: BasePath is
// <runtimeRoot>/storage (matching runtimed's filepath.Join(Config.Root,
// "storage")), NOT the root-only storagev1.DefaultBasePath.
func TestClassForRoot(t *testing.T) {
	t.Run("unprivileged home root", func(t *testing.T) {
		c := ClassForRoot("/Users/_k3sm")
		if c.BasePath != "/Users/_k3sm/storage" {
			t.Errorf("BasePath = %q, want /Users/_k3sm/storage", c.BasePath)
		}
		if c.BasePath == storagev1.DefaultBasePath {
			t.Error("must not fall back to the root-only DefaultBasePath")
		}
		if err := c.Validate(); err != nil {
			t.Errorf("resolved class must validate: %v", err)
		}
	})

	t.Run("root posture root", func(t *testing.T) {
		c := ClassForRoot("/var/lib/k3sm")
		if c.BasePath != storagev1.DefaultBasePath {
			t.Errorf("BasePath = %q, want %q", c.BasePath, storagev1.DefaultBasePath)
		}
	})
}
