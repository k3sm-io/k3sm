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
	"os"
	"path/filepath"
	"strings"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/runtimed/pkg/mount"
)

// M2.4 in-cluster API access. The driving reference is the snapshot-manager's
// in-pod kubectl (TestM2_InPodKubectl): a pod must
// reach kubernetes.default.svc with a projected SA token minted for ITS OWN
// ServiceAccount, the apiserver serving CA, and the namespace, all at the
// canonical in-pod paths. These unit tests fake the apiserver client (the
// TokenRequest subresource via a reactor) and exercise the provider's PodBox +
// the runtimed materializer at the seam — no real cluster, no root. The
// kubernetes.default.svc reachability leg is e2e (hack/acceptance/m2.sh).

// inPodCA is an opaque stand-in for the apiserver serving CA bundle published in
// the kube-root-ca.crt ConfigMap (its exact bytes are irrelevant to the seam).
const inPodCA = "-----BEGIN CERTIFICATE-----\nMIIB-k3sm-test-serving-ca\n-----END CERTIFICATE-----\n"

// caMountRoot is the canonical in-pod ServiceAccount mount path (the path the
// apiserver's ServiceAccount admission injects). k3sm has no mount namespace, so
// the materializer rebases it under the pod data volume.
const caMountRoot = "/var/run/secrets/kubernetes.io/serviceaccount"

// fakeSAToken is the token shape the CreateToken reactor returns, encoding which
// ServiceAccount/audience/TTL it was minted for so a test can assert the binding.
func fakeSAToken(sa, audience string, exp int64) string {
	return fmt.Sprintf("tok|sa=%s|aud=%s|exp=%d", sa, audience, exp)
}

// newInPodClient returns a fake clientset with the kube-root-ca.crt ConfigMap in
// ns and a TokenRequest reactor that mints fakeSAToken for whichever SA the
// CreateToken subresource names (the binding under test).
func newInPodClient(ns string) *fake.Clientset {
	cs := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "kube-root-ca.crt"},
		Data:       map[string]string{"ca.crt": inPodCA},
	})
	cs.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		ca, ok := action.(ktesting.CreateActionImpl)
		if !ok || ca.GetSubresource() != "token" {
			return false, nil, nil // not a TokenRequest; fall through
		}
		tr, _ := ca.GetObject().(*authnv1.TokenRequest)
		aud := ""
		var exp int64
		if tr != nil {
			if len(tr.Spec.Audiences) > 0 {
				aud = tr.Spec.Audiences[0]
			}
			if tr.Spec.ExpirationSeconds != nil {
				exp = *tr.Spec.ExpirationSeconds
			}
		}
		return true, &authnv1.TokenRequest{Status: authnv1.TokenRequestStatus{Token: fakeSAToken(ca.Name, aud, exp)}}, nil
	})
	return cs
}

// saAccessPod returns a pod as it looks AFTER the apiserver's ServiceAccount
// admission: spec.serviceAccountName set and the canonical projected SA volume
// (token + kube-root-ca.crt CA + downward-API namespace) mounted at the canonical
// in-pod path.
func saAccessPod(ns, name, sa string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			ServiceAccountName: sa,
			Containers: []corev1.Container{{
				Name:  "c0",
				Image: "registry/app:latest",
				VolumeMounts: []corev1.VolumeMount{
					{Name: "kube-api-access", MountPath: caMountRoot, ReadOnly: true},
				},
			}},
			Volumes: []corev1.Volume{{
				Name: "kube-api-access",
				VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: ptr(int64(3607))}},
						{ConfigMap: &corev1.ConfigMapProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"},
							Items:                []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}},
						}},
						{DownwardAPI: &corev1.DownwardAPIProjection{
							Items: []corev1.DownwardAPIVolumeFile{{Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
						}},
					},
				}},
			}},
		},
	}
}

// TestM2_InPodKubectl is the M2.4-a1 proof: a pod's projected SA token is minted
// for ITS OWN ServiceAccount (not the namespace default), the serving CA and the
// namespace land at the canonical in-pod paths, and the provider binds the pod's
// SA across the runtime seam.
func TestM2_InPodKubectl(t *testing.T) {
	const ns = "team"

	t.Run("token minted for the pod's ServiceAccount", func(t *testing.T) {
		r := newKubeResolver(newInPodClient(ns))
		ctx := withServiceAccount(context.Background(), "snapshot-manager")
		tok, err := r.ServiceAccountToken(ctx, ns, "", 3607)
		if err != nil {
			t.Fatalf("ServiceAccountToken: %v", err)
		}
		if !strings.Contains(tok, "sa=snapshot-manager") {
			t.Errorf("token %q not minted for the pod SA snapshot-manager", tok)
		}
		if !strings.Contains(tok, "exp=3607") {
			t.Errorf("token %q did not carry the requested TTL", tok)
		}
	})

	t.Run("token defaults to the default SA when unset", func(t *testing.T) {
		r := newKubeResolver(newInPodClient(ns))
		tok, err := r.ServiceAccountToken(context.Background(), ns, "", 0)
		if err != nil {
			t.Fatalf("ServiceAccountToken: %v", err)
		}
		if !strings.Contains(tok, "sa=default") {
			t.Errorf("token %q not minted for the default SA", tok)
		}
	})

	t.Run("CA, token and namespace materialize at the canonical paths", func(t *testing.T) {
		const sa = "snapshot-manager"
		cs := newInPodClient(ns)
		pod := saAccessPod(ns, "snap", sa)
		dataVol := t.TempDir()

		// Build the PodBox and bind the pod's SA exactly as the provider's
		// CreatePod does, then run the runtimed materializer at the seam.
		box, err := toPodBox(pod, "10.0.0.9", "10.0.0.9", dataVol, "", netv1.DNSConfig{}, nil)
		if err != nil {
			t.Fatalf("toPodBox: %v", err)
		}
		ctx := withServiceAccount(context.Background(), podServiceAccount(pod))
		layout, err := mount.Materialize(ctx, box, dataVol, "10.0.0.9", newKubeResolver(cs))
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}

		root := filepath.Join(dataVol, strings.TrimPrefix(caMountRoot, "/"))
		token := readInPodFile(t, root, "token")
		caCrt := readInPodFile(t, root, "ca.crt")
		namespace := readInPodFile(t, root, "namespace")

		// The in-pod config triple must be internally consistent: the token is
		// bound to the pod's SA, the CA is the apiserver serving CA, and the
		// namespace matches — a stock in-cluster client (token + ca.crt +
		// kubernetes.default.svc) would then validate end to end.
		if !strings.Contains(token, "sa="+sa) {
			t.Errorf("projected token %q not bound to the pod SA %q", token, sa)
		}
		if caCrt != inPodCA {
			t.Errorf("ca.crt = %q, want the apiserver serving CA", caCrt)
		}
		if namespace != ns {
			t.Errorf("namespace file = %q, want %q", namespace, ns)
		}
		// The projected SA mount is a credential ⇒ the SBPL read-only sub-scope.
		if len(layout.CredentialPaths()) != 1 || !strings.HasPrefix(layout.CredentialPaths()[0], root) {
			t.Errorf("projected SA mount not flagged read-only credential: %v", layout.CredentialPaths())
		}
	})

	t.Run("provider binds the pod's SA across the runtime seam", func(t *testing.T) {
		r, f := newRuntimedFake(t)

		withSA := saAccessPod(ns, "snap", "snapshot-manager")
		if err := r.CreatePod(context.Background(), withSA); err != nil {
			t.Fatalf("CreatePod (with SA): %v", err)
		}
		f.mu.Lock()
		got := f.gotSA
		f.mu.Unlock()
		if got != "snapshot-manager" {
			t.Errorf("runtime saw SA %q, want snapshot-manager", got)
		}

		noSA := saAccessPod(ns, "snap2", "")
		if err := r.CreatePod(context.Background(), noSA); err != nil {
			t.Fatalf("CreatePod (no SA): %v", err)
		}
		f.mu.Lock()
		got = f.gotSA
		f.mu.Unlock()
		if got != "default" {
			t.Errorf("runtime saw SA %q for an unset pod, want default", got)
		}
	})
}

// readInPodFile reads a materialized in-pod file under root, failing the test if
// it is absent (the canonical-path assertion).
func readInPodFile(t *testing.T, root, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatalf("read in-pod %s: %v", name, err)
	}
	return string(b)
}
