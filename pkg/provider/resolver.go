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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/mount"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// kubeResolver supplies ConfigMap/Secret data and mints ServiceAccount tokens for
// runtimed's volume materialization, backed by the provider's apiserver client.
// runtimed never talks to the apiserver — the provider (which holds the client)
// resolves and supplies the data via this mount.Resolver seam.
type kubeResolver struct {
	cs kubernetes.Interface
}

// newKubeResolver returns a kubeResolver over cs.
func newKubeResolver(cs kubernetes.Interface) *kubeResolver {
	return &kubeResolver{cs: cs}
}

// Compile-time check that kubeResolver satisfies the runtimed seam.
var _ mount.Resolver = (*kubeResolver)(nil)

// ConfigMap returns the key→bytes data of a ConfigMap, mapping an apiserver
// NotFound to os.ErrNotExist so the materializer can honor an optional source.
func (k *kubeResolver) ConfigMap(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	cm, err := k.cs.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, notFoundAware(err)
	}
	out := make(map[string][]byte, len(cm.Data)+len(cm.BinaryData))
	for key, v := range cm.Data {
		out[key] = []byte(v)
	}
	for key, v := range cm.BinaryData {
		out[key] = v
	}
	return out, nil
}

// Secret returns the key→bytes data of a Secret, mapping an apiserver NotFound to
// os.ErrNotExist.
func (k *kubeResolver) Secret(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	s, err := k.cs.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, notFoundAware(err)
	}
	out := make(map[string][]byte, len(s.Data)+len(s.StringData))
	for key, v := range s.Data {
		out[key] = v
	}
	for key, v := range s.StringData {
		out[key] = []byte(v)
	}
	return out, nil
}

// errNoPodIdentity is returned when ServiceAccountToken is reached with no pod
// identity on the request context. It is a FAIL-CLOSED sentinel: the alternative
// is minting a token bound to nothing, which outlives its pod.
var errNoPodIdentity = errors.New("no pod identity bound to the request context; refusing to mint an unbound serviceaccount token")

// ServiceAccountToken mints a bound token via the TokenRequest API (audience +
// expirationSeconds, rotated each materialize) for the POD's ServiceAccount — the
// in-pod-API surface. The mount.Resolver signature carries only the
// namespace (it is the single runtimed seam every pod shares), so the per-pod
// identity is bound to the call by the provider via the request context
// (podIdentityFromContext) — runtimed threads that ctx from CreatePod through
// mount.Materialize to here in-process. An empty audience defaults to the
// apiserver's audiences.
//
// The TokenRequest carries spec.boundObjectRef pinned to the POD OBJECT, exactly
// as upstream kubelet binds every projected token: Kind "Pod", APIVersion "v1",
// the pod's name AND its UID. Both halves are load-bearing. The UID is what lets
// the apiserver invalidate the token the moment the pod is deleted (without it a
// deleted pod's token stays usable until expiry), and the pair is what the
// apiserver echoes into the TokenReview response as the
// authentication.kubernetes.io/pod-name and pod-uid extras that identity
// consumers (service-mesh SDS, policy external-data, workload-identity
// federation) read to attribute a request to a workload. A ServiceAccount-kinded
// ref, or one without the UID, is a strictly weaker and different binding.
//
// FAIL-CLOSED: a call with no pod identity on the context returns
// errNoPodIdentity rather than minting an unbound token. Every legitimate caller
// reaches here inside CreatePod/UpdatePod, which bind the identity.
func (k *kubeResolver) ServiceAccountToken(ctx context.Context, namespace, audience string, expirationSeconds int64) (string, error) {
	id, ok := podIdentityFromContext(ctx)
	if !ok {
		return "", fmt.Errorf("mint token in namespace %s: %w", namespace, errNoPodIdentity)
	}
	spec := authnv1.TokenRequestSpec{
		BoundObjectRef: &authnv1.BoundObjectReference{
			Kind:       "Pod",
			APIVersion: "v1",
			Name:       id.name,
			UID:        id.uid,
		},
	}
	if audience != "" {
		spec.Audiences = []string{audience}
	}
	if expirationSeconds > 0 {
		spec.ExpirationSeconds = &expirationSeconds
	}
	tr, err := k.cs.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, id.serviceAccount, &authnv1.TokenRequest{Spec: spec}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("mint token for serviceaccount %s/%s bound to pod %s: %w", namespace, id.serviceAccount, id.name, err)
	}
	return tr.Status.Token, nil
}

// defaultServiceAccount is the ServiceAccount a pod runs as when it sets none —
// the apiserver's ServiceAccount admission default.
const defaultServiceAccount = "default"

// podIdentity is the pod-scoped identity the provider binds to a CreatePod /
// UpdatePod request context: the ServiceAccount the token is minted FOR, and the
// Pod object the token is BOUND TO. The two travel together because they are
// answered by one pod and consumed by one call — a second parallel context key
// could go missing independently, which is exactly the shape of the defect this
// carrier closes.
type podIdentity struct {
	serviceAccount string    // spec.serviceAccountName, defaulted
	name           string    // metadata.name
	uid            types.UID // metadata.uid — the half that makes the binding invalidate with the pod
}

// podIdentityKey is the context key under which the provider binds a pod's
// identity for the duration of a CreatePod, so the shared kubeResolver mints the
// pod's token against the right SA and pins it to the right Pod object. The
// mount.Resolver seam's ServiceAccountToken(ctx, namespace, audience, exp)
// signature carries neither, so the per-pod identity rides the request context
// that runtimed threads from CreatePod → mount.Materialize →
// ServiceAccountToken in-process. This needs no runtimed/apis change. A future
// daemon split (a real gRPC boundary between provider and runtime) cannot carry
// a context value across the wire, so it will bind the identity in the
// materialization RPC instead — tracked with that split.
type podIdentityKey struct{}

// withPodIdentity returns ctx carrying pod's ServiceAccount name, name and UID so
// the kubeResolver mints its token against the right SA and binds it to the pod.
func withPodIdentity(ctx context.Context, pod *corev1.Pod) context.Context {
	return context.WithValue(ctx, podIdentityKey{}, podIdentity{
		serviceAccount: podServiceAccount(pod),
		name:           pod.Name,
		uid:            pod.UID,
	})
}

// podIdentityFromContext returns the identity bound by withPodIdentity. ok is
// false when none is bound, OR when the bound one lacks either half of the pod
// object reference (name, UID) — a partial reference is not a weaker binding to
// fall back on, it is a different one, so it fails closed at the caller.
func podIdentityFromContext(ctx context.Context) (podIdentity, bool) {
	id, ok := ctx.Value(podIdentityKey{}).(podIdentity)
	if !ok || id.name == "" || id.uid == "" {
		return podIdentity{}, false
	}
	if id.serviceAccount == "" {
		id.serviceAccount = defaultServiceAccount
	}
	return id, true
}

// podServiceAccount returns the pod's effective ServiceAccount name. The
// apiserver's ServiceAccount admission stamps spec.serviceAccountName, but the
// provider defaults defensively for a pod that reaches it unset.
func podServiceAccount(pod *corev1.Pod) string {
	if sa := pod.Spec.ServiceAccountName; sa != "" {
		return sa
	}
	return defaultServiceAccount
}

// notFoundAware maps an apiserver NotFound to os.ErrNotExist (the sentinel the
// materializer/env resolver test with errors.Is to honor optional sources);
// other errors pass through.
func notFoundAware(err error) error {
	if apierrors.IsNotFound(err) {
		return os.ErrNotExist
	}
	return err
}

// kubeCredentials resolves private-registry pull credentials from a pod's
// imagePullSecrets, backed by the apiserver client. The resolved credential is
// consumed ONLY by runtimed's pull client and never reaches the pod dir (the
// pull-credential invariant); the proto carries only LocalObjectReference names.
type kubeCredentials struct {
	cs kubernetes.Interface
}

// newKubeCredentials returns a kubeCredentials over cs.
func newKubeCredentials(cs kubernetes.Interface) *kubeCredentials {
	return &kubeCredentials{cs: cs}
}

// Compile-time check that kubeCredentials satisfies the runtimed seam.
var _ runtimed.CredentialResolver = (*kubeCredentials)(nil)

// PullCredential reads the referenced docker-config Secrets and returns the
// credential whose registry matches ref's host, or ok=false for an anonymous pull
// (no secret matched). A missing pull secret is non-fatal (the next is tried).
func (k *kubeCredentials) PullCredential(ctx context.Context, namespace string, secrets []*runtimev1.LocalObjectReference, ref string) (*image.RegistryCredential, bool, error) {
	host := registryHost(ref)
	for _, s := range secrets {
		sec, err := k.cs.CoreV1().Secrets(namespace).Get(ctx, s.GetName(), metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, false, fmt.Errorf("read imagePullSecret %s/%s: %w", namespace, s.GetName(), err)
		}
		cred, ok, err := credentialFromSecret(sec, host)
		if err != nil {
			return nil, false, err
		}
		if ok {
			return cred, true, nil
		}
	}
	return nil, false, nil
}

// dockerConfigJSON is the .dockerconfigjson Secret payload ({"auths": {host: …}}).
type dockerConfigJSON struct {
	Auths map[string]dockerAuthEntry `json:"auths"`
}

// dockerAuthEntry is one registry's auth entry in a docker config.
type dockerAuthEntry struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	Auth          string `json:"auth"`
	IdentityToken string `json:"identitytoken"`
	RegistryToken string `json:"registrytoken"`
}

// credentialFromSecret parses a dockerconfigjson (or legacy dockercfg) Secret and
// returns the credential matching host, ok=false when none matches.
func credentialFromSecret(sec *corev1.Secret, host string) (*image.RegistryCredential, bool, error) {
	if raw, ok := sec.Data[corev1.DockerConfigJsonKey]; ok {
		var cfg dockerConfigJSON
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, false, fmt.Errorf("parse %s in secret %s: %w", corev1.DockerConfigJsonKey, sec.Name, err)
		}
		if e, ok := matchAuth(cfg.Auths, host); ok {
			return toRegistryCredential(e), true, nil
		}
		return nil, false, nil
	}
	if raw, ok := sec.Data[corev1.DockerConfigKey]; ok {
		var auths map[string]dockerAuthEntry // legacy .dockercfg has no "auths" wrapper
		if err := json.Unmarshal(raw, &auths); err != nil {
			return nil, false, fmt.Errorf("parse %s in secret %s: %w", corev1.DockerConfigKey, sec.Name, err)
		}
		if e, ok := matchAuth(auths, host); ok {
			return toRegistryCredential(e), true, nil
		}
	}
	return nil, false, nil
}

// toRegistryCredential converts a parsed docker auth entry to the runtimed type.
func toRegistryCredential(e dockerAuthEntry) *image.RegistryCredential {
	return &image.RegistryCredential{
		Username:      e.Username,
		Password:      e.Password,
		Auth:          e.Auth,
		IdentityToken: e.IdentityToken,
		RegistryToken: e.RegistryToken,
	}
}

// registryHost extracts the registry host from an image reference, defaulting to
// Docker Hub (index.docker.io) when the first path segment is not host-like.
func registryHost(ref string) string {
	s := ref
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		first := s[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			return first
		}
	}
	return "index.docker.io"
}

// matchAuth finds the auth entry for host, normalizing scheme/version suffixes and
// treating the Docker Hub aliases as equivalent.
func matchAuth(auths map[string]dockerAuthEntry, host string) (dockerAuthEntry, bool) {
	want := normalizeRegistry(host)
	for k, e := range auths {
		if normalizeRegistry(k) == want {
			return e, true
		}
	}
	if isDockerHub(want) {
		for k, e := range auths {
			if isDockerHub(normalizeRegistry(k)) {
				return e, true
			}
		}
	}
	return dockerAuthEntry{}, false
}

// normalizeRegistry strips the scheme and trailing /v1 /v2 from a registry key so
// "https://index.docker.io/v1/" and "index.docker.io" compare equal.
func normalizeRegistry(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, "/v1")
	s = strings.TrimSuffix(s, "/v2")
	return strings.TrimSuffix(s, "/")
}

// isDockerHub reports whether a normalized registry host is one of Docker Hub's
// equivalent names.
func isDockerHub(host string) bool {
	switch host {
	case "index.docker.io", "docker.io", "registry-1.docker.io":
		return true
	default:
		return false
	}
}
