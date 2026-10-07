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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// clientObjects is an objectReader that reads straight through a client, with
// no pod-reference registry. Tests of the resolver's own behavior (data
// mapping, NotFound handling, token binding) use it so they need not register
// a pod first; the registry is tested on its own in podrefs_test.go.
type clientObjects struct{ cs kubernetes.Interface }

func (c clientObjects) secret(ctx context.Context, ns, name string) (*corev1.Secret, error) {
	return c.cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
}

func (c clientObjects) configMap(ctx context.Context, ns, name string) (*corev1.ConfigMap, error) {
	return c.cs.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
}

// newTestKubeResolver is a kubeResolver over cs with no reference registry.
func newTestKubeResolver(cs kubernetes.Interface) *kubeResolver {
	return newKubeResolver(cs, clientObjects{cs})
}

// newTestKubeCredentials is a kubeCredentials over cs with no reference registry.
func newTestKubeCredentials(cs kubernetes.Interface) *kubeCredentials {
	return newKubeCredentials(clientObjects{cs})
}
