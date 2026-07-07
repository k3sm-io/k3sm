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

package policy

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// defaultLimitRangeName / defaultLimitRangeNamespace name the M10.0 memory-only
// default LimitRange. It lives in the `default` namespace ONLY — deliberately
// no other namespaces and NO namespace-watching controller (Res.5 scopes the
// default object to the out-of-the-box workload namespace; an operator who
// wants it elsewhere copies it).
const (
	defaultLimitRangeName      = "k3sm-default-memory"
	defaultLimitRangeNamespace = "default"
)

// defaultMemoryLimit / defaultMemoryRequest are the per-container memory
// defaults the LimitRange stamps onto containers that omit them.
const (
	defaultMemoryLimit   = "512Mi"
	defaultMemoryRequest = "256Mi"
)

// EnsureDefaultLimitRange idempotently provisions the MEMORY-ONLY default
// LimitRange in the `default` namespace (M10.0, Res.5): type Container with
// default.memory + defaultRequest.memory, so a container that declares no
// resources still gets an honest memory bound. Memory-ONLY because memory IS
// enforced by the runtime (the rusage sampler → OOMKill); CPU is best-effort
// on Darwin, so a CPU default/limit would over-claim a CFS-style guarantee
// k3sm cannot keep — NO cpu key appears under ANY field (default,
// defaultRequest, max, min, maxLimitRequestRatio).
//
// CREATE-IF-ABSENT, never update: unlike the binary-space config files the
// executor overwrites on boot, an in-cluster LimitRange is OPERATOR-space — an
// admin who tuned the values must not have them clobbered on the next server
// start. AlreadyExists is success. Safe to call on every server start.
func EnsureDefaultLimitRange(ctx context.Context, cs kubernetes.Interface) error {
	lr := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultLimitRangeName,
			Namespace: defaultLimitRangeNamespace,
			Labels:    map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: corev1.LimitRangeSpec{
			Limits: []corev1.LimitRangeItem{{
				Type: corev1.LimitTypeContainer,
				Default: corev1.ResourceList{
					corev1.ResourceMemory: resource.MustParse(defaultMemoryLimit),
				},
				DefaultRequest: corev1.ResourceList{
					corev1.ResourceMemory: resource.MustParse(defaultMemoryRequest),
				},
			}},
		},
	}
	if _, err := cs.CoreV1().LimitRanges(defaultLimitRangeNamespace).Create(ctx, lr, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create default memory limitrange: %w", err)
	}
	return nil
}
