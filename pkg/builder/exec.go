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
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// podExecer is the production Execer: a SPDY exec against the apiserver's
// pods/exec subresource, the same transport `kubectl exec` uses. It is separated
// from the Manager behind the Execer interface so the readiness state machine
// stays unit-testable with a fake — this type is exercised only by the live tier.
type podExecer struct {
	restCfg *rest.Config
	kube    kubernetes.Interface
}

// NewPodExecer returns an Execer that runs commands in a Pod over the apiserver
// exec subresource.
func NewPodExecer(restCfg *rest.Config, kube kubernetes.Interface) Execer {
	return &podExecer{restCfg: restCfg, kube: kube}
}

// Exec streams command in container of namespace/pod and returns its captured
// stdout and stderr. stdin is not wired: every builder probe is a one-shot read.
func (p *podExecer) Exec(ctx context.Context, namespace, pod, container string, command []string) (string, string, error) {
	req := p.kube.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(p.restCfg, "POST", req.URL())
	if err != nil {
		return "", "", fmt.Errorf("build exec request: %w", err)
	}
	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr})
	return stdout.String(), stderr.String(), err
}
