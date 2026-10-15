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

// The pod hostname derivation below is ported from Kubernetes v1.37.1
// (Apache-2.0, The Kubernetes Authors):
//   - pkg/kubelet/kubelet_pods.go: GeneratePodHostNameAndDomain and
//     truncatePodHostnameIfNeeded
//   - pkg/kubelet/util/util.go: GetNodenameForKernel
//   - pkg/kubelet/kuberuntime/kuberuntime_sandbox.go: no sandbox hostname for a
//     hostNetwork pod
// The error strings are the kubelet's, so an Event reads the same as upstream.

import (
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// podHostnameMaxLen caps a pod hostname at 63 characters (the 64-byte
	// nodename field less its terminating NUL), as the kubelet does.
	podHostnameMaxLen = 63
	// podFQDNMaxLen is the longest FQDN setHostnameAsFQDN may produce.
	podFQDNMaxLen = 64
)

// podHostnameError is a pod hostname derivation failure. It names the spec
// field the bad value came from and that value's length, which the vm refusal
// Event reports; Error is the kubelet's own text.
type podHostnameError struct {
	field  string
	length int
	err    error
}

func (e *podHostnameError) Error() string { return e.err.Error() }

func (e *podHostnameError) Unwrap() error { return e.err }

// podHostname returns the kernel hostname for pod: the value PodBox.hostname
// carries. It is THE SINGLE DERIVATION SITE: no other module derives a pod
// hostname, and a consumer (runtimed, the vm guest, any future /etc/hosts or
// HOSTNAME work) reads PodBox.hostname rather than re-deriving it.
//
// The rules, in the kubelet's order:
//  1. A hostNetwork pod gets "" (the kubelet sets no sandbox hostname for it),
//     without validating anything else.
//  2. spec.hostnameOverride, when set, is validated as a DNS-1123 subdomain,
//     truncated to 63 characters and returned with no domain, so subdomain and
//     setHostnameAsFQDN never apply to it.
//  3. Otherwise spec.hostname (a DNS-1123 label) or the pod name, truncated to
//     63 characters.
//  4. spec.subdomain (a DNS-1123 label) gives the domain
//     <subdomain>.<namespace>.svc.<clusterDomain>; with setHostnameAsFQDN the
//     result is <hostname>.<domain>, refused above 64 characters.
//
// truncated reports that the name was cut to 63 characters, so the caller can
// log it at the level its backend warrants; it is never raised as an Event,
// matching upstream.
func podHostname(pod *corev1.Pod, clusterDomain string) (hostname string, truncated bool, err error) {
	if pod.Spec.HostNetwork {
		return "", false, nil
	}
	if pod.Spec.HostnameOverride != nil {
		override := *pod.Spec.HostnameOverride
		if msgs := validation.IsDNS1123Subdomain(override); len(msgs) != 0 {
			return "", false, &podHostnameError{field: "spec.hostnameOverride", length: len(override),
				err: fmt.Errorf("pod HostnameOverride %q is not a valid DNS subdomain: %s", override, strings.Join(msgs, ";"))}
		}
		return truncatePodHostname(pod, "spec.hostnameOverride", override)
	}

	field := "metadata.name"
	hostname = pod.Name
	if len(pod.Spec.Hostname) > 0 {
		if msgs := validation.IsDNS1123Label(pod.Spec.Hostname); len(msgs) != 0 {
			return "", false, &podHostnameError{field: "spec.hostname", length: len(pod.Spec.Hostname),
				err: fmt.Errorf("pod Hostname %q is not a valid DNS label: %s", pod.Spec.Hostname, strings.Join(msgs, ";"))}
		}
		field, hostname = "spec.hostname", pod.Spec.Hostname
	}
	hostname, truncated, err = truncatePodHostname(pod, field, hostname)
	if err != nil {
		return "", false, err
	}

	domain := ""
	if len(pod.Spec.Subdomain) > 0 {
		if msgs := validation.IsDNS1123Label(pod.Spec.Subdomain); len(msgs) != 0 {
			return "", false, &podHostnameError{field: "spec.subdomain", length: len(pod.Spec.Subdomain),
				err: fmt.Errorf("pod Subdomain %q is not a valid DNS label: %s", pod.Spec.Subdomain, strings.Join(msgs, ";"))}
		}
		domain = fmt.Sprintf("%s.%s.svc.%s", pod.Spec.Subdomain, pod.Namespace, clusterDomain)
	}

	if domain == "" || pod.Spec.SetHostnameAsFQDN == nil || !*pod.Spec.SetHostnameAsFQDN {
		return hostname, truncated, nil
	}
	fqdn := fmt.Sprintf("%s.%s", hostname, domain)
	if len(fqdn) > podFQDNMaxLen {
		return "", false, &podHostnameError{field: "spec.setHostnameAsFQDN", length: len(fqdn),
			err: fmt.Errorf("failed to construct FQDN from pod hostname and cluster domain, FQDN %s is too long (%d characters is the max, %d characters requested)", fqdn, podFQDNMaxLen, len(fqdn))}
	}
	return fqdn, truncated, nil
}

// truncatePodHostname cuts hostname to 63 characters and trims a trailing '-'
// or '.', reporting whether it cut. field names where hostname came from.
func truncatePodHostname(pod *corev1.Pod, field, hostname string) (string, bool, error) {
	if len(hostname) <= podHostnameMaxLen {
		return hostname, false, nil
	}
	truncated := strings.TrimRight(hostname[:podHostnameMaxLen], "-.")
	if len(truncated) == 0 {
		return "", false, &podHostnameError{field: field, length: len(hostname),
			err: fmt.Errorf("hostname for pod %q was invalid: %q", pod.Name, hostname)}
	}
	return truncated, true, nil
}

// recordPodHostnameRefusal records the Warning Event for a create refused
// because the pod's hostname cannot be derived (a vm pod only: toPodBox sends an
// empty hostname for every other backend). It is a no-op for any other error.
// The reason and message prefix are the kubelet's for a sandbox it could not
// configure; the message adds the field and the length.
func (r *runtimedRuntime) recordPodHostnameRefusal(pod *corev1.Pod, err error) {
	var he *podHostnameError
	if !errors.As(err, &he) {
		return
	}
	r.recorder.Event(pod, corev1.EventTypeWarning, reasonFailedCreatePodSandBox,
		msgFailedPodHostname(he))
}
