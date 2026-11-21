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
	"errors"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"

	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/dns"
)

// The pod DNS env injection half of toPodBox: the policy gate, the None refusal,
// and the one call to the shim-ABI encoder. The corev1→netv1 mappings it consumes
// (dnsConfigOverride, dnsPolicyNoneConfig) stay in translate.go beside the rest of
// the spec direction.

// msgDNSNoneIPv6Only is the refusal of a dnsPolicy None pod whose nameservers are
// all IPv6: the container waiting message and the Warning Event both carry it.
const msgDNSNoneIPv6Only = "k3sm: dnsPolicy None with only IPv6 nameservers is not supported (the in-pod resolver serves IPv4 nameservers only)"

// podDNSRefusal is the fail-closed refusal of a dnsPolicy None pod whose own DNS
// config the in-pod resolver cannot honor. Its message is user-facing: the
// provider parks the pod with it as a CreateContainerConfigError rather than run
// the pod on the host resolver, which a None pod asked not to use. It wraps the
// darwin-net cause (dns.ErrNoUsableNameserver for an all-IPv6 config).
type podDNSRefusal struct {
	msg string
	err error
}

func (e *podDNSRefusal) Error() string { return e.msg }
func (e *podDNSRefusal) Unwrap() error { return e.err }

// podDNSNoneEnv encodes a dnsPolicy None pod's own config for the shim, or
// refuses it. dnsCfg must be the None mapping (dnsPolicyNoneConfig); any other
// config is refused rather than injected, so a caller that forgot the mapping
// can never hand a None pod a cluster resolver or no resolver at all.
//
// A config with some IPv6 nameservers yields the env for the IPv4 subset
// (dns.ErrNameserversDropped is not a refusal; buildBox reports the drop as a
// DNSConfigPartial Event). A config with none (dns.ErrNoUsableNameserver) is
// refused with msgDNSNoneIPv6Only, and any other encoding error is refused with
// its own text.
func podDNSNoneEnv(dnsCfg netv1.DNSConfig) (map[string]string, error) {
	if dnsCfg.Policy != netv1.DNSPolicyNone {
		return nil, &podDNSRefusal{
			msg: "k3sm: dnsPolicy None pod was translated without its own DNS config",
			err: fmt.Errorf("dns config policy %q, want %q", dnsCfg.Policy, netv1.DNSPolicyNone),
		}
	}
	env, err := dns.ConfigToEnvChecked(dnsCfg)
	switch {
	case err == nil, errors.Is(err, dns.ErrNameserversDropped) && env != nil:
		return env, nil
	case errors.Is(err, dns.ErrNoUsableNameserver):
		return nil, &podDNSRefusal{msg: msgDNSNoneIPv6Only, err: err}
	default:
		return nil, &podDNSRefusal{msg: "k3sm: dnsPolicy None config is not usable: " + err.Error(), err: err}
	}
}

// injectPodDNSEnv appends the K3SM_DNS_* environment the DYLD getaddrinfo shim
// reads (serialized by the single pinned dns.ConfigToEnvChecked encoder, never
// hand-rolled here — a wrong separator would break in-pod DNS) to every
// container, gated on the pod's DNSPolicy:
//
//   - cluster-first (clusterDNSPolicy): the cluster DNS VIP, domain, search list
//     and ndots, so a pod's unqualified Service lookups expand against the
//     cluster. When dnsCfg is not usable (no cluster DNS VIP / invalid) nothing is
//     injected and the shim defers to the host resolver rather than dialing a
//     dead VIP.
//   - None: the pod's own IPv4 nameservers in the shim's exclusive mode
//     (K3SM_DNS_SERVERS, K3SM_DNS_EXCLUSIVE=1), with its own search list and
//     ndots, and never the cluster's. A config the shim cannot honor returns a
//     *podDNSRefusal and injects nothing (podDNSNoneEnv): the pod must not start
//     on the host resolver.
//   - Default, and any other value: nothing, so the pod uses the host resolver.
//
// Scope parity: appended to InitContainers, Containers and EphemeralContainers, matching the
// box-wide DYLD shim annotation.
//
// Precedence (infra-wins): appended after each container's user env, so
// resolveContainerEnv's later-wins upsert makes the injected value authoritative
// — a workload cannot override its pod's DNS policy. Keys are sorted for
// deterministic output.
func injectPodDNSEnv(box *runtimev1.PodBox, policy corev1.DNSPolicy, dnsCfg netv1.DNSConfig) error {
	var env map[string]string
	switch {
	case clusterDNSPolicy(policy):
		e, err := dns.ConfigToEnvChecked(dnsCfg)
		if err != nil {
			return nil
		}
		env = e
	case policy == corev1.DNSNone:
		e, err := podDNSNoneEnv(dnsCfg)
		if err != nil {
			return err
		}
		env = e
	default:
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	appendEnv := func(c *runtimev1.Container) {
		for _, k := range keys {
			c.Env = append(c.Env, &runtimev1.EnvVar{Name: k, Value: env[k]})
		}
	}
	for _, c := range box.GetInitContainers() {
		appendEnv(c)
	}
	for _, c := range box.GetContainers() {
		appendEnv(c)
	}
	for _, c := range box.GetEphemeralContainers() {
		appendEnv(c)
	}
	return nil
}

// clusterDNSPolicy reports whether the pod's DNSPolicy selects cluster DNS. An empty
// policy is the upstream default (ClusterFirst). ClusterFirstWithHostNet MUST match
// too: k3sm pods share the host network by construction, so that value is reachable —
// matching only DNSClusterFirst would silently drop cluster DNS for those pods.
// Default and None do NOT select cluster DNS: Default injects nothing, and None
// injects its own config (injectPodDNSEnv).
func clusterDNSPolicy(policy corev1.DNSPolicy) bool {
	return policy == "" ||
		policy == corev1.DNSClusterFirst ||
		policy == corev1.DNSClusterFirstWithHostNet
}

// dnsNoneForming records what dnsPolicyNoneConfig altered in a pod's dnsConfig to
// make it fit, so the pod can be told (warnDNSConfigForming, kubelet's
// DNSConfigForming). The zero value means nothing was altered.
type dnsNoneForming struct {
	// droppedNameservers are the nameservers beyond netv1.MaxNameservers, after
	// duplicates were removed. A repeated nameserver is removed silently: it
	// changes nothing about resolution.
	droppedNameservers []string
	// droppedSearches are the search domains beyond dns.MaxSearchDomains.
	droppedSearches []string
	// ndotsZero is set when an explicit ndots:0 was applied as ndots 1.
	ndotsZero bool
}
