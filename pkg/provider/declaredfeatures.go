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

// kubeletDeclarableFeatures is every key a kubelet of the shipped Kubernetes
// version may publish in node.status.declaredFeatures: the Feature.Name() strings
// of the registry in k8s.io/component-helpers@v0.37.1/nodedeclaredfeatures/features
// (AllFeatures). That package is not in this module's graph, so the names are
// hard-coded here; keep them in parity with the registry at the shipped version.
// The list is re-verified against the registry on every DefaultKubeVersion bump,
// as part of the upstream conformance re-triage that bump requires.
// A registry name is not always its feature-gate name: the ContainerRestartRules
// gate declares RestartAllContainersOnContainerExits.
var kubeletDeclarableFeatures = []string{
	"RestartAllContainersOnContainerExits",
	"InPlacePodLevelResourcesVerticalScaling",
	"InPlacePodVerticalScalingInitContainers",
	"InPlacePodVerticalScalingMemoryBackedVolumes",
	"ExtendWebSocketsToKubelet",
	"UserNamespacesHostNetworkSupport",
	"DRANodeAllocatableResources",
	"DRAOptionalNodeOperations",
	"VolumeBindMountOptions",
}

// KubeletDeclarableFeatures returns a copy of the registry names a kubelet of the
// shipped Kubernetes version may declare, so a caller can check that every key
// DeclaredFeatures publishes is a real registry name.
func KubeletDeclarableFeatures() []string {
	return append([]string(nil), kubeletDeclarableFeatures...)
}

// DeclaredFeatures returns the node.status.declaredFeatures set this node
// publishes. It is the one place that set is computed, and it must stay truthful:
// the scheduler and admission read it to decide whether a pod that needs a
// feature may land here, so a key the node does not serve sends such a pod to a
// node that cannot run it.
//
// It returns nil today. The Darwin provider serves none of the features in
// kubeletDeclarableFeatures, so the field stays absent on the wire (omitempty)
// rather than published as an explicit empty list. When a provider capability
// starts serving one of them, its key is added here, from caps, in the same
// change that ships the feature.
//
// caps is reserved for the first served feature: the key it turns on is read from it.
func DeclaredFeatures(caps NodeCapabilities) []string {
	return nil
}
