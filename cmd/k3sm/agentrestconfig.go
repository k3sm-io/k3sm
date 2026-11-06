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

package main

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/kubeclient"
)

// agentRESTConfig loads a kubeconfig an agent's own loop reads: the mesh watcher,
// the MeshPeer list and the node-local datapath. As root it takes only inline
// credentials; any other account keeps kubeconfig's full loader.
func agentRESTConfig(path string) (*rest.Config, error) {
	if processEuid() == 0 {
		return kubeclient.CheckedConfig(path)
	}
	return clientcmd.BuildConfigFromFlags("", path)
}
