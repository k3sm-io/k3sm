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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/kubeclient"
)

// agentRESTConfig loads a kubeconfig a node's own loop reads: the mesh watcher, the
// MeshPeer list, the node-local datapath and the node's client. As root it takes only
// inline credentials, which is what every kubeconfig k3sm writes holds, so `sudo k3sm
// server` and `sudo k3sm agent` run on their own files as they do under launchd; any
// other account keeps kubeconfig's full loader.
func agentRESTConfig(path string) (*rest.Config, error) {
	if processEuid() == 0 {
		return kubeclient.CheckedConfig(path)
	}
	return clientcmd.BuildConfigFromFlags("", path)
}

// rootCheckedClient is agentRESTConfig for a site that also needs the clientset: the
// flat registry lookup and the server's admin client. A failure comes back as the
// loader produced it, for the site to wrap.
func rootCheckedClient(path string) (*rest.Config, kubernetes.Interface, error) {
	if processEuid() == 0 {
		return kubeclient.FromCheckedPath(path)
	}
	return kubeclient.FromPath(path)
}
