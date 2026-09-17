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

package kubeclient

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// FromPath loads the kubeconfig at path and returns both the rest.Config it
// resolved and a typed clientset built from it. path is used verbatim, and
// nothing else is consulted: an empty path reaches client-go's in-cluster
// fallback, which on a macOS host always fails, rather than quietly resolving to
// whatever KUBECONFIG or ~/.kube/config names (see the package comment).
//
// A load failure is returned EXACTLY as clientcmd produced it, with no context
// added. The caller names its own site — "load kubeconfig", "load node
// kubeconfig for node-local datapath", "build client config from <path>" — and
// those messages are what operators have been reading; a wrap here would either
// stutter with the caller's or silently reword it. The helper names nothing.
// (The NewForConfig failure is the one exception: it cannot be reached through
// a config this function itself just loaded successfully, so no caller has a
// distinguishable message for it and one canonical wrap is clearer than none.)
//
// Neither call dials: BuildConfigFromFlags reads a file and NewForConfig only
// constructs a client, so a returned client proves nothing about reachability.
// Timeouts and rate limits are the caller's to set on the returned config before
// it builds anything else from it.
func FromPath(path string) (*rest.Config, kubernetes.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, nil, err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	return cfg, cs, nil
}
