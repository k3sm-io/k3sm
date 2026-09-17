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

// Package kubeclient builds a typed Kubernetes client from ONE explicitly named
// kubeconfig file.
//
// It exists because the same two-call pair — clientcmd.BuildConfigFromFlags
// followed by kubernetes.NewForConfig — was written out at six sites that each
// already know exactly which file they must read.
//
// The package resolves nothing: no KUBECONFIG, no ~/.kube/config, no in-cluster
// config, no context or user override. That is deliberate and is the whole
// reason this is not a thin wrapper over the user-facing kubeconfig precedence
// the CLI applies (cmd/k3sm's resolveKubectlConfig). Its callers are
// privilege-scoped or instance-scoped, not the user's kubectl:
//
//   - the agent's node-local datapath holds the system:node credential and must
//     never fall back to an admin kubeconfig that happens to exist in the
//     operator's home;
//   - netd, as the root helper, has exactly one authorizer kubeconfig and no
//     fallback;
//   - the server's post-bring-up client is the control plane's OWN admin
//     kubeconfig, the one the executor just wrote for this work dir;
//   - `k3sm builder` refuses with a message naming `k3sm server` when the
//     work-dir kubeconfig is absent, which a fallback would turn into a silent
//     connection to some other cluster;
//   - pkg/dev's bring-up waits poll the kubeconfig of the dev INSTANCE they just
//     started, and several instances (plus whatever cluster the operator's
//     environment points at) can exist at once — a wait that picked up another
//     one would report the wrong cluster's nodes and namespace objects as this
//     instance's, and `dev up` would pass without the instance ever coming up.
//
// A resolver with precedence would change which credential, or which cluster,
// each of those trusts — so the one shared helper deliberately has none.
//
// It also always builds a clientset, so two sites keep clientcmd directly:
// cmd/k3sm's nodeRESTConfig, which pins a request timeout on the config before
// anything is built from it, and the mesh watcher, which needs only a
// *rest.Config and would otherwise construct and discard a client it never
// dials with.
package kubeclient
