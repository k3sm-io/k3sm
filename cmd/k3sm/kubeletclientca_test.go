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
	"bytes"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/hostnet"
)

// TestWorkerKubeletClientCAThreads proves the B176 anchor survives the one hop
// that is easy to drop: `k3sm agent` receives the cluster's client-identity CA in
// its join response and must hand it to the in-process node, because a joined
// worker binds :10250 on the WILDCARD and is therefore the most exposed instance
// of this endpoint in the whole product.
//
// serveTLS is asserted alongside it: the two travel together by construction —
// serving TLS is exactly the condition under which the provider routes
// (logs/exec/attach/port-forward) are attached, so a worker with serveTLS and no
// anchor is the pre-B176 posture.
func TestWorkerKubeletClientCAThreads(t *testing.T) {
	t.Parallel()
	ca, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	res := &bootstrap.JoinResult{
		PodCIDR:      "100.64.2.0/24",
		MeshIP:       "100.64.2.1",
		ClientCAPEM:  ca.CertPEM,
		ClusterCAPEM: ca.CertPEM,
	}
	opts := agentOptions{nodeName: "k3sm-worker", nodeIP: "100.64.2.1"}

	nodeOpts := agentNodeOptions(opts, res, "/var/lib/k3sm/agent/node.kubeconfig", hostnet.Mode{Backend: hostnet.BackendHelper}, nil)
	if !nodeOpts.serveTLS {
		t.Fatal("a joined worker must serve the kubelet API over TLS")
	}
	if !bytes.Equal(nodeOpts.kubeletClientCAPEM, ca.CertPEM) {
		t.Error("the join response's client-identity CA did not reach the worker's in-process node; its :10250 would have no anchor to authenticate the apiserver against")
	}
	if !wildcardListen(nodeOpts.listen) {
		t.Errorf("worker kubelet listen = %q — expected the wildcard bind this anchor exists to protect", nodeOpts.listen)
	}
}

// TestStandaloneNodeServeTLSDemandsClientCA proves standalone `k3sm node` refuses
// --serve-tls without --kubelet-client-ca.
//
// Unlike `k3sm server`/`k3sm agent`, this command is pointed at somebody else's
// cluster by --kubeconfig, so nothing in the process knows where that cluster's
// client CA lives — only the operator does. Being unable to name it is a refusal,
// NOT a reason to fall back to an unauthenticated listener: the fallback would be
// exactly the posture B176 removed, reintroduced through the one path that has no
// PKI of its own.
func TestStandaloneNodeServeTLSDemandsClientCA(t *testing.T) {
	t.Parallel()
	// --kubeconfig is deliberately supplied and points nowhere: it proves the
	// refusal happens at flag validation, before any cluster contact, rather than
	// as a downstream side effect.
	err := runNode([]string{"--serve-tls", "--kubeconfig", "/nonexistent/kubeconfig", "--runtime", runtimeHostProcess})
	if err == nil {
		t.Fatal("`k3sm node --serve-tls` without --kubelet-client-ca must refuse to start")
	}
	if !strings.Contains(err.Error(), "--kubelet-client-ca") {
		t.Errorf("error = %q, want it to name the missing --kubelet-client-ca", err)
	}
}
