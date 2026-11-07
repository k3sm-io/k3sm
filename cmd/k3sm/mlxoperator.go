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
	"context"
	"log/slog"
	"net"
	"strconv"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/crdensure"
	"k3sm.io/k3sm/pkg/interconnect"
	"k3sm.io/k3sm/pkg/mlx"
	"k3sm.io/k3sm/pkg/mlx/operator"
	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// mlxOperatorConfig assembles the MLX operator's Config for the server path.
//
// It is a function rather than a struct literal inline in runServer for ONE
// reason: Config.GPU. A nil GPU silently SKIPS the pre-render fit check — the
// seam documents that, and it is the correct answer for a genuinely daemon-less
// posture — so a regression that drops the wiring produces no error, no log line,
// and no failing reconcile, only models that are applied unchecked and die at load
// time. Assembling the Config here gives that field a test (see
// mlxoperator_test.go) instead of leaving it to review.
//
// gpu is the live GPU source; it is REQUIRED here even though the operator
// tolerates nil, because on this path the facts are obtainable — the node this
// same process is about to bring up holds the runtime that has them.
//
// indices is the node cluster-index source the interconnect resolver reads
// (meshPeerIndexSet), so the operator's slot-1 addresses and the resolver's
// slot-0 recompute come from one derivation. nil is the same silent degrade as
// a nil GPU (no model ever lands on the thunderbolt path), which the wiring
// test pins against.
//
// registryPort is the server's own registry on loopback (--registry-port),
// which resolves an artifact model's tag to its digest; artifact references
// must name the cluster registry (flatRegistryHost). 0 (the registry is off)
// leaves no resolver, so only references by digest are servable.
func mlxOperatorConfig(cs kubernetes.Interface, dyn dynamic.Interface, crd crdensure.CRDClient, gpu operator.GPUSource, indices func(context.Context) (interconnect.Indices, error), registryPort int, clusterDomain string, log *slog.Logger) operator.Config {
	var artifacts operator.ArtifactResolver
	if registryPort > 0 {
		base := "http://" + net.JoinHostPort(registrysvc.LoopbackAddress, strconv.Itoa(registryPort))
		if c, err := registryclient.New(base, registryclient.Options{}); err != nil {
			log.Error("mlx operator: no cluster registry client; artifact models by tag cannot be resolved", "err", err)
		} else {
			artifacts = operator.RegistryResolver(c)
		}
	}
	return operator.Config{
		Client:              cs,
		Dynamic:             dyn,
		CRD:                 crd,
		GPU:                 gpu,
		InterconnectIndices: indices,
		// The pinned serving image and port are left empty: they are release
		// facts this binary does not yet carry, so a model spec supplies them itself
		// and one that does not gets an InvalidSpec status naming what is missing —
		// rather than a StatefulSet built around an invented image.
		Options:       mlx.Options{RegistryHost: flatRegistryHost},
		Artifacts:     artifacts,
		ClusterDomain: clusterDomain,
		Log:           log,
	}
}
