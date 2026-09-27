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

// Package helmchart renders a helm.k3sm.io/v1 HelmChart into the Job that runs
// helm for it, and derives the HelmChart's status back from that Job. It is the
// k3sm analog of k3s's helm-controller, with the same object names, labels,
// argv shape and status conditions.
//
// This package is the PURE half. RenderJob is spec in, Job out; the status
// functions are Job state in, conditions out; ConfigHash is spec in, digest out.
// None of them performs IO or reads a clock of its own, so the Job shape and the
// status machine are decided by table tests. The reconcile loop that creates the
// Jobs, ConfigMaps and identity, and writes status through the status
// subresource, is k3sm.io/k3sm/pkg/helmchart/controller.
//
// # The Job
//
// Each HelmChart gets one install Job, helm-install-<chart>, and on deletion one
// delete Job, helm-delete-<chart>, both in the HelmChart's namespace. The Job is
// a NATIVE Darwin pod whose command[0] is the pinned helm host binary k3sm ships
// in its payload (see HelmVersion), not a container image: there is no
// klipper-helm image for darwin, and a host binary k3sm pins and verifies is the
// smaller trust surface anyway. Three properties are load bearing:
//
//   - It runs as the ServiceAccount helm-<chart>, bound to cluster-admin (k3s
//     parity; pkg/rbac.ProvisionHelmJobIdentity). helm installs arbitrary
//     objects, so nothing narrower is correct.
//   - It carries the internet-egress annotation ONLY when it fetches the chart
//     (repo, OCI or URL). A chartContent install reads the chart from a
//     ConfigMap and needs no network beyond the apiserver.
//   - It is bounded twice: backoffLimit (k3s's default 1000) and
//     activeDeadlineSeconds of twice the helm timeout, so a runaway install
//     cannot spawn pods indefinitely on the control-plane Mac.
//
// # What is refused
//
// A repo or chart whose scheme is http:// is refused with a Failed condition
// (reason InsecureRepo) and no Job: the Job runs as cluster-admin and must not
// fetch a chart over cleartext. The CRD refuses the same values at admission;
// this is the second layer, for a value the CEL rule's literal prefix check does
// not see (leading whitespace, for example). It is the one deliberate divergence
// from k3s, which allows http.
package helmchart
