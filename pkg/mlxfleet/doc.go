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

// Package mlxfleet is the one home for the upstream serving framework's API
// vocabulary that k3sm's MLX fleet reads: the CRD group, the kinds, the served
// and storage versions, and the chart version they were recorded from.
//
// The fleet's control plane is NVIDIA Dynamo (Apache-2.0), named here once as a
// compatibility fact; everywhere else in k3sm the feature is the MLX fleet. Its
// objects are read by `k3sm status` and by the fleet gate, and both used to spell
// the group and version strings inline. A literal that appears in two places
// drifts in one of them, and a wrong group or version does not fail — it reads
// nothing, so a fleet that is running reports as absent. This package exists so
// that a re-pin which moves a group, a version, or a kind fails a test instead.
//
// # What is pinned, and against what
//
// Every value here was read from the chart at ChartVersion, installed on a k3sm
// node in the M16.0 S2 spike (hack/spike/m16/findings-s2.md is the write-back).
// Two records in testdata/ carry the version in their file name, so bumping
// ChartVersion without re-recording them fails the tests that read them:
//
//   - crds-<ChartVersion>.txt is the CRD set the operator image applies — one
//     line per CRD, in the spelling the spike's s2.2 rung records — and
//     TestFleetGVKsMatchPin requires Resources to render to exactly it.
//   - operator-clusterrole-<ChartVersion>.yaml is the operator's ClusterRole,
//     verbatim, and operator-grant-<ChartVersion>.txt is that role flattened to
//     one (group, resource, verb) per line so a reviewer reads the grant rather
//     than the rules. TestFleetOperatorRBACPinned requires the two to agree, and
//     names the properties of the grant that were decided when it was read: no
//     wildcard, and the exact verbs it holds on Secrets.
//
// The grant is pinned because installing the chart is what confers it, and a
// grant nobody read is a grant nobody decided. The pin does not make the grant
// smaller; it makes a change to it visible at re-pin time, in a diff.
//
// # What does not live here
//
// No client, no reads, no status derivation. The status row that reports the
// fleet and the gate rung that asserts the grant live are consumers; this
// package is the vocabulary they share. The chart's digest-pinned reference and
// the upstream commit it was built from are recorded in the spike findings and
// the example values, not here: nothing in product code pulls the chart.
package mlxfleet
