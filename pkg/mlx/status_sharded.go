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

package mlx

// The conditions a SHARDED MLXModel carries beside Ready. They are published
// here, beside the reasons, because apis publishes only the Ready condition
// type; a consumer reads them by these names.
const (
	// ConditionShardsPlaced reports whether the operator found a placement for
	// every rank. False means no rank Pod exists, and the reason says what the
	// cluster lacks.
	ConditionShardsPlaced = "ShardsPlaced"
	// ConditionLinksHealthy reports whether every direct link the placement
	// counted on is still up.
	ConditionLinksHealthy = "LinksHealthy"
)

// Reasons carried by ShardsPlaced (and, while no placement exists, by Ready).
const (
	// ReasonPlaced means every rank has a node and its Pod was created.
	ReasonPlaced = "Placed"
	// ReasonNoDirectLinkTopology means the cluster lacks the nodes or the
	// cables the requested backend needs (too few GPU nodes matching the
	// selector, or no RDMA clique for jaccl). It is never answered with a
	// single-node fallback.
	ReasonNoDirectLinkTopology = "NoDirectLinkTopology"
	// ReasonInsufficientMemory means the per-rank share of spec.memory does not
	// fit on enough candidate nodes, or cannot fund a serving context at all.
	ReasonInsufficientMemory = "InsufficientMemory"
)
