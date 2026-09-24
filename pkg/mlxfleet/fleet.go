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

package mlxfleet

import (
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ChartVersion is the upstream chart version every value in this package was
// read from. It names the testdata records the pin tests read, so bumping it
// without re-recording them is a red test rather than a silent re-pin.
const ChartVersion = "1.5.0"

// Group is the API group every fleet CRD lives in.
const Group = "nvidia.com"

// Conversion strategies a fleet CRD declares, as the apiserver spells them.
const (
	ConversionNone    = "None"
	ConversionWebhook = "Webhook"
)

// Resource is one CRD the fleet's control plane installs.
//
// Storage is the version objects are persisted as and the one a reader should
// ask for: reading a served-but-not-storage version is a round trip through the
// conversion webhook, which is a thing the fleet gate exercises on purpose and
// the status path should not do by accident.
type Resource struct {
	Plural string
	Kind   string
	// Served lists the API versions the CRD serves, oldest first.
	Served []string
	// Storage is the version objects are stored as. It is always one of Served.
	Storage string
}

// The fleet CRDs at ChartVersion. A CRD that serves two versions converts
// between them through the operator's own webhook; the strategy is not stored
// here because it follows from the version count (Conversion).
var (
	ComponentDeployment = Resource{
		Plural: "dynamocomponentdeployments", Kind: "DynamoComponentDeployment",
		Served: []string{"v1alpha1", "v1beta1"}, Storage: "v1beta1",
	}
	GraphDeploymentRequest = Resource{
		Plural: "dynamographdeploymentrequests", Kind: "DynamoGraphDeploymentRequest",
		Served: []string{"v1alpha1", "v1beta1"}, Storage: "v1beta1",
	}
	// GraphDeployment is the object a fleet is declared as: the frontend and the
	// workers of one served model, which is what the status row counts.
	GraphDeployment = Resource{
		Plural: "dynamographdeployments", Kind: "DynamoGraphDeployment",
		Served: []string{"v1alpha1", "v1beta1"}, Storage: "v1beta1",
	}
	GraphDeploymentScalingAdapter = Resource{
		Plural: "dynamographdeploymentscalingadapters", Kind: "DynamoGraphDeploymentScalingAdapter",
		Served: []string{"v1alpha1", "v1beta1"}, Storage: "v1beta1",
	}
	Model = Resource{
		Plural: "dynamomodels", Kind: "DynamoModel",
		Served: []string{"v1alpha1"}, Storage: "v1alpha1",
	}
	// WorkerMetadata is the object each worker registers itself as under
	// Kubernetes-native discovery, so its count is the fleet's registered
	// workers.
	WorkerMetadata = Resource{
		Plural: "dynamoworkermetadatas", Kind: "DynamoWorkerMetadata",
		Served: []string{"v1alpha1"}, Storage: "v1alpha1",
	}
)

// Resources returns every fleet CRD, in CRD-name order. This is the set the
// operator image applies at ChartVersion, and the set the pin test renders.
func Resources() []Resource {
	return []Resource{
		ComponentDeployment,
		GraphDeploymentRequest,
		GraphDeployment,
		GraphDeploymentScalingAdapter,
		Model,
		WorkerMetadata,
	}
}

// GVK is the resource's storage-version GroupVersionKind.
func (r Resource) GVK() schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: Group, Version: r.Storage, Kind: r.Kind}
}

// Conversion is the CRD's conversion strategy: ConversionWebhook when it serves
// more than one version, ConversionNone otherwise. It is derived rather than
// stored so a pin cannot carry a strategy its version list contradicts.
func (r Resource) Conversion() string {
	if len(r.Served) > 1 {
		return ConversionWebhook
	}
	return ConversionNone
}

// CRDName is the CustomResourceDefinition object's name, plural.group.
func (r Resource) CRDName() string {
	return r.Plural + "." + Group
}

// ListPath is the apiserver path that lists the resource across all
// namespaces at its storage version.
func (r Resource) ListPath() string {
	return "/apis/" + Group + "/" + r.Storage + "/" + r.Plural
}

// Record is the one-line spelling of the resource the spike's s2.2 rung writes
// and the recorded CRD file holds, so the file is diffable against a live
// apiserver's answer without a parser on either side.
func (r Resource) Record() string {
	return r.CRDName() + " kind=" + r.Kind +
		" served=" + strings.Join(r.Served, ",") +
		" storage=" + r.Storage +
		" conversion=" + r.Conversion()
}
