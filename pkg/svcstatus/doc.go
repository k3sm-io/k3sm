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

// Package svcstatus joins the Service proxy to `k3sm status`. It converts the
// proxy's routing table into the record a server publishes in its work dir
// (Record), and compares that record with the API's Services and EndpointSlices
// for the status report's services row (Comparer).
//
// It exists so pkg/status, a reporting leaf, imports neither the proxy nor its
// contracts: the derivation of a Service port's Ready backends and the
// comparison of two backend views both stay in the proxy package
// (proxy.APIBackendSets, proxy.DiffBackendSets), and this package only adapts
// their types.
package svcstatus
