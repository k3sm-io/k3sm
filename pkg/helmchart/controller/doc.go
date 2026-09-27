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

// Package controller is the reconcile loop that turns a helm.k3sm.io/v1
// HelmChart into the Job that installs it, and deletes the release when the
// HelmChart goes away. It is the IMPURE half of k3sm's helm-controller: every
// Job shape, argv and status decision is made by the pure
// k3sm.io/k3sm/pkg/helmchart, and this package holds only the plumbing between
// the API and those decisions.
//
// # Shape
//
// Run ensures the HelmChart and HelmChartConfig CRDs, then campaigns for the
// kube-system/k3sm-helm-controller Lease with client-go's leaderelection
// (identity: the node name). Only the holder runs: three informers (HelmChart,
// HelmChartConfig, and Jobs carrying the helm.k3sm.io/chart label) feed one
// workqueue drained by a single worker. The informer/workqueue scaffold is
// copied from pkg/mlx/operator as a named trade: this is its second instance,
// and the third extracts it.
//
// Leader election is required here where pkg/addons does without: this
// controller deletes Jobs and clears finalizers, and two servers of an HA pair
// doing both at once would replace each other's Jobs. A lost Lease ends the
// term; the controller drains its worker and campaigns again.
//
// # A reconcile
//
//  1. Add the helm.k3sm.io/uninstall finalizer.
//  2. Refuse an http:// source (condition Failed, reason InsecureRepo) or a
//     chartContent that is not base64 (InvalidChartContent): a Warning Event
//     and a status, no Job.
//  3. Ensure the chart-values-<chart> ConfigMap, and chart-content-<chart> when
//     the spec carries chartContent, both owned by the HelmChart.
//  4. Ensure the Job identity (pkg/rbac.ProvisionHelmJobIdentity).
//  5. Ensure helm-install-<chart>, replacing it (Foreground delete, recreate
//     once gone) when its config hash differs from the spec's and the overlay's.
//  6. Write status through the status subresource: JobCreated, and Failed when
//     the Job failed. Under failurePolicy reinstall (the default) the failed Job
//     is then deleted so the install runs again; under abort it is left.
//
// Deleting a HelmChart runs helm-delete-<chart> after the install Job is gone.
// When it completes, the identity is deleted by name and the finalizer
// removed. When it fails (backoffLimit or activeDeadlineSeconds), the same
// happens, with a HelmChartUninstallFailed Warning Event naming the manual
// `helm uninstall`: a HelmChart that can never be deleted is the worse failure.
// The one-way consequence is that only this controller clears the finalizer, so
// a chart deleted while this controller is absent stays Terminating until it
// returns (docs/user/helm.md gives the manual patch).
//
// # Testing
//
// Reconcile is exported and driven directly against fake clients, bypassing
// the Lease. Run is exercised end to end against the fake clientset, whose
// object tracker serves the coordination.k8s.io Lease the elector reads and
// writes, so the election itself is real in that test.
package controller
