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

// Package placement evaluates node budget observations for new workloads.
package placement

import (
	"time"

	"k8s.io/apimachinery/pkg/api/resource"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
)

// BudgetAllows reports whether the node's current budget permits adding the
// request. The caller also checks allocatable capacity and workload constraints.
// Missing or stale observations defer to those checks.
func BudgetAllows(annotations map[string]string, request resource.Quantity, now time.Time) bool {
	raw := annotations[budgetv1alpha1.AnnotationStatus]
	if raw == "" {
		return true
	}
	report, err := budgetv1alpha1.ParseNodeBudgetReport(raw)
	if err != nil {
		return true
	}
	age := now.Sub(report.ObservedAt.Time)
	if age < -5*time.Second || age > 90*time.Second {
		return true
	}
	if !report.Admit {
		return false
	}
	limit := report.Recommendation.SafeAdditionalBytes
	return limit == nil || request.Cmp(*resource.NewQuantity(*limit, resource.BinarySI)) <= 0
}
