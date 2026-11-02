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

package status

import (
	"fmt"
	"path/filepath"
	"time"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
	"k3sm.io/k3sm/pkg/install"
)

// BudgetRecordInterval is how often a running node daemon rewrites its budget
// record: the pressure monitor's calm sampling period, so the record is never
// more than one sample behind what the node publishes.
const BudgetRecordInterval = 10 * time.Second

// BudgetRecordMaxAge is the oldest record `k3sm status` reports, measured
// from its observedAt. Six missed rewrites mean the node daemon is not
// running or not sampling, and a budget that old is unknown, never calm.
// A record dated further than this into the future is refused the same way.
const BudgetRecordMaxAge = 6 * BudgetRecordInterval

// BudgetPath is the budget record's path in a status directory (Dir).
func BudgetPath(statusDir string) string {
	return filepath.Join(statusDir, install.BudgetRecordName)
}

// EncodeBudgetRecord returns the budget record a node daemon writes for obs:
// the budget.k3sm.io/status annotation payload (NodeBudgetReport), validated
// by the same encoder, so the file and the annotation are one format.
func EncodeBudgetRecord(obs budgetv1alpha1.NodeBudgetObservation) ([]byte, error) {
	r := budgetv1alpha1.NodeBudgetReport{Schema: budgetv1alpha1.BudgetAnnotationSchema, NodeBudgetObservation: obs}
	s, err := r.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode the budget record: %w", err)
	}
	return []byte(s), nil
}

// ParseBudgetRecord decodes a budget record with the annotation payload's
// strict, size-bounded parser. The record sits in the world-readable status
// directory, so it is untrusted input like the annotation.
func ParseBudgetRecord(raw []byte) (budgetv1alpha1.NodeBudgetReport, error) {
	if len(raw) > budgetv1alpha1.MaxBudgetAnnotationBytes {
		return budgetv1alpha1.NodeBudgetReport{}, fmt.Errorf("budget record is %d bytes, at most %d: %w", len(raw), budgetv1alpha1.MaxBudgetAnnotationBytes, budgetv1alpha1.ErrBudgetAnnotationTooLarge)
	}
	r, err := budgetv1alpha1.ParseNodeBudgetReport(string(raw))
	if err != nil {
		return budgetv1alpha1.NodeBudgetReport{}, fmt.Errorf("parse the budget record: %w", err)
	}
	return r, nil
}

// budget is the report's budget block: the node's record read through the
// Budget seam, embedded as the NodeBudgetStatus the cluster publishes, with
// no writer and no conditions (those are the status writer's). It is nil,
// and the block left out, whenever the budget is unknown: no seam, no
// record, an unreadable or unparseable one, or one whose observedAt is unset
// or further than BudgetRecordMaxAge from now. It never fails the report.
func (c Collector) budget(now time.Time) *budgetv1alpha1.NodeBudgetStatus {
	if c.Budget == nil {
		return nil
	}
	raw, err := c.Budget()
	if err != nil {
		return nil
	}
	r, err := ParseBudgetRecord(raw)
	if err != nil {
		return nil
	}
	at := r.ObservedAt.Time
	if at.IsZero() || now.Sub(at) > BudgetRecordMaxAge || at.Sub(now) > BudgetRecordMaxAge {
		return nil
	}
	return &budgetv1alpha1.NodeBudgetStatus{NodeBudgetObservation: r.NodeBudgetObservation}
}
