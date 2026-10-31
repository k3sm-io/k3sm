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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
)

// contractBudget is a node budget the way the node daemon samples it: a warn
// level on the compressor, still admitting, with a headroom recommendation.
func contractBudget(observedAt time.Time) budgetv1alpha1.NodeBudgetObservation {
	i64 := func(v int64) *int64 { return &v }
	return budgetv1alpha1.NodeBudgetObservation{
		ObservedAt: metav1.NewTime(observedAt),
		Platform:   budgetv1alpha1.PlatformDarwin,
		Level:      budgetv1alpha1.LevelWarn,
		Admit:      true,
		Capacity: budgetv1alpha1.BudgetCapacity{
			CPUCapacityMilli:      i64(12000),
			CPUSystemReserveMilli: i64(1000),
			MemCapacityBytes:      i64(32 << 30),
			MemSystemReserveBytes: i64(2 << 30),
			MemAllocatableBytes:   i64(30 << 30),
		},
		Signals: []budgetv1alpha1.BudgetSignal{{
			ID:                 budgetv1alpha1.SignalMemoryCompressor,
			Unit:               budgetv1alpha1.UnitPermille,
			Value:              i64(620),
			WarnThreshold:      i64(600),
			AdmitStopThreshold: i64(700),
			CriticalThreshold:  i64(800),
			LimitingResource:   budgetv1alpha1.ResourceMemory,
		}},
		Darwin: &budgetv1alpha1.DarwinSignals{VMPressureLevel: i64(1)},
		Recommendation: budgetv1alpha1.BudgetRecommendation{
			SafeAdditionalBytes: i64(3 << 30),
			Basis:               budgetv1alpha1.SignalMemoryCompressor,
		},
	}
}

// budgetRecordSeam is a Budget seam serving the encoded record for obs.
func budgetRecordSeam(t *testing.T, obs budgetv1alpha1.NodeBudgetObservation) func() ([]byte, error) {
	t.Helper()
	raw, err := EncodeBudgetRecord(obs)
	if err != nil {
		t.Fatalf("EncodeBudgetRecord: %v", err)
	}
	return func() ([]byte, error) { return raw, nil }
}

// TestReportCarriesBudgetBlock pins the budget block of `k3sm status -o
// json`: the node's record, embedded as the apis NodeBudgetStatus type, as an
// additive top-level "budget" key under schemaVersion 1, and left out whenever
// the budget is unknown.
func TestReportCarriesBudgetBlock(t *testing.T) {
	t.Parallel()
	running := func(t *testing.T) Collector {
		return contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", heartbeatingKube(goldenTime), nil)
	}

	t.Run("a fresh record is embedded verbatim", func(t *testing.T) {
		t.Parallel()
		obs := contractBudget(goldenTime.Add(-5 * time.Second))
		c := running(t)
		c.Budget = budgetRecordSeam(t, obs)
		r := c.Collect(context.Background())
		if r.SchemaVersion != 1 {
			t.Fatalf("schemaVersion = %d, want 1: the block is additive", r.SchemaVersion)
		}
		if r.Budget == nil {
			t.Fatal("report has no budget block for a fresh record")
		}
		want := budgetv1alpha1.NodeBudgetStatus{NodeBudgetObservation: obs}
		gotJSON, err := json.Marshal(r.Budget)
		if err != nil {
			t.Fatal(err)
		}
		wantJSON, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotJSON, wantJSON) {
			t.Errorf("budget block encodes\n%s\nwant the NodeBudgetStatus encoding\n%s", gotJSON, wantJSON)
		}
		if r.Budget.Writer != nil || len(r.Budget.Conditions) != 0 {
			t.Errorf("budget block carries writer %+v and conditions %+v; those belong to the cluster's status writer", r.Budget.Writer, r.Budget.Conditions)
		}

		// The block decodes as NodeBudgetStatus and validates, so one schema
		// reads both it and NodeBudget.status.
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(raw, &top); err != nil {
			t.Fatal(err)
		}
		var st budgetv1alpha1.NodeBudgetStatus
		dec := json.NewDecoder(bytes.NewReader(top["budget"]))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&st); err != nil {
			t.Fatalf("budget block does not decode strictly as NodeBudgetStatus: %v", err)
		}
		if err := st.Validate(); err != nil {
			t.Errorf("budget block does not validate as NodeBudgetStatus: %v", err)
		}
		if st.Level != budgetv1alpha1.LevelWarn || !st.Admit || len(st.Signals) != 1 {
			t.Errorf("decoded block level=%s admit=%v signals=%d, want warn, true, 1", st.Level, st.Admit, len(st.Signals))
		}

		// An older reader that knows only the schemaVersion 1 keys of the
		// running golden decodes the report as before.
		legacy := Report{}
		if err := json.Unmarshal(raw, &struct {
			SchemaVersion *int     `json:"schemaVersion"`
			Verdict       *Verdict `json:"verdict"`
		}{&legacy.SchemaVersion, &legacy.Verdict}); err != nil {
			t.Fatalf("a reader that ignores unknown keys fails: %v", err)
		}
		if legacy.SchemaVersion != 1 || legacy.Verdict != VerdictRunning {
			t.Errorf("legacy read schemaVersion=%d verdict=%v", legacy.SchemaVersion, legacy.Verdict)
		}
	})

	for _, tc := range []struct {
		name string
		seam func(t *testing.T) func() ([]byte, error)
	}{
		{"no Budget seam", func(*testing.T) func() ([]byte, error) { return nil }},
		{"no record", func(*testing.T) func() ([]byte, error) {
			return func() ([]byte, error) { return nil, fs.ErrNotExist }
		}},
		{"an unreadable record", func(*testing.T) func() ([]byte, error) {
			return func() ([]byte, error) { return nil, errors.New("read: permission denied") }
		}},
		{"a record that does not parse", func(*testing.T) func() ([]byte, error) {
			return func() ([]byte, error) { return []byte(`{"schema":1,"level":"ok","bogus":true}`), nil }
		}},
		{"a record of another schema", func(*testing.T) func() ([]byte, error) {
			return func() ([]byte, error) { return []byte(`{"schema":2,"level":"ok"}`), nil }
		}},
		{"a stale record", func(t *testing.T) func() ([]byte, error) {
			return budgetRecordSeam(t, contractBudget(goldenTime.Add(-BudgetRecordMaxAge-time.Second)))
		}},
		{"a record from the future", func(t *testing.T) func() ([]byte, error) {
			return budgetRecordSeam(t, contractBudget(goldenTime.Add(BudgetRecordMaxAge+time.Second)))
		}},
		{"a record with no observation time", func(*testing.T) func() ([]byte, error) {
			return func() ([]byte, error) { return []byte(`{"schema":1,"platform":"darwin","darwin":{}}`), nil }
		}},
	} {
		t.Run(tc.name+" leaves the block out", func(t *testing.T) {
			t.Parallel()
			c := running(t)
			c.Budget = tc.seam(t)
			r := c.Collect(context.Background())
			if r.Budget != nil {
				t.Fatalf("budget block %+v, want none: an unknown budget is never reported", r.Budget)
			}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var top map[string]json.RawMessage
			if err := json.Unmarshal(raw, &top); err != nil {
				t.Fatal(err)
			}
			if _, ok := top["budget"]; ok {
				t.Errorf("report JSON carries a budget key for an unknown budget")
			}
			if r.SchemaVersion != 1 {
				t.Errorf("schemaVersion = %d, want 1", r.SchemaVersion)
			}
		})
	}

	t.Run("the record round-trips through its encoder", func(t *testing.T) {
		t.Parallel()
		obs := contractBudget(goldenTime)
		raw, err := EncodeBudgetRecord(obs)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseBudgetRecord(raw)
		if err != nil {
			t.Fatal(err)
		}
		gotJSON, err := json.Marshal(got.NodeBudgetObservation)
		if err != nil {
			t.Fatal(err)
		}
		wantJSON, err := json.Marshal(obs)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotJSON, wantJSON) {
			t.Errorf("round trip\n%s\nwant\n%s", gotJSON, wantJSON)
		}
	})
}
