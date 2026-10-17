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
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateAlertsGolden rewrites the alerts goldens from the collectors:
// go test ./pkg/status -run TestAlertsJSONContractGolden -update-alerts-golden
var updateAlertsGolden = flag.Bool("update-alerts-golden", false, "rewrite testdata/alerts_json_*.json from the collectors")

// alertsGoldens names each `k3sm alerts -o json` golden and the contract
// scenario it is cut from. The degraded one is the expired worker: it carries
// a step to confirm, a step that needs an administrator, a needs-admin row and
// a docs page on every alert, so a consumer's fixture covers each mark.
var alertsGoldens = map[string]string{
	"degraded": "agent-expired",
}

// encodeAlertsJSON is the bytes `k3sm alerts -o json` writes for a report:
// two-space indented JSON and a final newline (cmd/k3sm alertsRunner.run).
func encodeAlertsJSON(rep AlertsReport) ([]byte, error) {
	encoded, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// TestAlertsJSONContractGolden regenerates each alerts golden with Alerts over
// its scenario's collected report and compares it byte for byte, so the file
// a consumer vendors is exactly what the verb prints for that posture.
func TestAlertsJSONContractGolden(t *testing.T) {
	scenarios := contractScenarios()
	for name, scenario := range alertsGoldens {
		t.Run(name, func(t *testing.T) {
			sc, ok := scenarios[scenario]
			if !ok {
				t.Fatalf("no contract scenario %q", scenario)
			}
			c := sc.collector(t)
			rep := c.CollectAlerts(context.Background())
			if rep.Verdict != sc.verdict {
				t.Fatalf("verdict %s, scenario says %s", rep.Verdict, sc.verdict)
			}
			got, err := encodeAlertsJSON(rep)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			path := filepath.Join("testdata", "alerts_json_"+name+".json")
			if *updateAlertsGolden {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s is not what Alerts produces for %s; rerun with -update-alerts-golden and re-vendor it", path, scenario)
			}

			// The golden carries every mark a consumer must handle.
			var confirm, admin, docs bool
			for _, row := range rep.Alerts {
				if row.Alert == nil {
					t.Fatalf("row %s is listed without an alert", row.Name)
				}
				docs = docs || row.Alert.Docs != ""
				for _, step := range row.Alert.Fix {
					confirm = confirm || step.Confirm
					admin = admin || step.NeedsAdmin
				}
			}
			if !confirm || !admin || !docs {
				t.Errorf("golden lacks a mark: confirm=%v needsAdmin=%v docs=%v", confirm, admin, docs)
			}
		})
	}
}
