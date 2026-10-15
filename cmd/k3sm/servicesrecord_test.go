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

package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/status"
)

// TestRecordServicesWritesAPrivateRecord pins the writer: the record lands at
// status.ServicesPath, mode 0600 like its siblings, and parses back with the
// server's pinned Service and unproxied DNS VIP.
func TestRecordServicesWritesAPrivateRecord(t *testing.T) {
	wd := t.TempDir()
	srv := netserve.New(netserve.Config{Client: fake.NewClientset(), WorkDir: wd, DNSVIP: "10.43.0.10", APIServerEndpoint: "127.0.0.1:6444"})
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	path := status.ServicesPath(wd)
	if err := recordServices(srv, path, now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec status.ServicesRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if !rec.UpdatedAt.Equal(now) || len(rec.Unproxied) != 1 || rec.Unproxied[0] != "10.43.0.10" || rec.VIPs == nil {
		t.Errorf("record = %+v", rec)
	}
}
