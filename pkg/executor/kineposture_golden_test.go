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

package executor

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// updateGolden rewrites the golden files a test compares against. Run it only when
// a change to a golden output is the intended behaviour, and review the diff.
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata golden files")

// kinePostureGoldenPath holds the single-node kine posture's rendered outputs, captured
// before the etcd posture was added.
const kinePostureGoldenPath = "testdata/kine-posture.golden.json"

// kinePostureCase is one single-node Config and what it renders.
type kinePostureCase struct {
	Name             string   `json:"name"`
	WorkDir          string   `json:"workDir"`
	KinePort         int      `json:"kinePort"`
	KineArgs         []string `json:"kineArgs"`
	DatastorePosture string   `json:"datastorePosture"`
	EtcdServers      string   `json:"etcdServers"`
}

// renderKinePosture renders the kine-posture outputs for c's inputs.
func renderKinePosture(t *testing.T, c kinePostureCase) kinePostureCase {
	t.Helper()
	cfg := Config{WorkDir: c.WorkDir, KinePort: c.KinePort}
	args, err := kineArgs(cfg)
	if err != nil {
		t.Fatalf("%s: kineArgs: %v", c.Name, err)
	}
	c.KineArgs = args
	c.DatastorePosture = datastorePosture(cfg)
	c.EtcdServers = flagValue(apiServerArgs(cfg), "--etcd-servers")
	return c
}

// TestKineArgsUnchangedAfterRetirement pins the single-node kine posture byte for byte:
// kine's argv, the posture name and the apiserver's --etcd-servers value equal what they
// were before the etcd HA posture existed. Single-node is the default and stays kine →
// SQLite; nothing about adding (or later retiring) an HA posture may move it.
func TestKineArgsUnchangedAfterRetirement(t *testing.T) {
	inputs := []kinePostureCase{
		{Name: "root posture defaults", WorkDir: DefaultWorkDir, KinePort: DefaultKinePort},
		{Name: "custom work dir and port", WorkDir: "/srv/k3sm/server", KinePort: 32379},
	}
	got := make([]kinePostureCase, 0, len(inputs))
	for _, in := range inputs {
		got = append(got, renderKinePosture(t, in))
	}
	path := filepath.FromSlash(kinePostureGoldenPath)
	if *updateGolden {
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var want []kinePostureCase
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("kine posture drifted from the golden\n got: %+v\nwant: %+v", got, want)
	}
}
