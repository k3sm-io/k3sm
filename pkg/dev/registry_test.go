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

package dev

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleInstance(name string) Instance {
	return Instance{
		Version:     registryVersion,
		Name:        name,
		WorkDir:     "/tmp/k3sm/" + name + "/server",
		APIPort:     16450,
		KinePort:    12390,
		PID:         4242,
		Tier:        tierRootless,
		Datapath:    DatapathNone,
		ServiceCIDR: ServiceCIDR,
		PodCIDR:     PodCIDR,
		EUID:        501,
		KubeContext: kubeContextName(name),
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
	}
}

func TestRegistryRoundTrip(t *testing.T) {
	reg := NewRegistry(t.TempDir())
	want := sampleInstance("alpha")
	if err := reg.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := reg.Load("alpha")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestRegistrySaveDefaultsVersion(t *testing.T) {
	reg := NewRegistry(t.TempDir())
	in := sampleInstance("beta")
	in.Version = 0 // Save must stamp the current schema version
	if err := reg.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := reg.Load("beta")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Version != registryVersion {
		t.Errorf("Version = %d, want %d (Save stamps the schema version)", got.Version, registryVersion)
	}
}

func TestRegistryLoadNotFound(t *testing.T) {
	reg := NewRegistry(t.TempDir())
	_, err := reg.Load("ghost")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Load(ghost) = %v, want ErrNotFound", err)
	}
}

func TestRegistryListSortedAndSurvivesLiveness(t *testing.T) {
	reg := NewRegistry(t.TempDir())
	for _, n := range []string{"charlie", "alpha", "bravo"} {
		if err := reg.Save(sampleInstance(n)); err != nil {
			t.Fatalf("Save %s: %v", n, err)
		}
	}
	// A durable manifest is read regardless of process liveness: List does not
	// consult any pid, so a "dead" instance is still listed.
	got, err := reg.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("List returned %d, want 3", len(got))
	}
	for i, want := range []string{"alpha", "bravo", "charlie"} {
		if got[i].Name != want {
			t.Errorf("List[%d].Name = %q, want %q (sorted)", i, got[i].Name, want)
		}
	}
}

func TestRegistryListMissingRootIsEmpty(t *testing.T) {
	reg := NewRegistry(filepath.Join(t.TempDir(), "never-created"))
	got, err := reg.List()
	if err != nil {
		t.Fatalf("List on missing root: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("List = %v, want empty for a missing root", got)
	}
}

func TestRegistryListSkipsCorruptEntry(t *testing.T) {
	root := t.TempDir()
	reg := NewRegistry(root)
	if err := reg.Save(sampleInstance("good")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// A corrupt manifest must not blind List (one bad entry is skipped, not fatal).
	bad := filepath.Join(root, "bad")
	if err := os.MkdirAll(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, instanceFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := reg.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].Name != "good" {
		t.Errorf("List = %v, want just [good] (corrupt entry skipped)", got)
	}
}

func TestRegistryRemove(t *testing.T) {
	reg := NewRegistry(t.TempDir())
	if err := reg.Save(sampleInstance("gone")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := reg.Remove("gone"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := reg.Load("gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Load after Remove = %v, want ErrNotFound", err)
	}
	if err := reg.Remove("gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Remove of absent = %v, want ErrNotFound", err)
	}
}
