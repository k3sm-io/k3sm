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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// registryVersion is the on-disk manifest schema version. It is written into
// every instance.json so a future `k3sm dev` can migrate or reject an
// incompatible layout (the CLI-commitment decision — the format is a
// compatibility contract from day one).
const registryVersion = 1

// instanceFile is the per-instance manifest filename under <root>/<name>/.
const instanceFile = "instance.json"

// Datapath tags the network posture an instance booted with (also the fidelity
// axis the banner keys off).
const (
	// DatapathNone is the rootless tier: runtimed + network=none. No lo0/utun
	// datapath — Service traffic is INERT (needs --datapath).
	DatapathNone = "none"
	// DatapathDirect is the root tier: runtimed + network=direct. Real
	// Service/ClusterIP/DNS/pod-IP over lo0 aliases.
	DatapathDirect = "direct"
)

// Instance is the durable per-instance manifest (~/.k3sm/dev/<name>/instance.json).
// It is written at `up` and read INDEPENDENT of process liveness (so `list`
// survives sleep/reboot); `down` removes it. Every field is content the lifecycle
// needs to teardown or reclaim an instance without re-probing.
type Instance struct {
	// Version is the manifest schema version (registryVersion).
	Version int `json:"version"`
	// Name is the instance name (the `--name`; default "dev").
	Name string `json:"name"`
	// WorkDir is the control-plane state root the detached `k3sm server` owns.
	WorkDir string `json:"workDir"`
	// PodRoot is the runtimed root the detached server was given (--pod-root):
	// pod dirs, the image blob cache and the PVC storage root. It lives OUTSIDE
	// the registry root (see PodRootBasePrefix), so unlike WorkDir it is not
	// reclaimed by Remove — teardown deletes it explicitly. Empty on a manifest
	// written before the split, which read the root from the work-dir parent.
	PodRoot string `json:"podRoot"`
	// APIPort / KinePort are the probe-allocated ports (so parallel rootless
	// instances never collide).
	APIPort  int `json:"apiPort"`
	KinePort int `json:"kinePort"`
	// PID is the detached `k3sm server` process (its own process group), recorded
	// so `down` tears it down and `list` reports liveness. It is authoritative
	// only when the manifest is fresh — `list` cross-checks it against
	// System.ProcessAlive.
	PID int `json:"pid"`
	// Tier is the privilege tier: "rootless" (network=none) or "root" (--datapath).
	Tier string `json:"tier"`
	// Runtime is the EFFECTIVE pod runtime the detached server booted with:
	// "runtimed" (Seatbelt-confined, the default) or "hostprocess" (UNCONFINED, the
	// honest fallback taken when the k3sm-execshim helper could not be provisioned).
	// Recorded so `list` and the fidelity banner report confined-vs-unconfined
	// isolation honestly. An empty value on an older manifest reads as runtimed
	// (the pre-fallback default).
	Runtime string `json:"runtime"`
	// Datapath is the network backend the instance booted with (DatapathNone or
	// DatapathDirect) — the teardown lo0-flush + the fidelity banner key off it.
	Datapath string `json:"datapath"`
	// ServiceCIDR / PodCIDR are the CIDRs whose lo0 aliases teardown/pre-flight
	// sweep (Lo0Flush). Recorded so a future CIDR change does not orphan a running
	// instance's aliases.
	ServiceCIDR string `json:"serviceCIDR"`
	PodCIDR     string `json:"podCIDR"`
	// EUID is the effective uid that created the instance — part of the
	// (name × euid) identity so a root datapath instance and a rootless one never
	// share a workdir.
	EUID int `json:"euid"`
	// KubeContext is the kubeconfig context name merged on `up` (removed on
	// `down`).
	KubeContext string `json:"kubeContext"`
	// Kubeconfig is the resolved file the context was merged into (--kubeconfig /
	// $KUBECONFIG / ~/.kube/config), recorded so `down` (and `down --all` after a
	// reboot) removes it from the same file without needing the flag again.
	Kubeconfig string `json:"kubeconfig"`
	// CreatedAt is when `up` wrote the manifest (informational; `list` shows age).
	CreatedAt time.Time `json:"createdAt"`
}

// Registry is the durable instance store rooted at a directory (default
// ~/.k3sm/dev). It is pure file I/O + JSON — no process state — so `list` reads
// it regardless of whether any instance's server is alive.
type Registry struct {
	root string
}

// NewRegistry returns a Registry rooted at root (created lazily on Save).
func NewRegistry(root string) *Registry { return &Registry{root: root} }

// DefaultRegistryRoot is <home>/.k3sm/dev — the durable manifest root, under the
// invoking user's home so a rootless and a (SUDO_USER-scoped) datapath run share
// one view. It errors when no home is resolvable.
func DefaultRegistryRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir for dev registry root: %w", err)
	}
	return filepath.Join(home, ".k3sm", "dev"), nil
}

// dir is the per-instance directory <root>/<name>.
func (r *Registry) dir(name string) string { return filepath.Join(r.root, name) }

// path is the per-instance manifest path <root>/<name>/instance.json.
func (r *Registry) path(name string) string { return filepath.Join(r.dir(name), instanceFile) }

// ErrNotFound is returned by Load/Remove when no manifest exists for a name.
var ErrNotFound = errors.New("dev: instance not found")

// Save writes inst's manifest atomically (temp + rename) under <root>/<name>/,
// creating the directory. The file is 0600 (the workdir path is not secret, but
// keeping the manifest owner-only matches the token-bearing kubeconfig beside it).
func (r *Registry) Save(inst Instance) error {
	if inst.Version == 0 {
		inst.Version = registryVersion
	}
	d := r.dir(inst.Name)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return fmt.Errorf("create instance dir %s: %w", d, err)
	}
	data, err := json.MarshalIndent(inst, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal instance %s: %w", inst.Name, err)
	}
	data = append(data, '\n')
	tmp := r.path(inst.Name) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write instance manifest: %w", err)
	}
	if err := os.Rename(tmp, r.path(inst.Name)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit instance manifest: %w", err)
	}
	return nil
}

// Load reads the manifest for name, returning ErrNotFound when absent.
func (r *Registry) Load(name string) (Instance, error) {
	var inst Instance
	data, err := os.ReadFile(r.path(name))
	if err != nil {
		if os.IsNotExist(err) {
			return inst, fmt.Errorf("%w: %q", ErrNotFound, name)
		}
		return inst, fmt.Errorf("read instance manifest %s: %w", name, err)
	}
	if err := json.Unmarshal(data, &inst); err != nil {
		return inst, fmt.Errorf("parse instance manifest %s: %w", name, err)
	}
	return inst, nil
}

// List returns every instance manifest under the root, sorted by name. A missing
// root is an empty list (no instances yet), not an error. A single unparseable
// manifest is skipped, never fatal — one corrupt entry must not blind `list`.
func (r *Registry) List() ([]Instance, error) {
	entries, err := os.ReadDir(r.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read dev registry %s: %w", r.root, err)
	}
	var out []Instance
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		inst, err := r.Load(e.Name())
		if err != nil {
			continue
		}
		out = append(out, inst)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Remove deletes an instance's entire directory (manifest + any lock file),
// returning ErrNotFound when it never existed.
func (r *Registry) Remove(name string) error {
	if _, err := os.Stat(r.path(name)); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %q", ErrNotFound, name)
		}
		return fmt.Errorf("stat instance %s: %w", name, err)
	}
	if err := os.RemoveAll(r.dir(name)); err != nil {
		return fmt.Errorf("remove instance %s: %w", name, err)
	}
	return nil
}
