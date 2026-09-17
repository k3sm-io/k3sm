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

package install

import (
	"errors"
	"fmt"
	"io/fs"
)

// The role boundary: how install decides that a Mac is a control plane or a
// worker, and never both.
//
// The decision has to be made against the DISK rather than against the Config,
// because the Config describes what an operator just asked for while the disk
// describes what the machine already is. Both questions are answered through
// the same read seam (System.ReadFile of the other role's plist), whose
// fs.ErrNotExist arm is the posture "that role is not installed here" rather
// than a failure.

// refuseCrossRole refuses an install whose OTHER role's daemon plist is already
// on disk.
//
// The two daemons cannot coexist: each brings up a Virtual Kubelet node out of
// the same data root, registers under the same node name and drives the same
// netd helper, so a Mac carrying both would present two nodes to one cluster
// and have them fight over one run dir. Nothing downstream detects that — the
// second daemon simply behaves as though the first were not there — so the
// install is the only place it can be stopped, and it is stopped before the
// first byte is written rather than half-way through.
//
// The remedy is named because it is not guessable: `k3sm uninstall` removes the
// daemon and keeps the data root, the log dir and the recorded arguments, so a
// role change costs an operator one extra command and no state.
func refuseCrossRole(sys System, cfg Config) error {
	cfg = cfg.withDefaults()
	other := cfg.Role.other()
	path := cfg.plistPath(other.daemonLabel())
	switch _, err := sys.ReadFile(path); {
	case err == nil:
		return fmt.Errorf("install: this Mac is already installed as a k3sm %s (%s is on disk) and a node is one role or the other, never both: run `k3sm uninstall` first, then install the %s role (uninstall keeps the data root, the logs and the arguments you configured)",
			other, path, cfg.Role)
	case errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("install: check whether this Mac already carries the %s daemon %s: %w", other, path, err)
	}
}

// uninstallManifest is the set of artifacts THIS Mac has, which is the
// configured role's manifest plus the other role's when that role's daemon
// plist is on disk.
//
// Reading the disk is what makes a role change safe: an operator switching a
// node from server to agent uninstalls and installs again, and the uninstall
// runs from a Config that says nothing about which role is installed. A
// manifest built from the Config alone would leave the other role's plist
// behind — a KeepAlive root job pointing at a binary the install-dir sweep just
// deleted.
//
// An unreadable probe INCLUDES the other role rather than excluding it. Booting
// out a label that is not loaded and removing a path that is not there are both
// no-op successes, so including a role that turns out to be absent costs
// nothing, while excluding one that is present leaks a daemon.
func uninstallManifest(sys System, cfg Config) []artifact {
	cfg = cfg.withDefaults()
	m := artifactManifest(cfg)
	other := cfg.Role.other()
	path := cfg.plistPath(other.daemonLabel())
	switch _, err := sys.ReadFile(path); {
	case errors.Is(err, fs.ErrNotExist):
		return m
	case err != nil:
		cfg.Logger.Warn("could not tell whether this Mac also carries the other role's daemon; tearing it down anyway (a bootout of a label that is not loaded is a no-op)",
			"path", path, "err", err)
	}
	return mergeManifests(m, artifactManifest(cfg.asRole(other)))
}

// asRole returns cfg describing the named role. It is a copy, so a caller that
// needs both manifests holds neither role's fields in the other's.
func (c Config) asRole(r Role) Config {
	c.Role = r
	return c
}

// mergeManifests appends every artifact of other that primary does not already
// carry, identified by kind, path and label.
//
// The appended entries land at the END, which is where they belong: uninstall
// walks the manifest in REVERSE install order, so the other role's node daemon
// is booted out first of all — before netd, the helper it drives — exactly as
// the configured role's own daemon would be.
func mergeManifests(primary, other []artifact) []artifact {
	type key struct {
		kind  artifactKind
		path  string
		label string
	}
	seen := make(map[key]bool, len(primary))
	for _, a := range primary {
		seen[key{a.kind, a.path, a.label}] = true
	}
	out := primary
	for _, a := range other {
		k := key{a.kind, a.path, a.label}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	return out
}
