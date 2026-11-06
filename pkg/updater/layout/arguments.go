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

package layout

import (
	"fmt"
	"slices"

	"k3sm.io/k3sm/pkg/install/order"
)

// daemonLabels is the closed set of labels a job runs current/<bin> daemon
// <label> under: the jobs the restart order names.
var daemonLabels = []string{order.NetdLabel, order.ServerLabel, order.AgentLabel, order.DatavolLabel}

// daemonBinaries is the closed set of binaries such a job runs.
var daemonBinaries = []string{K3smBinary}

// DaemonArguments returns the frozen program arguments of a k3sm launchd job:
// current/<bin> daemon <label>. Every argument the job needs lives in the
// signed binary, so these never change in an update, and an update never
// rewrites a plist.
func (l Layout) DaemonArguments(bin, label string) ([]string, error) {
	path, err := l.Binary(bin)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(daemonBinaries, bin) {
		return nil, fmt.Errorf("binary %q: %w", bin, ErrBadName)
	}
	if !slices.Contains(daemonLabels, label) {
		return nil, fmt.Errorf("label %q: %w", label, ErrBadName)
	}
	return []string{path, "daemon", label}, nil
}

// UpdaterArguments returns the frozen program arguments of the updater job.
// It is the one job that does not run through current: it runs through the
// updater's own pointer, so the updater can move independently of the node.
func (l Layout) UpdaterArguments() []string {
	return []string{l.UpdaterCurrentBinary(), "daemon", UpdaterLabel}
}

// GuardArguments returns the frozen program arguments of the guard job: the
// pinned known-good updater's guard verb.
func (l Layout) GuardArguments() []string {
	return []string{l.UpdaterGuardBinary(), "guard"}
}
