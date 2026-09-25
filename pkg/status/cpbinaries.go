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
	"errors"
	"fmt"
	"os"

	"k3sm.io/k3sm/pkg/executor"
)

// The staged control-plane version (B395). `k3sm version` reports the pin this
// binary was BUILT with, which is what it intends to run; the work dir's
// executor.KubeMarkerName marker records what was actually STAGED there. The two
// differ exactly when a binary-only upgrade moved the pin without re-staging the
// payload, and the daemon then keeps serving the old control plane: it logs an
// ERROR, and this annotation is how an operator who never reads that log finds out.
//
// A missing marker is every install that predates the marker, so it renders as
// unknown-staged with no severity: the next seed from a marked payload writes one,
// and flagging every existing install on its first report after the upgrade would
// be an alarm with no fault behind it.

// StagedPosture is what the marker says about the staged control-plane set.
type StagedPosture int

const (
	// StagedMatch: the marker vouches for the pin this binary was built with.
	StagedMatch StagedPosture = iota
	// StagedUnvouched: no marker (or a malformed one) — staged before markers existed.
	StagedUnvouched
	// StagedStale: the marker names a version older than (or not comparable to) the pin.
	StagedStale
	// StagedNewer: the marker names a version newer than the pin; the daemon refuses
	// the downgrade and keeps serving the newer set.
	StagedNewer
	// StagedUnreadable: the marker may exist but this process may not read it.
	StagedUnreadable
)

// StagedVerdict is the annotation-shaped reading of the marker.
type StagedVerdict struct {
	Posture StagedPosture
	Staged  string
	Pinned  string
	Detail  string
	Remedy  string
}

// ClassifyStagedControlPlane reads a marker into a verdict. Pure: the caller passes
// the marker's content (or the read error) and the pin.
func ClassifyStagedControlPlane(marker []byte, readErr error, pinned string) StagedVerdict {
	v := StagedVerdict{Pinned: pinned}
	switch {
	case readErr != nil && !errors.Is(readErr, os.ErrNotExist):
		v.Posture = StagedUnreadable
		if errors.Is(readErr, os.ErrPermission) {
			v.Detail = "unknown-staged (marker not readable by this user; run as root to read it), pinned " + pinned
		} else {
			v.Detail = "unknown-staged (marker unreadable: " + errText(readErr) + "), pinned " + pinned
		}
		return v
	case readErr != nil:
		v.Posture = StagedUnvouched
	default:
		v.Staged = executor.ParseKubeMarker(marker)
		if v.Staged == "" {
			v.Posture = StagedUnvouched
		}
	}
	switch {
	case v.Posture == StagedUnvouched:
		v.Detail = "unknown-staged (no " + executor.KubeMarkerName + " marker; staged before markers existed), pinned " + pinned
	case v.Staged == pinned:
		v.Posture = StagedMatch
		v.Detail = v.Staged + " staged, pinned " + pinned
	case executor.KubeVersionOlder(pinned, v.Staged):
		v.Posture = StagedNewer
		v.Detail = fmt.Sprintf("control-plane binaries staged %s are NEWER than this build's pin %s (the daemon refuses the downgrade and serves the staged set)", v.Staged, pinned)
		v.Remedy = executor.NewerControlPlaneRemedy
	default:
		v.Posture = StagedStale
		v.Detail = fmt.Sprintf("control-plane binaries staged %s, but this build pins %s: the old control plane is still serving", v.Staged, pinned)
		v.Remedy = executor.StaleControlPlaneRemedy
	}
	return v
}

// applyStagedControlPlane folds the verdict into the server row. The staged/pinned
// pair always lands in the wide view; a mismatch is a WARN on a row that is
// otherwise OK (the control plane is serving, just not the intended one) and never
// softens or overrides a worse verdict already on the row — a parked daemon's
// remedy comes first.
func applyStagedControlPlane(row *Row, v StagedVerdict) {
	switch v.Posture {
	case StagedStale, StagedNewer:
		row.Wide["cp-binaries"] = v.Detail
		if row.Severity == SeverityOK {
			row.Severity = SeverityWarn
			row.Detail = v.Detail
		}
		if row.Remedy == "" {
			row.Remedy = v.Remedy
		}
	default:
		row.Wide["cp-binaries"] = v.Detail
	}
}

// stagedControlPlane reads the work dir's control-plane marker through the FS seam
// and annotates the server row with it, against the pin this binary was built with
// (executor.DefaultKubeVersion — what version.Get reports).
func (c Collector) stagedControlPlane(row *Row) {
	if c.FS == nil || c.Paths.WorkDir == "" {
		return
	}
	b, err := c.FS.ReadFile(executor.KubeMarkerPath(c.Paths.WorkDir))
	applyStagedControlPlane(row, ClassifyStagedControlPlane(b, err, executor.DefaultKubeVersion))
}
