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
	"context"
	"errors"
	"fmt"

	"k3sm.io/k3sm/pkg/install"
)

// RowDeveloperMode is the developer-mode marker (install.DeveloperModeMarkerPath).
// The row exists only while something is at the marker path or the path cannot
// be read, and it never moves the verdict (advisoryRows).
const RowDeveloperMode = "developer-mode"

// The developer-mode row's sentences. They are part of what a consumer reads,
// so they change like an API.
const (
	developerModeOnDetail      = "Developer mode: the signature of the k3sm that runs as root is not checked"
	developerModeOnRemedy      = "Run sudo k3sm install --developer-mode off. Installing a release signed with a Developer ID also turns it off; reinstalling an ad-hoc signed build from source does not"
	developerModeInvalidDetail = "A developer-mode marker exists but is not a root-owned file, so it is ignored and the signature checks stay on"
)

// The ancestor cause: the marker is fine and a directory above it is not, so
// removing the marker clears the row and leaves the directory to fix.
const (
	developerModeAncestorDetailFmt = "A developer-mode marker exists but %s, a directory above it, is not a root-owned real directory that neither group nor others can write, with no ACL, so the marker is ignored and the signature checks stay on"
	developerModeAncestorRemedyFmt = "Make %s a root-owned real directory that neither group nor others can write, with no ACL; removing the marker clears this row but leaves that directory as it is"
)

// developerModeInvalidRemedy removes a marker that fails the checks, and
// developerModeInvalidDirRemedy one that is a directory, which rm refuses
// without -r. rm -r does not follow a symlink inside it.
const (
	developerModeInvalidRemedy    = "sudo rm " + install.DeveloperModeMarkerPath
	developerModeInvalidDirRemedy = "sudo rm -r " + install.DeveloperModeMarkerPath
)

// The unknown state: the read could not see the path. It says neither that a
// marker exists nor that the signature checks stay on, because root may read a
// valid marker there that this account cannot. As root the report has nothing
// further to ask, so the remedy looks at the path instead.
const (
	developerModeUnknownDetail     = "The developer-mode marker path could not be read from this account, so this report cannot say whether developer mode is on"
	developerModeUnknownRootRemedy = "Check the path and the directories above it with ls -ldO@e " + install.DeveloperModeMarkerPath + " /Library /"
)

// developerModeRow reports the developer-mode marker: on for a valid one,
// invalid for anything else at the path, unknown when the read could not see
// the path, and no row when the path is absent.
// The wide signing key names how the installed k3sm is signed, when
// SigningTeamID is wired and can tell.
func (c Collector) developerModeRow(ctx context.Context) (Row, bool) {
	if c.DeveloperMode == nil {
		return Row{}, false
	}
	row := Row{Name: RowDeveloperMode, Severity: SeverityWarn}
	switch c.DeveloperMode() {
	case install.DeveloperModeMarkerOn:
		row.State, row.Detail, row.Remedy = StateOn, developerModeOnDetail, developerModeOnRemedy
	case install.DeveloperModeInvalid:
		row.State, row.Detail, row.Remedy = StateInvalid, developerModeInvalidDetail, developerModeInvalidRemedy
		if c.DeveloperModeAncestor != nil {
			if dir := c.DeveloperModeAncestor(); dir != "" {
				row.Detail = fmt.Sprintf(developerModeAncestorDetailFmt, dir)
				row.Remedy = fmt.Sprintf(developerModeAncestorRemedyFmt, dir)
			}
		}
		if row.Remedy == developerModeInvalidRemedy && c.DeveloperModeMarkerIsDir != nil && c.DeveloperModeMarkerIsDir() {
			row.Remedy = developerModeInvalidDirRemedy
		}
	case install.DeveloperModeUnknown:
		row.State, row.Detail, row.Remedy = StateUnknown, developerModeUnknownDetail, needsAdminRemedy
		if c.EUID == 0 {
			row.Remedy = developerModeUnknownRootRemedy
		}
	default:
		return Row{}, false
	}
	if signing, ok := c.installedSigning(ctx); ok {
		row.Wide = map[string]string{"signing": signing}
	}
	return row, true
}

// installedSigning is "ad-hoc" or "team <ID>" for the installed k3sm, and
// false when there is no reader or it cannot tell.
func (c Collector) installedSigning(ctx context.Context) (string, bool) {
	if c.SigningTeamID == nil || c.Paths.Binary == "" {
		return "", false
	}
	team, err := c.SigningTeamID(ctx, c.Paths.Binary)
	switch {
	case errors.Is(err, install.ErrNoTeamID):
		return "ad-hoc", true
	case err != nil:
		return "", false
	}
	return "team " + team, true
}

// developerModeAlert is the developer-mode row's alert: a signed release turns
// the mode off, an invalid marker is removed by hand, and an unread one is read
// again as root.
func developerModeAlert(r Row) *Alert {
	switch r.State {
	case StateOn:
		return alert("Developer mode is on, so k3sm does not check the signature of the k3sm that runs as root.", docsDeveloperMode,
			manual(developerModeOnRemedy))
	case StateInvalid:
		if r.Remedy != developerModeInvalidRemedy && r.Remedy != developerModeInvalidDirRemedy {
			return alert("A directory above the developer-mode marker is not a root-owned real directory nobody else can write; the marker is ignored and the signature checks stay on.", docsDeveloperMode,
				manual(r.Remedy))
		}
		return alert("Something is at the developer-mode marker path that is not a root-owned file nobody else can write; it is ignored and the signature checks stay on.", docsDeveloperMode,
			cmd("Remove it", r.Remedy))
	case StateUnknown:
		const cause = "The developer-mode marker path could not be read from this account, so this report cannot say whether developer mode is on."
		if r.Remedy == needsAdminRemedy {
			return alert(cause, docsDeveloperMode, reportAsAdmin())
		}
		return alert(cause, docsDeveloperMode, manual(r.Remedy))
	}
	return nil
}
