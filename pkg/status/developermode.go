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

	"k3sm.io/k3sm/pkg/install"
)

// RowDeveloperMode is the developer-mode marker (install.DeveloperModeMarkerPath).
// The row exists only while something is at the marker path, and it never
// moves the verdict (advisoryRows).
const RowDeveloperMode = "developer-mode"

// The developer-mode row's sentences. They are part of what a consumer reads,
// so they change like an API.
const (
	developerModeOnDetail      = "Developer mode: the signature of the k3sm that runs as root is not checked"
	developerModeOnRemedy      = "Run sudo k3sm install --developer-mode off. Installing a release signed with a Developer ID also turns it off; reinstalling an ad-hoc signed build from source does not"
	developerModeInvalidDetail = "A developer-mode marker exists but is not a root-owned file, so it is ignored and the signature checks stay on"
)

// developerModeInvalidRemedy removes a marker that fails the checks.
const developerModeInvalidRemedy = "sudo rm " + install.DeveloperModeMarkerPath

// developerModeRow reports the developer-mode marker: on for a valid one,
// invalid for anything else at the path, and no row when the path is absent.
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
// the mode off, and an invalid marker is removed by hand.
func developerModeAlert(r Row) *Alert {
	switch r.State {
	case StateOn:
		return alert("Developer mode is on, so k3sm does not check the signature of the k3sm that runs as root.", docsDeveloperMode,
			manual(developerModeOnRemedy))
	case StateInvalid:
		return alert("Something is at the developer-mode marker path that is not a root-owned file nobody else can write; it is ignored and the signature checks stay on.", docsDeveloperMode,
			cmd("Remove it", developerModeInvalidRemedy))
	}
	return nil
}
