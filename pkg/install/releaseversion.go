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
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
)

var (
	// ErrUnversioned reports a staged build that carries no release version.
	ErrUnversioned = errors.New("the staged k3sm carries no release version")
	// ErrDowngrade reports a staged version lower than the installed one, or
	// an installed version this install cannot compare against.
	ErrDowngrade = errors.New("the staged k3sm would replace a newer or unknown installed version")
)

// checkStagedVersion refuses an unversioned staged build, and a staged version
// lower than the installed one unless AllowDowngrade. An installed version
// that cannot be read or compared is treated as a downgrade: the override is
// the same flag, and the default is to refuse.
func checkStagedVersion(cfg Config) error {
	staged, ok := parseReleaseVersion(cfg.StagedVersion)
	if !ok {
		return fmt.Errorf("install: %w: %q is not a release version, and an install from a staging directory takes only a release build", ErrUnversioned, cfg.StagedVersion)
	}
	installedPath := cfg.installedBinary()
	raw, err := cfg.StagingFS.BinaryVersion(installedPath)
	var reason string
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		reason = fmt.Sprintf("the version of the installed %s could not be read (%v)", installedPath, err)
	default:
		installed, ok := parseReleaseVersion(raw)
		switch {
		case !ok:
			reason = fmt.Sprintf("the installed %s reports %q, which is not a release version", installedPath, raw)
		case staged.compare(installed) < 0:
			reason = fmt.Sprintf("the installed k3sm is %s and this one is %s", raw, cfg.StagedVersion)
		default:
			return nil
		}
	}
	if cfg.AllowDowngrade {
		cfg.Logger.Warn("installing over a newer or unknown version because --allow-downgrade was passed", "reason", reason)
		return nil
	}
	return fmt.Errorf("install: %w: %s; pass --allow-downgrade to install it anyway", ErrDowngrade, reason)
}

// releaseVersion is a parsed semantic version. Build metadata is dropped, as
// semver orders it.
type releaseVersion struct {
	major, minor, patch uint64
	pre                 []string
}

// semverPattern is MAJOR.MINOR.PATCH with an optional leading v, an optional
// pre-release and optional build metadata.
var semverPattern = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// pseudoVersionTail is the timestamp-and-commit tail of a Go pseudo-version
// (v0.0.0-20261013000000-abcdefabcdef and its variants): the version a build
// with no release stamp reports, which is not a release.
var pseudoVersionTail = regexp.MustCompile(`(^|[.-])\d{14}-[0-9a-f]{12}$`)

// parseReleaseVersion parses a release version. "dev", an empty string, a Go
// pseudo-version and anything else that is not semver report false.
func parseReleaseVersion(s string) (releaseVersion, bool) {
	m := semverPattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return releaseVersion{}, false
	}
	if m[4] != "" && pseudoVersionTail.MatchString(m[4]) {
		return releaseVersion{}, false
	}
	var v releaseVersion
	var err error
	if v.major, err = strconv.ParseUint(m[1], 10, 64); err != nil {
		return releaseVersion{}, false
	}
	if v.minor, err = strconv.ParseUint(m[2], 10, 64); err != nil {
		return releaseVersion{}, false
	}
	if v.patch, err = strconv.ParseUint(m[3], 10, 64); err != nil {
		return releaseVersion{}, false
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, true
}

// compare orders two versions by semver precedence: -1, 0 or 1.
func (v releaseVersion) compare(o releaseVersion) int {
	for _, d := range [][2]uint64{{v.major, o.major}, {v.minor, o.minor}, {v.patch, o.patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	// A release outranks any of its pre-releases.
	switch {
	case len(v.pre) == 0 && len(o.pre) == 0:
		return 0
	case len(v.pre) == 0:
		return 1
	case len(o.pre) == 0:
		return -1
	}
	for i := 0; i < len(v.pre) && i < len(o.pre); i++ {
		if c := comparePreIdent(v.pre[i], o.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(v.pre) < len(o.pre):
		return -1
	case len(v.pre) > len(o.pre):
		return 1
	}
	return 0
}

// comparePreIdent orders two pre-release identifiers: numeric ones
// numerically and below alphanumeric ones, alphanumeric ones in ASCII order.
func comparePreIdent(a, b string) int {
	an, aerr := strconv.ParseUint(a, 10, 64)
	bn, berr := strconv.ParseUint(b, 10, 64)
	switch {
	case aerr == nil && berr == nil:
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		}
		return 0
	case aerr == nil:
		return -1
	case berr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// versionStampPrefix is the -X flag the release pipeline stamps the version
// with (pkg/version.Version).
const versionStampPrefix = "k3sm.io/k3sm/pkg/version.Version="

// stampedVersion is the version a k3sm binary reports, from its build
// information: the -X stamp in the recorded -ldflags when there is one,
// otherwise the main module's version, otherwise "dev".
func stampedVersion(bi *debug.BuildInfo) string {
	for _, s := range bi.Settings {
		if s.Key != "-ldflags" {
			continue
		}
		fields := strings.Fields(s.Value)
		for i, f := range fields {
			f = strings.Trim(f, `"'`)
			switch {
			case f == "-X" && i+1 < len(fields):
				if v, ok := strings.CutPrefix(strings.Trim(fields[i+1], `"'`), versionStampPrefix); ok {
					return v
				}
			case strings.HasPrefix(f, "-X="):
				if v, ok := strings.CutPrefix(strings.TrimPrefix(f, "-X="), versionStampPrefix); ok {
					return v
				}
			}
		}
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return "dev"
}
