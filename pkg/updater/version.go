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

package updater

import (
	"cmp"
	"fmt"
	"strings"

	"k3sm.io/k3sm/pkg/updater/layout"
)

// NormalizeVersion is the one form versions are compared in: no v prefix, lower
// case, no build metadata. The high-water mark and the bad list hold it, so
// V0.3.0-RC1, v0.3.0-rc1 and 0.3.0-rc1+x are one version to both.
func NormalizeVersion(v string) string {
	v = strings.ToLower(v)
	v = strings.TrimPrefix(v, "v")
	v, _, _ = strings.Cut(v, "+")
	return v
}

// compareVersions orders two release versions by semver precedence. A migrated
// unknown-<hash> name or anything else that is not a release version is an error
// wrapping layout.ErrBadVersion: it has no order.
func compareVersions(a, b string) (int, error) {
	for _, v := range []string{a, b} {
		if err := layout.ValidateVersion(v); err != nil {
			return 0, err
		}
		if layout.IsUnknownVersion(v) {
			return 0, fmt.Errorf("%w: %q has no order", layout.ErrBadVersion, v)
		}
	}
	coreA, preA, hasPreA := strings.Cut(NormalizeVersion(a), "-")
	coreB, preB, hasPreB := strings.Cut(NormalizeVersion(b), "-")
	partsA, partsB := strings.Split(coreA, "."), strings.Split(coreB, ".")
	for i := range partsA {
		if c := compareNumeric(partsA[i], partsB[i]); c != 0 {
			return c, nil
		}
	}
	switch {
	case !hasPreA && !hasPreB:
		return 0, nil
	case !hasPreA:
		return 1, nil
	case !hasPreB:
		return -1, nil
	}
	idsA, idsB := strings.Split(preA, "."), strings.Split(preB, ".")
	for i := 0; i < len(idsA) && i < len(idsB); i++ {
		if c := comparePreID(idsA[i], idsB[i]); c != 0 {
			return c, nil
		}
	}
	return cmp.Compare(len(idsA), len(idsB)), nil
}

// compareNumeric orders two digit strings of any length without parsing them,
// so no version overflows an integer.
func compareNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if c := cmp.Compare(len(a), len(b)); c != 0 {
		return c
	}
	return cmp.Compare(a, b)
}

func comparePreID(a, b string) int {
	numA, numB := allDigits(a), allDigits(b)
	switch {
	case numA && numB:
		return compareNumeric(a, b)
	case numA:
		return -1
	case numB:
		return 1
	}
	return cmp.Compare(a, b)
}

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
