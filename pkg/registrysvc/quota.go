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

package registrysvc

import (
	"fmt"
	"maps"
	"mime"
	"slices"
	"strconv"
	"strings"
)

// QuotaFlagName is the repeatable flag that sets a registry quota.
const QuotaFlagName = "registry-quota"

// maxQuotas bounds how many artifact types carry a quota, so the serve config
// stays well inside its size bound.
const maxQuotas = 64

// QuotaFlag is the value of --registry-quota <artifactType>=<bytes>, which may
// be given once per artifact type. The zero value holds no quota.
type QuotaFlag map[string]int64

// String renders the quotas sorted by type, as the flag would be given.
func (q QuotaFlag) String() string {
	parts := make([]string, 0, len(q))
	for _, t := range slices.Sorted(maps.Keys(q)) {
		parts = append(parts, t+"="+strconv.FormatInt(q[t], 10))
	}
	return strings.Join(parts, ",")
}

// Set adds one <artifactType>=<bytes> quota. The type must be a media type and
// given once; the bytes a positive decimal integer.
func (q *QuotaFlag) Set(v string) error {
	t, n, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("--%s %q: want <artifactType>=<bytes>", QuotaFlagName, v)
	}
	b, err := strconv.ParseInt(n, 10, 64)
	if err != nil {
		return fmt.Errorf("--%s %q: bytes %q is not a decimal integer", QuotaFlagName, v, n)
	}
	if *q == nil {
		*q = QuotaFlag{}
	}
	if _, dup := (*q)[t]; dup {
		return fmt.Errorf("--%s: %q is given twice", QuotaFlagName, t)
	}
	if err := validQuota(t, b); err != nil {
		return fmt.Errorf("--%s: %w", QuotaFlagName, err)
	}
	if len(*q) >= maxQuotas {
		return fmt.Errorf("--%s: more than %d artifact types", QuotaFlagName, maxQuotas)
	}
	(*q)[t] = b
	return nil
}

// validQuota checks one quota: a media type with no parameters, and a
// positive byte count.
func validQuota(t string, b int64) error {
	mt, params, err := mime.ParseMediaType(t)
	if err != nil || mt != t || len(params) != 0 {
		return fmt.Errorf("quota artifact type %q is not a media type", t)
	}
	if b <= 0 {
		return fmt.Errorf("quota %d for %q must be positive", b, t)
	}
	return nil
}

// validQuotas checks every quota of a serve config.
func validQuotas(q map[string]int64) error {
	if len(q) > maxQuotas {
		return fmt.Errorf("more than %d quotas", maxQuotas)
	}
	for _, t := range slices.Sorted(maps.Keys(q)) {
		if err := validQuota(t, q[t]); err != nil {
			return err
		}
	}
	return nil
}
