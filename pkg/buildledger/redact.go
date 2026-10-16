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

package buildledger

import (
	"regexp"
	"strings"
)

// redacted replaces a credential the redactor removed.
const redacted = "[redacted]"

var (
	// urlUserinfo is the user[:password]@ part of a URL.
	urlUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/\s@]+@`)
	// authorization is an Authorization header's value, with its scheme.
	authorization = regexp.MustCompile(`(?i)(authorization:\s*)(?:(?:basic|bearer|token|digest)\s+)?[^\s,;"']+`)
	// bearer is a bare bearer token.
	bearer = regexp.MustCompile(`(?i)(\bbearer\s+)[^\s,;"']+`)
	// secretFlag is a --secret argument: --secret=<arg> or --secret <arg>.
	secretFlag = regexp.MustCompile(`(--secret[=\s]+)([^\s"']+)`)
)

// redact removes credentials an error can carry before it is stored: URL
// userinfo, an Authorization header's value, a bearer token, and the values of
// a --secret argument (each key name is kept, so the record still says which
// secret was involved). It is a pattern filter over known shapes, not a
// guarantee that no secret survives.
func redact(s string) string {
	s = urlUserinfo.ReplaceAllString(s, "$1")
	s = authorization.ReplaceAllString(s, "${1}"+redacted)
	s = bearer.ReplaceAllString(s, "${1}"+redacted)
	return secretFlag.ReplaceAllStringFunc(s, func(m string) string {
		sub := secretFlag.FindStringSubmatch(m)
		parts := strings.Split(sub[2], ",")
		for i, p := range parts {
			if k, _, ok := strings.Cut(p, "="); ok {
				parts[i] = k + "=" + redacted
			} else {
				parts[i] = redacted
			}
		}
		return sub[1] + strings.Join(parts, ",")
	})
}
