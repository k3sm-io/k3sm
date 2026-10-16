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

package update

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"k3sm.io/k3sm/pkg/install"
)

// ReleaseBaseFlag is the install and daemon argument that points the managed
// update at another release index than GitHub's: a mirror, or a lab rig
// serving its own builds. Empty is DefaultBaseURL.
const ReleaseBaseFlag = install.UpdateReleaseBaseFlag

// ParseReleaseBase validates a --update-release-base value: an absolute https
// URL, or an http URL whose host is a loopback or RFC 1918 address (a lab
// rig on a private network), with no user information, query or fragment.
// The trailing slash is dropped. An http base on any other host is refused:
// the archive's sha256 is always checked, but a plain-http index on a public
// network is one anybody on the path can answer.
func ParseReleaseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil {
		return nil, fmt.Errorf("--%s %q does not parse: %w", ReleaseBaseFlag, raw, err)
	}
	switch {
	case u.Host == "" || !u.IsAbs():
		return nil, fmt.Errorf("--%s %q is not an absolute URL", ReleaseBaseFlag, raw)
	case u.User != nil:
		return nil, fmt.Errorf("--%s must not carry user information", ReleaseBaseFlag)
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return nil, fmt.Errorf("--%s %q must not carry a query or a fragment", ReleaseBaseFlag, raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !privateHost(u.Hostname()) {
			return nil, fmt.Errorf("--%s %q: plain http is allowed only on a loopback or RFC 1918 address (a lab rig); use https", ReleaseBaseFlag, raw)
		}
	default:
		return nil, fmt.Errorf("--%s %q is neither https nor http", ReleaseBaseFlag, raw)
	}
	return u, nil
}

// privateHost reports whether host is localhost, a loopback address, or an
// RFC 1918 IPv4 address (10/8, 172.16/12, 192.168/16).
func privateHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsLoopback() || (a.Is4() && a.IsPrivate())
}

// HostPin is the set of places an archive may be fetched from, on the first
// request and on every redirect: https on AllowedHosts, and, when Base is
// set, the recorded release base's own scheme, host and port.
type HostPin struct {
	// Base is the recorded --update-release-base, or nil.
	Base *url.URL
}

// Check accepts u when the pin admits it.
func (p HostPin) Check(u *url.URL) error {
	if p.Base != nil && u.User == nil && strings.EqualFold(u.Scheme, p.Base.Scheme) && strings.EqualFold(u.Host, p.Base.Host) {
		return nil
	}
	return checkURL(u)
}

// CheckRaw parses raw and checks it.
func (p HostPin) CheckRaw(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: the archive URL does not parse: %w", ErrRefused, err)
	}
	return p.Check(u)
}
