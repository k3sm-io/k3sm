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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
)

// ErrRefused is the base error of every refusal this package makes before it
// hands a build set to the root helper.
var ErrRefused = errors.New("update refused")

// Payload is the JSON value of the k3sm.io/update-payload Node annotation the
// update controller writes.
type Payload struct {
	// URL is the darwin/arm64 release archive.
	URL string `json:"url"`
	// SHA256 is the archive's lowercase hex sha256.
	SHA256 string `json:"sha256"`
	// Signature is the code-signature policy: if-signed (also when empty) or
	// required.
	Signature updatesv1alpha1.UpdateSignaturePolicy `json:"signature"`
	// AllowDowngrade permits a tag below the running build.
	AllowDowngrade bool `json:"allowDowngrade,omitempty"`
}

// ParsePayload decodes and checks the payload annotation: a known signature
// policy and a lowercase hex sha256. The archive URL is the HostPin's to judge.
func ParsePayload(raw string) (Payload, error) {
	var p Payload
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Payload{}, fmt.Errorf("%w: the payload annotation is not valid JSON: %w", ErrRefused, err)
	}
	if dec.More() {
		return Payload{}, fmt.Errorf("%w: the payload annotation holds more than one JSON value", ErrRefused)
	}
	switch p.Signature {
	case "", updatesv1alpha1.UpdateSignatureIfSigned, updatesv1alpha1.UpdateSignatureRequired:
	default:
		return Payload{}, fmt.Errorf("%w: unknown signature policy %q", ErrRefused, p.Signature)
	}
	if !isSHA256Hex(p.SHA256) {
		return Payload{}, fmt.Errorf("%w: the payload sha256 is not a lowercase hex sha256", ErrRefused)
	}
	return p, nil
}

// RequireTeamSignature reports whether the payload's policy is required, the
// one policy that makes the installer refuse a set without a Developer ID
// team signature whatever the installed build carries.
func (p Payload) RequireTeamSignature() bool {
	return p.Signature == updatesv1alpha1.UpdateSignatureRequired
}

// isSHA256Hex reports whether s is 64 lowercase hex digits.
func isSHA256Hex(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// AllowedHosts are the only hosts an archive is fetched from, on the first
// request and on every redirect: GitHub's release download host and the two
// hosts it redirects release assets to.
var AllowedHosts = []string{"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}

// CheckURL accepts an https URL with no user information, on an AllowedHosts
// host and the default port.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: the archive URL does not parse: %w", ErrRefused, err)
	}
	return checkURL(u)
}

func checkURL(u *url.URL) error {
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%w: the archive URL %s is not https", ErrRefused, redact(u))
	case u.User != nil:
		return fmt.Errorf("%w: the archive URL carries user information", ErrRefused)
	case u.Port() != "" && u.Port() != "443":
		return fmt.Errorf("%w: the archive URL %s names port %s", ErrRefused, redact(u), u.Port())
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range AllowedHosts {
		if host == h {
			return nil
		}
	}
	return fmt.Errorf("%w: the archive host %q is not one of %s", ErrRefused, host, strings.Join(AllowedHosts, ", "))
}

// redact is u without its query, which a redirect to an asset host carries
// signed credentials in.
func redact(u *url.URL) string {
	c := *u
	c.RawQuery, c.ForceQuery, c.Fragment, c.User = "", false, "", nil
	return c.String()
}

// MaxMessageBytes bounds the message of the phase annotation.
const MaxMessageBytes = 256

// FormatPhase is the phase annotation value: "<phase>", or "<phase>: <msg>"
// with msg's control characters removed and clipped to MaxMessageBytes at a
// rune boundary.
func FormatPhase(phase updatesv1alpha1.UpdateNodePhase, msg string) string {
	msg = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, msg))
	if len(msg) > MaxMessageBytes {
		cut := MaxMessageBytes
		for cut > 0 && !utf8.RuneStart(msg[cut]) {
			cut--
		}
		msg = msg[:cut]
	}
	if msg == "" {
		return string(phase)
	}
	return string(phase) + ": " + msg
}

// ParsePhase splits a phase annotation value into its phase and message.
func ParsePhase(v string) (updatesv1alpha1.UpdateNodePhase, string) {
	p, msg, _ := strings.Cut(v, ":")
	return updatesv1alpha1.UpdateNodePhase(strings.TrimSpace(p)), strings.TrimSpace(msg)
}
