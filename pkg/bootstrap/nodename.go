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

package bootstrap

import (
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// ErrInvalidNodeName is wrapped by every error CanonicalNodeName returns.
var ErrInvalidNodeName = errors.New("bootstrap: invalid node name")

// maxNodeNameQuote bounds how much of a refused name an error quotes, so a
// megabyte of garbage in a request does not become a megabyte of log line.
const maxNodeNameQuote = 64

// CanonicalNodeName returns the one canonical FORM of a node name, or an error
// wrapping ErrInvalidNodeName. Every comparison and every lookup keyed on a
// node name is meant to run on this form, so "the same name" has exactly one
// definition.
//
// The order of the checks is load-bearing:
//
//  1. Any byte >= 0x80 is refused before anything else happens, so no Unicode
//     case folding or space trimming can ever run on the input. Folding is what
//     makes U+212A KELVIN SIGN compare equal to "k", and Unicode trimming is
//     what strips U+00A0 and U+0085; neither belongs anywhere near an identity.
//  2. Any ASCII control byte (0x00-0x1F, 0x7F) is refused wherever it sits, a
//     trailing newline or tab included: it is refused, never trimmed.
//  3. Only ASCII spaces are trimmed from the ends.
//  4. ASCII letters are lowercased byte by byte.
//  5. The result must be a non-empty DNS-1123 subdomain of at most 253 bytes,
//     which is exactly the rule the Kubernetes Node object enforces; no
//     stricter per-label cap is added, so every name upstream accepts is
//     accepted here. A trailing dot is refused with its own message because it is the most
//     common way a fully-qualified hostname slips in.
//
// This is the canonical form only. Whether a name is short enough to also
// carry a node-password binding is a separate, later check.
func CanonicalNodeName(name string) (string, error) {
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 0x80:
			return "", fmt.Errorf("%w: %s contains a non-ASCII byte", ErrInvalidNodeName, quoteNodeName(name))
		case c < 0x20 || c == 0x7f:
			return "", fmt.Errorf("%w: %s contains a control character", ErrInvalidNodeName, quoteNodeName(name))
		}
	}
	trimmed := strings.Trim(name, " ")
	b := []byte(trimmed)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	canon := string(b)
	switch {
	case canon == "":
		return "", fmt.Errorf("%w: the name is empty", ErrInvalidNodeName)
	case strings.HasSuffix(canon, "."):
		return "", fmt.Errorf("%w: %s ends in a dot; use the name without it", ErrInvalidNodeName, quoteNodeName(canon))
	case len(canon) > validation.DNS1123SubdomainMaxLength:
		return "", fmt.Errorf("%w: the name is %d bytes, longer than %d", ErrInvalidNodeName, len(canon), validation.DNS1123SubdomainMaxLength)
	}
	if errs := validation.IsDNS1123Subdomain(canon); len(errs) > 0 {
		return "", fmt.Errorf("%w: %s is not a lowercase DNS-1123 subdomain", ErrInvalidNodeName, quoteNodeName(canon))
	}
	return canon, nil
}

// quoteNodeName renders a refused name for an error: Go-quoted, so no control
// byte or invalid UTF-8 reaches a log raw, and truncated to maxNodeNameQuote
// bytes.
func quoteNodeName(name string) string {
	if len(name) > maxNodeNameQuote {
		return fmt.Sprintf("%q...", name[:maxNodeNameQuote])
	}
	return fmt.Sprintf("%q", name)
}
