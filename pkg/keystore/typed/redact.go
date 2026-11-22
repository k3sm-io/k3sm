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

package typed

import (
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"k3sm.io/apis/keystore/credential"
)

// Envelope and Credential carry secrets (RefreshToken, AccessToken, Value,
// Seed), so every way the standard library formats a value prints a
// redaction instead: String and GoString, Format for every fmt verb, and
// LogValue for log/slog. The redaction names the kind, and each present
// field with its length, and never a byte of any field.

// kindOrder is the order redact tries the typed kinds in.
var kindOrder = []credential.Kind{credential.KindToken, credential.KindSSH, credential.KindOAuth}

// redact is the redacted form of e, under the type name typeName.
func redact(typeName string, e *Envelope) string {
	var (
		kinds []string
		parts []string
	)
	for _, k := range kindOrder {
		present := false
		fs := fields[k]
		for i := range fs {
			v, ok := fs[i].get(e)
			if !ok {
				continue
			}
			present = true
			parts = append(parts, fs[i].name+": "+strconv.Itoa(len(v))+" bytes")
		}
		if present {
			kinds = append(kinds, string(k))
		}
	}
	kind := "none"
	switch len(kinds) {
	case 0:
	case 1:
		kind = kinds[0]
	default:
		kind = "mixed " + strings.Join(kinds, "+")
	}
	return typeName + "{kind: " + kind + strings.Join(append([]string{""}, parts...), ", ") + "}"
}

// String returns e redacted: its kind and each present field's length.
func (e Envelope) String() string { return redact("typed.Envelope", &e) }

// GoString is String, for %#v.
func (e Envelope) GoString() string { return e.String() }

// Format writes String for every verb, so no verb or flag prints a field.
func (e Envelope) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, e.String()) }

// LogValue is String, for log/slog.
func (e Envelope) LogValue() slog.Value { return slog.StringValue(e.String()) }

// String returns c redacted: its kind and each present field's length.
func (c Credential) String() string { return redact("typed.Credential", &Envelope{Credential: c}) }

// GoString is String, for %#v.
func (c Credential) GoString() string { return c.String() }

// Format writes String for every verb, so no verb or flag prints a field.
func (c Credential) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue is String, for log/slog.
func (c Credential) LogValue() slog.Value { return slog.StringValue(c.String()) }

var (
	_ fmt.Stringer   = Envelope{}
	_ fmt.GoStringer = Envelope{}
	_ fmt.Formatter  = Envelope{}
	_ slog.LogValuer = Envelope{}
	_ fmt.Stringer   = Credential{}
	_ fmt.GoStringer = Credential{}
	_ fmt.Formatter  = Credential{}
	_ slog.LogValuer = Credential{}
)
