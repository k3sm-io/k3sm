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
	"encoding"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"k3sm.io/apis/keystore/credential"
)

// Envelope and Credential carry secrets (RefreshToken, AccessToken, Value,
// Seed), so every way the standard library formats or encodes a value
// produces a redaction instead: String and GoString, Format for every fmt
// verb, LogValue for log/slog, and for the reflection encoders MarshalJSON
// (encoding/json, and so slog's JSON handler for a slice or map of them),
// MarshalText and GobEncode. The redaction names the kind, and each present
// field with its length, and never a byte of any field. There is no
// matching decoder: nothing round-trips a secret through these encoders.
//
// One path no method can close: fmt and the reflection encoders cannot call
// a method on an unexported struct field, so a struct with an unexported
// field of either type prints its bytes under %v. pkg/keystore declares no
// such field, and TestNoUnexportedSecretField holds it to that.

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

// MarshalJSON returns String as a JSON string.
func (e Envelope) MarshalJSON() ([]byte, error) { return json.Marshal(e.String()) }

// MarshalText returns String.
func (e Envelope) MarshalText() ([]byte, error) { return []byte(e.String()), nil }

// GobEncode returns String.
func (e Envelope) GobEncode() ([]byte, error) { return []byte(e.String()), nil }

// MarshalJSON returns String as a JSON string.
func (c Credential) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// MarshalText returns String.
func (c Credential) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// GobEncode returns String.
func (c Credential) GobEncode() ([]byte, error) { return []byte(c.String()), nil }

var (
	_ json.Marshaler         = Envelope{}
	_ encoding.TextMarshaler = Envelope{}
	_ gob.GobEncoder         = Envelope{}
	_ json.Marshaler         = Credential{}
	_ encoding.TextMarshaler = Credential{}
	_ gob.GobEncoder         = Credential{}
	_ fmt.Stringer           = Envelope{}
	_ fmt.GoStringer         = Envelope{}
	_ fmt.Formatter          = Envelope{}
	_ slog.LogValuer         = Envelope{}
	_ fmt.Stringer           = Credential{}
	_ fmt.GoStringer         = Credential{}
	_ fmt.Formatter          = Credential{}
	_ slog.LogValuer         = Credential{}
)
