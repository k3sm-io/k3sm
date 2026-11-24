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

// Package strictjson reads a JSON object's fields by their exact names, the
// one rule the keystore's readers of untrusted JSON share: the audit log's
// reader (whose lines a writer outside the store can forge) and the user
// socket's request headers. encoding/json matches a struct's keys
// case-insensitively and lets the last of two keys win, so two readers of
// the same bytes can disagree on a field; with Object in front, they
// cannot.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Object reads b, which must be one JSON object and nothing after it, and
// returns the raw value of each name in known that it gives, a null left
// as given. It is an error when any two keys, known or not, are the same
// under encoding/json's case folding (a key given twice), or when a key
// that folds to a known name is spelled otherwise. Every other key is
// ignored.
func Object(b []byte, known ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	out := make(map[string]json.RawMessage, len(known))
	var seen []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("a key is not a string")
		}
		for _, k := range seen {
			if strings.EqualFold(k, key) {
				return nil, fmt.Errorf("the key %s is given twice", quoteKnown(key, known))
			}
		}
		seen = append(seen, key)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		for _, k := range known {
			if !strings.EqualFold(k, key) {
				continue
			}
			if k != key {
				return nil, fmt.Errorf("the key %s is spelled in another case", k)
			}
			out[k] = v
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the object")
	}
	return out, nil
}

// quoteKnown names key in an error as the known name it folds to, or as
// "(unknown)": an error never echoes a key the writer chose.
func quoteKnown(key string, known []string) string {
	for _, k := range known {
		if strings.EqualFold(k, key) {
			return k
		}
	}
	return "(unknown)"
}
