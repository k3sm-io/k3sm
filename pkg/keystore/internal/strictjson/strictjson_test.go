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

package strictjson

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Object returns each known field exactly as given, ignores unknown keys,
// and refuses anything but one object whose keys are each given once
// under case folding and whose known keys are spelled exactly.
func TestObject(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		ok       bool
		op       string // the raw value of "op" when ok
	}{
		{"exact", `{"op":"rm","x":1}`, true, `"rm"`},
		{"null kept as given", `{"op":null}`, true, `null`},
		{"absent", `{"x":1}`, true, ``},
		{"nested keys are not judged", `{"op":"rm","x":{"a":1,"A":2}}`, true, `"rm"`},
		{"trailing space", `{"op":"rm"} `, true, `"rm"`},
		{"known in another case", `{"Op":"rm"}`, false, ``},
		{"known given twice", `{"op":"rm","op":"list"}`, false, ``},
		{"known twice in another case", `{"op":"rm","OP":"list"}`, false, ``},
		{"unknown given twice in any case", `{"x":1,"X":2}`, false, ``},
		{"not an object", `["op"]`, false, ``},
		{"null", `null`, false, ``},
		{"data after", `{"op":"rm"}{}`, false, ``},
		{"truncated", `{"op":"rm"`, false, ``},
	} {
		got, err := Object([]byte(tc.in), "op", "entry")
		if (err == nil) != tc.ok {
			t.Errorf("%s: Object(%s) = %v, want ok %v", tc.name, tc.in, err, tc.ok)
			continue
		}
		if tc.ok && !bytes.Equal(got["op"], json.RawMessage(tc.op)) {
			t.Errorf("%s: op = %s, want %s", tc.name, got["op"], tc.op)
		}
		if err != nil && bytes.Contains([]byte(err.Error()), []byte("X")) {
			t.Errorf("%s: the error %q echoes a key the writer chose", tc.name, err)
		}
	}
}
