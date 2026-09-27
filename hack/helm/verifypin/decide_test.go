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

package main

import (
	"strings"
	"testing"
)

func TestDecide(t *testing.T) {
	const asset = "helm-v4.3.0-darwin-arm64.tar.gz"
	pin := strings.Repeat("d", 64)
	cases := []struct {
		name string
		file string
		ok   bool
	}{
		{"matching line", pin + "  " + asset + "\n", true},
		{"binary-mode marker", pin + " *" + asset + "\n", true},
		{"other digest", strings.Repeat("e", 64) + "  " + asset + "\n", false},
		{"other asset", pin + "  helm-v4.3.0-darwin-amd64.tar.gz\n", false},
		{"empty", "", false},
		{"two lines", pin + "  " + asset + "\n" + pin + "  x\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decide(tc.file, asset, pin)
			if (err == nil) != tc.ok {
				t.Errorf("decide = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}
