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

// Fixture for the repeated-fail-then-skip corpus case: run under -count=2, the
// first run of TestFlake fails and the second skips.
package v1

import "testing"

var runs int

func TestFlake(t *testing.T) {
	runs++
	if runs == 1 {
		t.Error("read udp 127.0.0.1: i/o timeout")
		return
	}
	t.Skip("port unavailable")
}

func TestOK(t *testing.T) {}
