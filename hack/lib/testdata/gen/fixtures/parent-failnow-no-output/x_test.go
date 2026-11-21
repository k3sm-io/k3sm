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

// Fixture for the parent-failnow-no-output corpus case: TestParent/a fails with
// the recorded signature, and TestParent itself then fails through t.Fail,
// which writes no output line.
package v1

import "testing"

func TestParent(t *testing.T) {
	t.Run("a", func(t *testing.T) {
		t.Error("read udp 127.0.0.1: i/o timeout")
	})
	t.Run("b", func(t *testing.T) {})
	t.Fail()
}
