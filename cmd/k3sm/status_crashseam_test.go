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

import "testing"

// TestStatusCollectorsWireTheCrashRecordReader pins that every production
// status collector sets the crash record seam: a nil seam silently skips the
// crash-loop read, so a constructor that forgot it would lose detection.
func TestStatusCollectorsWireTheCrashRecordReader(t *testing.T) {
	if newStatusCollector().ReadCrashRecord == nil {
		t.Error("newStatusCollector: ReadCrashRecord is nil")
	}
	if newDaemonsCollector().ReadCrashRecord == nil {
		t.Error("newDaemonsCollector: ReadCrashRecord is nil")
	}
}
