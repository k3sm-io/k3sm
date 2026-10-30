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

// Package racewitness holds a planted data race. hack/ci.sh runs this test with
// the same flags as the repo's own tests and requires the race detector to
// report it, which proves the gate's race detection is live.
package racewitness

import "testing"

func TestPlantedRace(t *testing.T) {
	var n int
	done := make(chan struct{})
	go func() {
		n++
		close(done)
	}()
	n++
	<-done
	_ = n
}
