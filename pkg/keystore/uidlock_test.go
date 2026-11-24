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

package keystore

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

// A uid lock released twice is released once: the second call neither
// blocks nor frees another holder's lock.
func TestUIDUnlockIdempotent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		tbl := newUsageTable()
		unlock, err := tbl.lockUID(ctx, 1001, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		unlock()
		second, err := tbl.lockUID(ctx, 1001, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer second()
		done := make(chan struct{})
		go func() { unlock(); close(done) }()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("a second call of a released unlock blocked")
		}
		if _, err := tbl.lockUID(ctx, 1001, 10*time.Millisecond); err == nil {
			t.Fatal("a second call of a released unlock freed another holder's lock")
		}
	})
}
