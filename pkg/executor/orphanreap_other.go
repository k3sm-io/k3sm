//go:build !darwin || !cgo

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

package executor

import (
	"errors"
	"syscall"
	"time"
)

// errOrphanScanUnavailable is what list returns on a build that cannot read
// executable paths (a non-darwin or CGO_ENABLED=0 build). The reap then proves
// nothing is ours and leaves every holder to the preflight refusal.
var errOrphanScanUnavailable = errors.New("executor: this build cannot read process executable paths")

// defaultOrphanSeams on a build that cannot read executable paths: the list is
// refused, so the reap proves nothing is ours and every holder keeps the
// preflight refusal.
var defaultOrphanSeams = orphanSeams{
	list:   func() ([]orphanProc, error) { return nil, errOrphanScanUnavailable },
	lookup: func(int) (orphanProc, bool) { return orphanProc{}, false },
	kill:   func(int, syscall.Signal) error { return errOrphanScanUnavailable },
}

// ProcessStartTime is unavailable on this build; the zero time makes every
// process "not older than this server", so nothing is reaped.
func ProcessStartTime() (time.Time, error) { return time.Time{}, nil }
