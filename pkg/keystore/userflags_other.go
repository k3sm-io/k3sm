//go:build !darwin

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
	"os"
	"syscall"
)

// clearUserFlags is a no-op off Darwin: BSD user flags are a Darwin feature.
func clearUserFlags(context.Context, *os.Root, string, uint32) ([]string, error) { return nil, nil }

// Off Darwin there are no user flags, so rm-scope clears none.
const (
	userLockingFlags = 0
	maxFlagOpens     = 4096
	oSymlink         = 0
	sfFlagsMask      = 0
)

// flagOpenLimit is maxFlagOpens.
var flagOpenLimit = maxFlagOpens

// scopeFchflags is never called off Darwin: no file carries a user flag.
var scopeFchflags = func(int, int) error { return nil }

// setFlagsAt is never called off Darwin: no file carries a user flag.
var setFlagsAt = func(int, string, uint32) error { return nil }

// statImmutable reports no flag: a build off darwin reads none.
func statImmutable(*syscall.Stat_t) bool { return false }
