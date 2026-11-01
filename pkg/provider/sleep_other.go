//go:build !(darwin && cgo)

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

package provider

import (
	"context"
	"errors"
)

// errPowerUnsupported is returned by the host on a build with no power API.
var errPowerUnsupported = errors.New("system power management is not available on this build")

// unsupportedPowerHost is the PowerHost of a build without IOKit (a non-darwin
// or CGO_ENABLED=0 build): it holds no assertion and delivers no notices.
type unsupportedPowerHost struct{}

func newPowerHost() PowerHost { return unsupportedPowerHost{} }

// PreventSleep implements PowerHost; it always fails.
func (unsupportedPowerHost) PreventSleep(string) (func() error, error) {
	return nil, errPowerUnsupported
}

// PowerSource implements PowerHost; the source is unknown.
func (unsupportedPowerHost) PowerSource() PowerSource { return PowerSourceUnknown }

// WatchSleep implements PowerHost; it always fails.
func (unsupportedPowerHost) WatchSleep(context.Context) (<-chan PowerNotice, error) {
	return nil, errPowerUnsupported
}
