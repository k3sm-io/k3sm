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

package main

import "errors"

// errUnsupported is returned when the Security framework is not linked.
var errUnsupported = errors.New("the Security framework probe needs darwin and cgo")

// check refuses: without cgo there is no Security framework.
func check(_, _ string) (CheckResult, error) { return CheckResult{}, errUnsupported }

// info refuses: without cgo there is no Security framework.
func info(_ string) (InfoResult, error) { return InfoResult{}, errUnsupported }
