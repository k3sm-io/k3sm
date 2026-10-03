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

// Package testgate is a test-only package that holds module-wide test gates:
// tests that scan the whole k3sm.io/k3sm module and so belong to no product
// package. It has no non-test code and nothing imports it.
//
// TestNoUntaggedRealSocketTests keeps real sockets out of the unit tier; its
// allowlist is testdata/realsocket.allow.
package testgate
