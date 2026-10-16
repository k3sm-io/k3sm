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

// Package buildledger keeps the history of `k3sm build`: one JSON record per
// build, written when the build starts and rewritten when it finishes, in a
// directory owned by the user who ran the build.
//
// The ledger is a record of what was attempted, never an input to a build: a
// write that fails is reported by the caller and the build goes on.
package buildledger
