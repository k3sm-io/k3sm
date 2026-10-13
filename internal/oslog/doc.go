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

// Package oslog writes a line to the macOS unified log (os_log) under the
// io.k3sm subsystem, so an operator finds k3sm's lifecycle events with
// `log show --predicate 'subsystem == "io.k3sm"'` beside the slog output.
//
// It is the one cgo call k3sm makes for logging: os_log is a C macro with no Go
// binding. A build without cgo, or on another OS, compiles a no-op, and so does
// a message the C side cannot take (one with a NUL byte).
package oslog
