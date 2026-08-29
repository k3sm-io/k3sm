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

package executor

// processExited has no non-darwin implementation: k3sm targets darwin/arm64, and
// the darwin build reads kern.proc.pid. Reporting false everywhere else means the
// health deadline behaves exactly as it did before the probe existed — the
// conservative direction — and keeps this package cross-compilable.
func processExited(int) bool { return false }
