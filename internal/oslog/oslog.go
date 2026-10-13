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

package oslog

// Subsystem is the unified-log subsystem every k3sm line is written under.
const Subsystem = "io.k3sm"

// Level is the os_log type a line is written at.
type Level int

const (
	// Default is OS_LOG_TYPE_DEFAULT, the level persisted to the log store.
	Default Level = 0x00
	// Error is OS_LOG_TYPE_ERROR.
	Error Level = 0x10
)
