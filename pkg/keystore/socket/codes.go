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

package socket

// Code is an error reply's code. The set is closed and reserved: a server
// sends no other, and a client maps a code it does not know to a generic
// failure that prints it.
type Code string

// The error codes of k3sm-keys/1.
const (
	CodeNotFound           Code = "not-found"
	CodeQuota              Code = "quota"
	CodeBusy               Code = "busy"
	CodeLogFull            Code = "log-full"
	CodeScopeOwnerChanged  Code = "scope-owner-changed"
	CodeScopeOwnerUnknown  Code = "scope-owner-unknown"
	CodeUserScopeOff       Code = "user-scope-off"
	CodeRateLimited        Code = "rate-limited"
	CodeRefused            Code = "refused"
	CodeUnsupportedVersion Code = "unsupported-version"
	CodeUnknownOp          Code = "unknown-op"
	CodeInternal           Code = "internal"
)

// errorHeader is a TypeError frame's header.
type errorHeader struct {
	Code Code `json:"code"`
}
