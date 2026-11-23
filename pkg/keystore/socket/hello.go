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

// The HELLO exchange. The client opens with
// {"proto":"k3sm-keys","min":1,"max":1}; the server answers with the highest
// version both support and its frame cap,
// {"proto":"k3sm-keys","version":1,"max_frame":131072}, or with error code
// unsupported-version when the ranges do not meet.
const (
	// Proto is the protocol name both HELLO headers carry.
	Proto = "k3sm-keys"
	// MinVersion and MaxVersion are the range of versions this server speaks.
	MinVersion = 1
	MaxVersion = 1
)

// helloRequest is the client's HELLO header.
type helloRequest struct {
	Proto string `json:"proto"`
	Min   int    `json:"min"`
	Max   int    `json:"max"`
}

// HelloReply is the server's HELLO header.
type HelloReply struct {
	Proto    string `json:"proto"`
	Version  int    `json:"version"`
	MaxFrame int    `json:"max_frame"`
}

// selectVersion returns the highest version in both ranges, and false when
// they do not overlap (an inverted range overlaps nothing).
func selectVersion(clientMin, clientMax, serverMin, serverMax int) (int, bool) {
	lo, hi := max(clientMin, serverMin), min(clientMax, serverMax)
	if lo > hi {
		return 0, false
	}
	return hi, true
}
