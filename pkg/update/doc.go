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

// Package update answers "is there a newer k3sm, and which nodes are not on
// it?". Check resolves the latest release exactly the way install.sh does,
// reads the version of this binary and of every Node, and compares them. It
// only reads: downloading and installing a release is not this package's job.
//
// The tag a release index answers with is data. It is validated to the
// characters a git version tag carries and is never handed to a shell or a
// file path; the one place it is spliced is a URL path segment, escaped.
package update
