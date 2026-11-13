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

package install

import "errors"

// ErrFileTooLarge is what ReadOwnedRegularFile reports for a regular file over
// its size limit, whether the fstat said so or the file grew past it during the
// read. It is a sentinel so a caller can tell the size refusal apart from a
// read that failed for any other reason (EIO, EACCES) after the file was
// opened and judged regular.
var ErrFileTooLarge = errors.New("larger than the read limit")
