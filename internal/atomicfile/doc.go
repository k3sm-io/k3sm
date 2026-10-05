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

// Package atomicfile installs a file at a path that must not already exist, so a
// reader sees either no file or all of it, and an existing file is never replaced.
// It is the one home of k3sm's temp-file + fsync + link(2) + directory-fsync install,
// used for CA keypairs and the server-bootstrap secret.
//
// A temp file lives beside its target as ".<name>.tmp-<digits>". WriteNew removes it
// on every return; only a hard kill between its creation and that removal can leave
// one behind, and ReapOrphans is how a later run removes it.
package atomicfile
