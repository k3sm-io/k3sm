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

// Package atomicfile installs a file at a path through a temp file beside it, so a
// reader sees either the old file or all of the new one. It is the one home of
// k3sm's temp-file + fsync + link(2)/rename(2) + directory-fsync install: WriteNew
// (never replaces; CA keypairs and the server-bootstrap secret), Replace (re-issued
// material), and InstallFile / InstallReader, through which every executable or
// dylib k3sm writes goes, so a binary is never rewritten in place (see
// InstallReader for why that kills processes on macOS). The one other binary
// writer is `k3sm install`, which builds a whole staged tree and swaps it in with
// one rename, so it too never rewrites a live inode. TestNoInPlaceBinaryWrites
// guards the rule.
//
// A temp file lives beside its target as ".<name>.tmp-<digits>". WriteNew removes it
// on every return; only a hard kill between its creation and that removal can leave
// one behind, and ReapOrphans is how a later run removes it.
package atomicfile
