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

package store

import "k3sm.io/k3sm/pkg/ociregistry/ref"

// SetIndexRemoved sets the seam RemoveLayout runs right after index.json is
// removed, for the external crash test that drives it through a GC sweep.
func SetIndexRemoved(s *Store, fn func() error) { s.indexRemoved = fn }

// SetHalfFound sets the seam ReapHalfRemovedLayouts runs between finding a
// candidate and locking it.
func SetHalfFound(s *Store, fn func(n ref.Name)) { s.halfFound = fn }

// setLocalBlobResolved sets the seam LocalBlobSource.OpenBlob runs between
// resolving a blob's path and opening it.
func setLocalBlobResolved(l *LocalBlobSource, fn func(path string)) { l.resolved = fn }
