//go:build !(darwin && cgo)

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

package netdsvc

// SystemStore is the resolverPublisher stand-in on a build without the darwin
// SystemConfiguration binding: every call reports ErrNodeResolverUnsupported.
type SystemStore struct{}

// OpenSystemStore reports ErrNodeResolverUnsupported.
func OpenSystemStore() (*SystemStore, error) { return nil, ErrNodeResolverUnsupported }

// Publish reports ErrNodeResolverUnsupported.
func (*SystemStore) Publish(string, ResolverEntry) error { return ErrNodeResolverUnsupported }

// Remove reports ErrNodeResolverUnsupported.
func (*SystemStore) Remove(string) error { return ErrNodeResolverUnsupported }

// Present reports ErrNodeResolverUnsupported.
func (*SystemStore) Present(string) (bool, error) { return false, ErrNodeResolverUnsupported }

// Close is a no-op.
func (*SystemStore) Close() error { return nil }
