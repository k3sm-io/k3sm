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

package keystore

import "errors"

// hasExtendedACL reports no ACL: a build without darwin's acl(3) has no
// extended ACL to read. A k3sm build is darwin with cgo, where acl_darwin.go
// reads it.
func hasExtendedACL(int) (bool, error) { return false, nil }

// errNoACLRead is linkHasExtendedACL's answer in a build that cannot read
// an ACL: unknown, so a repair it names includes removing one.
var errNoACLRead = errors.New("this build reads no ACL")

// linkHasExtendedACL cannot tell: a build without darwin's acl(3) reads no
// ACL by path.
func linkHasExtendedACL(string) (bool, error) { return false, errNoACLRead }

// removeExtendedACL removes nothing: a build without darwin's acl(3)
// cannot. Where fdHasACL still reads an ACL (darwin without cgo), the
// judge that follows refuses the file, so the build fails closed.
func removeExtendedACL(int) error { return nil }
