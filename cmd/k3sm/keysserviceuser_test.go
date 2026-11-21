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

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"
	"testing"
)

// The keys tests drive the real keystore, laid out as pkg/keystore's tests
// lay it out (serviceuser_test.go there, which this copies rather than
// imports). Non-root, the running user is both the service user and the
// floor's owner, as no other owner can be made. As root they take the
// deployment's shape: root runs the verbs and owns the data root and the
// floor, another uid owns the store, and every chown is real.

const (
	// keysTestUIDEnv and keysTestGIDEnv name the service user a root run
	// uses, both or neither; unset, it is the local user keysServiceUserName.
	// They are pkg/keystore's, so one setting serves both packages.
	keysTestUIDEnv = "K3SM_KEYSTORE_TEST_UID"
	keysTestGIDEnv = "K3SM_KEYSTORE_TEST_GID"
	// keysServiceUserName is the service user a k3sm install creates.
	keysServiceUserName = "_k3sm"
)

// keysAsRoot reports whether the tests run as root.
func keysAsRoot() bool { return os.Geteuid() == 0 }

// keysServiceIdentity is the service user resolved once per test binary: its
// ids, or why a root run has none (skip), or a malformed setting (err).
type keysServiceIdentity struct {
	uid, gid uint32
	skip     string
	err      error
}

var keysResolveService = sync.OnceValue(func() keysServiceIdentity {
	if !keysAsRoot() {
		return keysServiceIdentity{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	}
	u, uSet := os.LookupEnv(keysTestUIDEnv)
	g, gSet := os.LookupEnv(keysTestGIDEnv)
	switch {
	case uSet && gSet:
		uid, err := keysParseID(keysTestUIDEnv, u)
		if err != nil {
			return keysServiceIdentity{err: err}
		}
		gid, err := keysParseID(keysTestGIDEnv, g)
		if err != nil {
			return keysServiceIdentity{err: err}
		}
		if uid == 0 {
			return keysServiceIdentity{err: fmt.Errorf("%s is 0: the service user is never root", keysTestUIDEnv)}
		}
		return keysServiceIdentity{uid: uid, gid: gid}
	case uSet || gSet:
		return keysServiceIdentity{err: fmt.Errorf("set both %s and %s, or neither", keysTestUIDEnv, keysTestGIDEnv)}
	}
	su, err := user.Lookup(keysServiceUserName)
	if err != nil {
		return keysServiceIdentity{skip: fmt.Sprintf("running as root needs a service user: set %s and %s, or create the local user %s (%v)", keysTestUIDEnv, keysTestGIDEnv, keysServiceUserName, err)}
	}
	uid, err := keysParseID("the uid of "+keysServiceUserName, su.Uid)
	if err != nil {
		return keysServiceIdentity{err: err}
	}
	gid, err := keysParseID("the gid of "+keysServiceUserName, su.Gid)
	if err != nil {
		return keysServiceIdentity{err: err}
	}
	if uid == 0 {
		return keysServiceIdentity{err: fmt.Errorf("the local user %s is uid 0: the service user is never root", keysServiceUserName)}
	}
	return keysServiceIdentity{uid: uid, gid: gid}
})

func keysParseID(what, s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a uint32: %w", what, s, err)
	}
	return uint32(n), nil
}

// keysServiceIDs returns the uid and gid the tests' stores belong to: the
// running user's when not root; as root, those keysTestUIDEnv and
// keysTestGIDEnv give, or else keysServiceUserName's. A root run with
// neither skips the test.
func keysServiceIDs(tb testing.TB) (uid, gid uint32) {
	tb.Helper()
	id := keysResolveService()
	switch {
	case id.err != nil:
		tb.Fatal(id.err)
	case id.skip != "":
		tb.Skip(id.skip)
	}
	return id.uid, id.gid
}

// keysFloorIDs returns the floor's and data root's owner: root when the tests
// run as root, as in production, and the running user otherwise, which
// cannot make a root-owned file.
func keysFloorIDs() (uid, gid int) {
	if keysAsRoot() {
		return 0, 0
	}
	return os.Getuid(), os.Getgid()
}

// keysGiveToService hands each path to the service user, as a directory or
// file the service user made would be. Non-root, the running user already is
// the service user, and nothing changes.
func keysGiveToService(tb testing.TB, paths ...string) {
	tb.Helper()
	if !keysAsRoot() {
		return
	}
	uid, gid := keysServiceIDs(tb)
	for _, p := range paths {
		if err := os.Lchown(p, int(uid), int(gid)); err != nil {
			tb.Fatal(err)
		}
	}
}
