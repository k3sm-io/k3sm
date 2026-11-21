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

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"
	"testing"
)

// The tests run as a non-root user or as root. Non-root, the running user is
// both the service user and the floor's owner, as no other owner can be made.
// As root they take the deployment's shape: root runs the verbs and owns the
// data root and the floor, another uid owns the store, and every chown is
// real.

const (
	// testUIDEnv and testGIDEnv name the service user a root run uses, both
	// or neither; unset, it is the local user serviceUserName.
	testUIDEnv = "K3SM_KEYSTORE_TEST_UID"
	testGIDEnv = "K3SM_KEYSTORE_TEST_GID"
	// serviceUserName is the service user a k3sm install creates.
	serviceUserName = "_k3sm"
)

// asRoot reports whether the tests run as root.
func asRoot() bool { return os.Geteuid() == 0 }

// serviceIdentity is the service user resolved once per test binary: its
// ids, or why a root run has none (skip), or a malformed setting (err).
type serviceIdentity struct {
	uid, gid uint32
	skip     string
	err      error
}

var resolveService = sync.OnceValue(func() serviceIdentity {
	if !asRoot() {
		return serviceIdentity{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	}
	u, uSet := os.LookupEnv(testUIDEnv)
	g, gSet := os.LookupEnv(testGIDEnv)
	switch {
	case uSet && gSet:
		uid, err := parseID(testUIDEnv, u)
		if err != nil {
			return serviceIdentity{err: err}
		}
		gid, err := parseID(testGIDEnv, g)
		if err != nil {
			return serviceIdentity{err: err}
		}
		if uid == 0 {
			return serviceIdentity{err: fmt.Errorf("%s is 0: the service user is never root", testUIDEnv)}
		}
		return serviceIdentity{uid: uid, gid: gid}
	case uSet || gSet:
		return serviceIdentity{err: fmt.Errorf("set both %s and %s, or neither", testUIDEnv, testGIDEnv)}
	}
	su, err := user.Lookup(serviceUserName)
	if err != nil {
		return serviceIdentity{skip: fmt.Sprintf("running as root needs a service user: set %s and %s, or create the local user %s (%v)", testUIDEnv, testGIDEnv, serviceUserName, err)}
	}
	uid, err := parseID("the uid of "+serviceUserName, su.Uid)
	if err != nil {
		return serviceIdentity{err: err}
	}
	gid, err := parseID("the gid of "+serviceUserName, su.Gid)
	if err != nil {
		return serviceIdentity{err: err}
	}
	if uid == 0 {
		return serviceIdentity{err: fmt.Errorf("the local user %s is uid 0: the service user is never root", serviceUserName)}
	}
	return serviceIdentity{uid: uid, gid: gid}
})

func parseID(what, s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a uint32: %w", what, s, err)
	}
	return uint32(n), nil
}

// serviceIDs returns the uid and gid the tests' stores belong to: the running
// user's when not root; as root, those testUIDEnv and testGIDEnv give, or
// else serviceUserName's. A root run with neither skips the test.
func serviceIDs(tb testing.TB) (uid, gid uint32) {
	tb.Helper()
	id := resolveService()
	switch {
	case id.err != nil:
		tb.Fatal(id.err)
	case id.skip != "":
		tb.Skip(id.skip)
	}
	return id.uid, id.gid
}

// floorIDs returns the floor's and data root's owner: root when the tests run
// as root, as in production, and the running user otherwise, which cannot
// make a root-owned file.
func floorIDs() (uid, gid uint32) {
	if asRoot() {
		return 0, 0
	}
	return uint32(os.Getuid()), uint32(os.Getgid())
}

// otherUID returns a uid that is neither the service user's nor the running
// user's, for a test that needs a third owner.
func otherUID(tb testing.TB) uint32 {
	tb.Helper()
	svc, _ := serviceIDs(tb)
	uid := svc + 1
	for uid == uint32(os.Geteuid()) || uid == svc {
		uid++
	}
	return uid
}

// giveToService hands each path to the service user, as a directory or file
// the service user made would be. Non-root, the running user already is the
// service user, and nothing changes.
func giveToService(tb testing.TB, paths ...string) {
	tb.Helper()
	if !asRoot() {
		return
	}
	uid, gid := serviceIDs(tb)
	for _, p := range paths {
		if err := os.Lchown(p, int(uid), int(gid)); err != nil {
			tb.Fatal(err)
		}
	}
}
