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
	"context"
	"fmt"
	"strconv"
	"strings"

	"k3sm.io/k3sm/pkg/keystore"
)

// keysFloorRebuild is `k3sm keys floor --rebuild`, the root maintenance
// verb that rebuilds the user-scope floor log (docs/design/keystore.md §
// "Root maintenance verbs"). keysFloor hands it every floor invocation but
// floor merge, so its usage line names both forms.
func keysFloorRebuild(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("floor", env)
	if v.env.audit != nil {
		v.env.audit.op = "floor-rebuild"
	}
	rebuild := v.fs.Bool("rebuild", false, "rebuild the user-scope floor log")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	if len(pos) != 0 || !*rebuild {
		return v.failf(keysBadUsage, "usage: %s, or %s", keysFloorRebuildUsage, keysFloorMergeUsage)
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	rep, err := s.RebuildFloor(env.earlierRuns(ctx), env.attrWriter())
	if err != nil && !keystore.Committed(err) {
		return v.failf(keysRefused, "%v", err)
	}
	fmt.Fprintf(env.stdout, "rebuilt the user-scope floor: %d scopes, %d keys\n", rep.Scopes, rep.Keys)
	if err != nil {
		printRebuildDrops(env, rep)
		return v.failf(keysCommitted, "%v", err)
	}
	if !rep.Lost() {
		return keysOK
	}
	printRebuildDrops(env, rep)
	fmt.Fprintln(env.stdout, "the rebuild dropped what is listed above; the new floor is in place (exit 4)")
	return keysCommitted
}

// printRebuildDrops prints the rebuild's drop counts, by class.
func printRebuildDrops(env keysEnv, rep keystore.RebuildReport) {
	for _, d := range []struct {
		n    int
		what string
	}{
		{rep.Dropped, "lines of the old floor that did not parse (a torn last line included)"},
		{rep.OverLong, "lines of the old floor over the per-line bound"},
		{rep.ForgedLive, "live lines with no key on disk, past the floor's key bound (forged live keys)"},
		{rep.RemovedKeys, "keys of user scopes root removed"},
	} {
		if d.n > 0 {
			fmt.Fprintf(env.stdout, "dropped %d %s\n", d.n, d.what)
		}
	}
}

// earlierRuns returns ctx carrying the report of a committed maintenance
// run of the other verb that a verb finds in the marker: printed to
// stderr before the marker is replaced (keystore.WithEarlierRun).
func (env keysEnv) earlierRuns(ctx context.Context) context.Context {
	return keystore.WithEarlierRun(ctx, func(r keystore.EarlierRun) {
		fmt.Fprintf(env.stderr, "k3sm keys: %s\n", r)
	})
}

// keysAuditVerb is `k3sm keys audit --rotate [--discard-oldest]`, the root
// maintenance verb that moves the audit log aside to keystore-audit.log.1,
// keeping four archives, and flags a new, empty log append-only.
func keysAuditVerb(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("audit", env)
	rotate := v.fs.Bool("rotate", false, "rotate the audit log, keeping four archives")
	discard := v.fs.Bool("discard-oldest", false, "delete the oldest archive, keystore-audit.log.4, to make room")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	if len(pos) != 0 || !*rotate {
		return v.failf(keysBadUsage, "usage: sudo k3sm keys audit --rotate [--discard-oldest]")
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	rep, err := s.RotateAudit(env.earlierRuns(ctx), env.attrWriter(), *discard)
	if err != nil && !keystore.Committed(err) {
		return v.failf(keysRefused, "%v", err)
	}
	if rep.Discarded {
		fmt.Fprintln(env.stdout, "discarded the oldest audit archive")
	}
	fmt.Fprintf(env.stdout, "rotated the audit log: %d archives kept, keystore-audit.log.1 the newest\n", rep.Archives)
	if err != nil {
		return v.failf(keysCommitted, "%v", err)
	}
	return keysOK
}

// attrWriter is the file-attribute writer the maintenance verbs act
// through: the env's, or the seam.
func (env keysEnv) attrWriter() keystore.FileAttrWriter {
	if env.attrs != nil {
		return env.attrs
	}
	return fileAttrSeam
}

// keysRmScope is `k3sm keys rm-scope user/<uid> --yes`, the root verb that
// removes a user scope.
func keysRmScope(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("rm-scope", env)
	yes := v.fs.Bool("yes", false, "confirm: remove the scope and every entry in it")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	if len(pos) != 1 {
		return v.failf(keysBadUsage, "usage: sudo k3sm keys rm-scope user/<uid> --yes")
	}
	uid, ok := parseScopeArg(pos[0])
	if !ok {
		return v.failf(keysBadUsage, "the scope is not user/<decimal uid> (it is not echoed)")
	}
	if !*yes {
		return v.failf(keysBadUsage, "removing user/%d removes every entry in it and cannot be undone: pass --yes", uid)
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	recorded, err := s.RemoveScope(ctx, uid)
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	if !recorded {
		fmt.Fprintf(env.stdout, "removed user/%d, but the removed-scopes record is full, so it is not listed: a copy of its directory put back would open, and floor --rebuild keeps its floor keys\n", uid)
		return keysOK
	}
	fmt.Fprintf(env.stdout, "removed user/%d; run sudo k3sm keys floor --rebuild to free its floor keys\n", uid)
	return keysOK
}

// parseScopeArg parses user/<uid>, the uid canonical decimal.
func parseScopeArg(a string) (uint32, bool) {
	rest, ok := strings.CutPrefix(a, "user/")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(rest, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != rest {
		return 0, false
	}
	return uint32(n), true
}
