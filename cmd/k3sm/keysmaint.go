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
)

// keysFloor is `k3sm keys floor --rebuild`, the root maintenance verb that
// rebuilds the user-scope floor log (docs/design/keystore.md § "Root
// maintenance verbs").
func keysFloor(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("floor", env)
	rebuild := v.fs.Bool("rebuild", false, "rebuild the user-scope floor log")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	if len(pos) != 0 || !*rebuild {
		return v.failf(keysBadUsage, "usage: sudo k3sm keys floor --rebuild")
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	attrs := env.attrs
	if attrs == nil {
		attrs = fileAttrSeam
	}
	rep, err := s.RebuildFloor(ctx, attrs)
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	fmt.Fprintf(env.stdout, "rebuilt the user-scope floor: %d scopes, %d keys\n", rep.Scopes, rep.Keys)
	if rep.Dropped > 0 {
		fmt.Fprintf(env.stdout, "dropped %d lines of the old floor that did not parse\n", rep.Dropped)
	}
	if rep.RemovedKeys > 0 {
		fmt.Fprintf(env.stdout, "dropped %d keys of removed user scopes\n", rep.RemovedKeys)
	}
	return keysOK
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
	if err := s.RemoveScope(ctx, uid); err != nil {
		return v.failf(keysRefused, "%v", err)
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
