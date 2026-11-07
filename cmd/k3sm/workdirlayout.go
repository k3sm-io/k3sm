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
	"errors"
	"fmt"
	"path/filepath"
)

// ErrWorkDirLayout reports a --work-dir whose base name is not the one its role
// requires, so the pod sandbox's deny of the role's state directory would not
// cover it.
var ErrWorkDirLayout = errors.New("work dir is outside the pod sandbox's deny")

// checkWorkDirLayout refuses a work dir whose base name is not subdir
// (sandbox.ServerSubdir for a server, sandbox.AgentSubdir for an agent).
//
// The pod sandbox denies <data root>/server and <data root>/agent, where the
// data root is the work dir's parent (executor.RuntimeRoot). Pods, the registry
// and runtimed run as one uid, so that deny is all that keeps a pod out of the
// CA keys, the datastore and the registry store under the work dir. A work dir
// under any other name, /data/k3sm/srv say, would leave the deny guarding
// /data/k3sm/server while the real state sat beside it, readable and writable
// by every pod. Every layout k3sm creates already ends in the role's name, so
// the check refuses only a hand-picked --work-dir, and it runs before anything
// is created or written.
func checkWorkDirLayout(workDir, subdir string) error {
	clean := filepath.Clean(workDir)
	if filepath.Base(clean) == subdir {
		return nil
	}
	return fmt.Errorf("%w: --work-dir %s must be named %q: pods are denied <data root>/%s, and the data root is the work dir's parent, so state in a directory under any other name would be open to them; pass --work-dir <data root>/%s, for example --work-dir %s",
		ErrWorkDirLayout, workDir, subdir, subdir, subdir, filepath.Join(filepath.Dir(clean), subdir))
}
