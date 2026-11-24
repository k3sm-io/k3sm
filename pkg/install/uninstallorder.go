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

package install

// bootouts is each label an uninstall pass booted out without an error. An
// entry with afterBootout is removed only when its label is in it, so a
// directory holding the socket of a job still loaded stays.
type bootouts map[string]bool

// bootout boots label out and records it when that succeeded.
func (b bootouts) bootout(sys System, label string) error {
	if err := sys.LaunchctlBootout(label); err != nil {
		return err
	}
	b[label] = true
	return nil
}

// remove removes a's path with rm, unless a waits on a bootout this pass
// did not complete; then it is kept with a Warn, and a rerun finishes it.
func (b bootouts) remove(cfg Config, a artifact, rm func(string) error) error {
	if a.afterBootout != "" && !b[a.afterBootout] {
		cfg.Logger.Warn("kept: its daemon was not booted out in this pass; rerun uninstall once it is", "path", a.path, "label", a.afterBootout)
		return nil
	}
	return rm(a.path)
}
