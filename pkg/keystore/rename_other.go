//go:build !darwin

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

// renameExcl is renameatx_np with RENAME_EXCL on macOS. Elsewhere there is
// no rename this package trusts not to replace a name, so the floor merge's
// tree rename is refused.
func renameExcl(int, string, int, string) error {
	return errors.ErrUnsupported
}
