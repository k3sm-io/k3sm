//go:build darwin

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

import "golang.org/x/sys/unix"

// noFollow is O_NOFOLLOW_ANY (<sys/fcntl.h> 0x20000000): openat(2) fails with
// ELOOP if any component of the relative path, not only the last, is a
// symlink. It closes the window between the store's symlink walk and the
// open. It replaces O_NOFOLLOW rather than joining it: darwin refuses the two
// together with EINVAL.
const noFollow = unix.O_NOFOLLOW_ANY
