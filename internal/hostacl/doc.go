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

// Package hostacl sets and removes the access-control entries a host share
// needs so the pods' user can reach it, as the share's owner, without root.
//
// It exists instead of running chmod(1) because `chmod -R +a` follows
// symlinks inside the tree it walks (with or without -P), so a symlink a pod
// left in a shared directory would carry the pods' entry to its target. This
// package opens every component with O_NOFOLLOW and changes each ACL through
// the open descriptor, skips symlinks and hard-linked files, and touches only
// what the share's owner owns.
//
// The entries are the Unix-permission half of a share only. The pod's
// Seatbelt profile, built from the node's share list, is the boundary: an
// entry left behind after a share is removed reaches nothing a pod's profile
// does not grant.
package hostacl
