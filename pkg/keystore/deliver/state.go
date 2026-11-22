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

package deliver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"syscall"

	"k3sm.io/k3sm/pkg/addons"
)

// StateFileName is the reconciler's record of the Secrets it created, in the
// server's work dir (/var/lib/k3sm/server/keystore-delivery-state.json on an
// install). Pods are kept off it by the runtime's whole-tree pod deny on the
// server work dir (runtimed/pkg/sandbox TestStateDirDeniedUnderACustomLeaf,
// TestStateDirEnforcedAcrossCaseAndNormalization); the keystore- prefix,
// which the runtime's keystore-* deny also covers, is defence in depth only.
//
// The server writes it, so it is owned by the server's euid (_k3sm on an
// install, root on a root server), not by root. That adds no trust: a
// process running as the server's uid already holds the admin kubeconfig,
// and so can write any Secret without forging this file.
const StateFileName = "keystore-delivery-state.json"

// StateFileMode is the state file's mode, 0600: it names no value, but it is
// what ownership rests on, so only its owner reads or writes it.
const StateFileMode os.FileMode = 0o600

// StateFileCheck is the state file's check: owned by uid (the server's euid)
// and not group- or other-writable.
func StateFileCheck(uid uint32) FileCheck {
	return func(fi fs.FileInfo) error {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st == nil {
			return errors.New("owner unknown")
		}
		if st.Uid != uid {
			return fmt.Errorf("owned by uid %d, not the server's uid %d", st.Uid, uid)
		}
		return addons.NotShared(fi)
	}
}

// StateDirCheck is the check on the directory holding the state file: owned
// by uid (the server's euid), by root, or by one of also, and not group- or
// other-writable.
//
// A root server names the service user in also, since its work dir is the
// service user's. That owner can rename or delete the file in it. A missing
// record only makes the reconciler skip a Secret it cannot prove it created,
// failing closed. A file it wrote itself is refused, since the file must be
// owned by root (the euid, StateFileCheck). The residual is replay: it can
// put back an older state file root wrote, which restores records only for
// Secrets this server created, in targets root declared.
func StateDirCheck(uid uint32, also ...uint32) FileCheck {
	return func(fi fs.FileInfo) error {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st == nil {
			return errors.New("owner unknown")
		}
		if st.Uid != uid && st.Uid != 0 && !slices.Contains(also, st.Uid) {
			return fmt.Errorf("owned by uid %d, neither the server's uid %d, root, nor the service user", st.Uid, uid)
		}
		return addons.NotShared(fi)
	}
}

// chownNone leaves a new state file as it is: the server creates it, so it
// is already the server's own.
func chownNone(*os.File) error { return nil }

// Owned is one Secret the reconciler created: its namespace, name and the UID
// the apiserver gave it. The label on a Secret is forgeable by anyone who can
// write Secrets in its namespace; the UID is not, since a recreated object
// gets a new one.
type Owned struct {
	Namespace  string `json:"namespace"`
	SecretName string `json:"secretName"`
	UID        string `json:"uid"`
}

// State is the state file's content: the UIDs of the Secrets the reconciler
// created, keyed by namespace/name.
type State struct {
	owned map[string]string
}

// stateDoc is State as the file holds it.
type stateDoc struct {
	Version int     `json:"version"`
	Secrets []Owned `json:"secrets"`
}

func stateKey(namespace, name string) string { return namespace + "/" + name }

// UID is the recorded UID of namespace/name, or "" when none is recorded.
func (s *State) UID(namespace, name string) string { return s.owned[stateKey(namespace, name)] }

// Set records uid for namespace/name.
func (s *State) Set(namespace, name, uid string) {
	if s.owned == nil {
		s.owned = map[string]string{}
	}
	s.owned[stateKey(namespace, name)] = uid
}

// Retain drops every record whose namespace/name keep does not report, and
// reports whether it dropped any.
func (s *State) Retain(keep func(namespace, name string) bool) bool {
	dropped := false
	for k := range s.owned {
		ns, name, _ := strings.Cut(k, "/")
		if !keep(ns, name) {
			delete(s.owned, k)
			dropped = true
		}
	}
	return dropped
}

// ParseState decodes a state file strictly, as Parse does a declaration.
func ParseState(data []byte) (State, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var d stateDoc
	if err := dec.Decode(&d); err != nil {
		return State{}, fmt.Errorf("decode: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return State{}, errors.New("trailing data after the state")
	}
	if d.Version != SchemaVersion {
		return State{}, fmt.Errorf("version %d, want %d", d.Version, SchemaVersion)
	}
	if len(d.Secrets) > MaxTargets {
		return State{}, fmt.Errorf("%d records, the limit is %d", len(d.Secrets), MaxTargets)
	}
	s := State{owned: make(map[string]string, len(d.Secrets))}
	for i, o := range d.Secrets {
		if o.Namespace == "" || o.SecretName == "" || o.UID == "" || strings.Contains(o.Namespace, "/") {
			return State{}, fmt.Errorf("record %d is incomplete", i)
		}
		k := stateKey(o.Namespace, o.SecretName)
		if _, dup := s.owned[k]; dup {
			return State{}, fmt.Errorf("record %d repeats a Secret", i)
		}
		s.owned[k] = o.UID
	}
	return s, nil
}

// Marshal encodes s as the file holds it, sorted, with a trailing newline.
func (s State) Marshal() ([]byte, error) {
	d := stateDoc{Version: SchemaVersion, Secrets: make([]Owned, 0, len(s.owned))}
	for k, uid := range s.owned {
		ns, name, _ := strings.Cut(k, "/")
		d.Secrets = append(d.Secrets, Owned{Namespace: ns, SecretName: name, UID: uid})
	}
	slices.SortFunc(d.Secrets, func(a, b Owned) int {
		return strings.Compare(stateKey(a.Namespace, a.SecretName), stateKey(b.Namespace, b.SecretName))
	})
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ReadState reads the state file at path as Read reads the declaration, with
// dirCheck on its directory's descriptor and check on the opened file's. A
// missing file is an empty state.
func ReadState(path string, open Opener, dirCheck, check FileCheck) (State, error) {
	data, _, exists, err := readChecked(path, open, dirCheck, check)
	if err != nil {
		return State{}, err
	}
	if !exists {
		return State{owned: map[string]string{}}, nil
	}
	s, err := ParseState(data)
	if err != nil {
		return State{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return s, nil
}

// WriteState installs s at path, mode StateFileMode, atomically, as Write
// installs a declaration, once dirCheck accepts path's directory.
func WriteState(path string, s State, dirCheck FileCheck, chown func(f *os.File) error) error {
	data, err := s.Marshal()
	if err != nil {
		return fmt.Errorf("encode the delivery state: %w", err)
	}
	return writeAtomic(path, data, StateFileMode, dirCheck, chown)
}
