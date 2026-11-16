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

package provider

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/internal/hostacl"
	"k3sm.io/runtimed/pkg/hostshare"
)

// ExposeDriver is the CSI driver name k3sm reserves for an exposure volume:
// a pod-lifetime directory the pod writes and one named host account reads
// (or reads and writes). The provider handles it itself; no CSI driver
// process and no CSIDriver object exist for it, and every other CSI driver
// stays refused as an unmodeled source.
const ExposeDriver = "expose.k3sm.io"

const (
	// exposeAttrUser names the host account that receives the exposure.
	exposeAttrUser = "user"
	// exposeAttrAccess is "read" (the default) or "read-write".
	exposeAttrAccess = "access"
)

const (
	// reasonFailedExposure is recorded when a pod's exposure volume is
	// refused: a bad shape, a non-native pod, an account the node does not
	// have, or no root-made grant that admits it. The pod is refused before
	// the CreatePod RPC.
	reasonFailedExposure = "FailedExposure"
	// reasonExposureGranted is recorded once at create for each admitted
	// exposure volume, naming the account, the access and the host path.
	reasonExposureGranted = "ExposureGranted"
)

// exposeUserName is a plain account name, the form hostshare accepts in a
// grant.
var exposeUserName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// toExposeSource maps an inline CSI volume of ExposeDriver onto the runtime's
// exposure source. It carries the account by name; the uid is resolved on the
// node by authorizeExposures, which the runtime checks again. Every field the
// exposure does not use is refused rather than ignored, so a spec that asks
// for something the node would not do fails at create with a reason.
func toExposeSource(v *corev1.Volume, native bool) (*runtimev1.ExposeVolumeSource, error) {
	refuse := func(why string) error { return exposeRefusal(v.Name, errors.New(why)) }
	if !native {
		return nil, refuse("exposure volumes are native-pod only")
	}
	c := v.CSI
	if c.FSType != nil && *c.FSType != "" {
		return nil, refuse("an exposure volume takes no fsType")
	}
	if c.ReadOnly != nil && *c.ReadOnly {
		return nil, refuse("an exposure volume is written by the pod; leave readOnly unset or false and choose the host account's access with volumeAttributes.access")
	}
	if c.NodePublishSecretRef != nil {
		return nil, refuse("an exposure volume takes no nodePublishSecretRef")
	}
	keys := make([]string, 0, len(c.VolumeAttributes))
	for k := range c.VolumeAttributes {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if k != exposeAttrUser && k != exposeAttrAccess {
			return nil, refuse(fmt.Sprintf("unknown volumeAttributes key %q (want %s and, optionally, %s)", k, exposeAttrUser, exposeAttrAccess))
		}
	}
	name := c.VolumeAttributes[exposeAttrUser]
	if name == "" {
		return nil, refuse("volumeAttributes.user is required: the host account that receives the exposure")
	}
	if !exposeUserName.MatchString(name) {
		return nil, refuse(fmt.Sprintf("volumeAttributes.user %q is not a plain account name", name))
	}
	rw := false
	if a, ok := c.VolumeAttributes[exposeAttrAccess]; ok {
		var err error
		if rw, err = hostshare.ParseAccess(a); err != nil {
			return nil, refuse(fmt.Sprintf("volumeAttributes.access %q is not read or read-write", a))
		}
	}
	return &runtimev1.ExposeVolumeSource{User: name, ReadWrite: rw}, nil
}

// toExposeVolume is toVolume's case for a mounted CSI volume of
// ExposeDriver (toExposeSource); authorizeExposures decides it. Every other
// CSI driver stays an unmodeled source.
func toExposeVolume(v *corev1.Volume, native bool) (*runtimev1.Volume, error) {
	x, err := toExposeSource(v, native)
	if err != nil {
		return nil, err
	}
	return &runtimev1.Volume{Name: v.Name, Expose: x}, nil
}

func exposeRefusal(volume string, err error) error {
	return &volumeRefusal{
		reason: reasonFailedExposure,
		volume: volume,
		kind:   "csi",
		err:    fmt.Errorf("%w: %w", ErrVolumeSourceUnsupported, err),
	}
}

// authorizeExposures resolves each exposure volume's account to its uid on
// this node and decides the volumes against the node's root-owned grants
// (hostshare.AuthorizeExposures), the same file and the same rules runtimed
// applies when it binds them. A refusal is a *volumeRefusal (reason
// FailedExposure), so CreatePod records it and refuses the pod before the
// RPC. The check exists so the refusal is an Event on the pod rather than a
// runtime create failure; runtimed remains the enforcement point.
func (r *runtimedRuntime) authorizeExposures(box *runtimev1.PodBox) error {
	if !boxHasExposure(box) {
		return nil
	}
	lookup := r.lookupExposeUser
	if lookup == nil {
		lookup = lookupUserUID
	}
	for _, v := range box.GetVolumes() {
		x := v.GetExpose()
		if x == nil {
			continue
		}
		uid, err := lookup(x.GetUser())
		if err != nil {
			return exposeRefusal(v.GetName(), fmt.Errorf("%w: volume %q: host account %q does not exist on this node", hostshare.ErrNotExposed, v.GetName(), x.GetUser()))
		}
		x.Uid = uid
	}
	var grants []hostshare.ExposeGrant
	if r.hostSharesFile != "" {
		load := r.loadExposeGrants
		if load == nil {
			load = loadExposeGrants
		}
		var err error
		if grants, err = load(r.hostSharesFile); err != nil {
			r.log.Error("host share file unreadable; exposing nothing", "file", r.hostSharesFile, "err", err)
			return exposeRefusal(firstExposureVolume(box), err)
		}
	}
	name := r.exposeAccountName
	if name == nil {
		name = accountNameOf
	}
	if _, err := hostshare.AuthorizeExposures(grants, box, r.exposeRoot, name); err != nil {
		return exposeRefusal(refusedExposureName(box, err), err)
	}
	return nil
}

// recordExposureGrants records one Normal Event per exposure volume of box.
// buildBox has already admitted every one of them.
func (r *runtimedRuntime) recordExposureGrants(pod *corev1.Pod, box *runtimev1.PodBox) {
	if r.recorder == nil || !boxHasExposure(box) {
		return
	}
	mounted := boxMountedNames(box)
	for _, v := range box.GetVolumes() {
		x := v.GetExpose()
		if x == nil || !mounted[v.GetName()] {
			continue
		}
		dir, err := hostshare.ExposeDir(r.exposeRoot, box.GetNamespace(), box.GetName(), v.GetName())
		if err != nil {
			continue
		}
		access := "read"
		if x.GetReadWrite() {
			access = "read-write"
		}
		r.recorder.Eventf(pod, corev1.EventTypeNormal, reasonExposureGranted,
			"volume %q: exposed to host account %s (uid %d), %s, at %s", v.GetName(), x.GetUser(), x.GetUid(), access, dir)
	}
}

// msgFailedExposure is the FailedExposure-event message: the volume name and
// the reason, or a generic reason when the node's file could not be read.
func msgFailedExposure(volume string, err error) string {
	why := "the node's host-share file could not be read, so it exposes nothing (see the node log)"
	if !isLoadError(err) {
		why = err.Error()
		if i := strings.Index(why, ": volume "); i >= 0 {
			if j := strings.Index(why[i+len(": volume "):], ": "); j >= 0 {
				why = why[i+len(": volume ")+j+2:]
			}
		}
		why = strings.TrimPrefix(why, ErrVolumeSourceUnsupported.Error()+": ")
	}
	return fmt.Sprintf("Error: exposure volume %q is refused: %s.", volume, why)
}

// loadError marks an error from reading the node's file, so its text (which
// names node paths) stays in the node log and out of the Event.
type loadError struct{ err error }

func (e *loadError) Error() string { return e.err.Error() }
func (e *loadError) Unwrap() error { return e.err }

func isLoadError(err error) bool {
	var le *loadError
	return errors.As(err, &le)
}

// loadExposeGrants is the production grant loader: the exposure grants of the
// node's root-owned file, after hostshare's ownership and symlink checks.
func loadExposeGrants(file string) ([]hostshare.ExposeGrant, error) {
	eff, err := hostshare.LoadEffective(file)
	if err != nil {
		return nil, &loadError{err}
	}
	return eff.Exposes, nil
}

// lookupUserUID resolves a host account name to its uid.
func lookupUserUID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(uid), nil
}

// accountNameOf is the current account name of uid on this node.
func accountNameOf(uid uint32) (string, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

func boxHasExposure(box *runtimev1.PodBox) bool {
	return slices.ContainsFunc(box.GetVolumes(), func(v *runtimev1.Volume) bool { return v.GetExpose() != nil })
}

func boxMountedNames(box *runtimev1.PodBox) map[string]bool {
	out := map[string]bool{}
	for _, cs := range [][]*runtimev1.Container{box.GetInitContainers(), box.GetContainers()} {
		for _, c := range cs {
			for _, m := range c.GetVolumeMounts() {
				out[m.GetName()] = true
			}
		}
	}
	return out
}

func firstExposureVolume(box *runtimev1.PodBox) string {
	for _, v := range box.GetVolumes() {
		if v.GetExpose() != nil {
			return v.GetName()
		}
	}
	return ""
}

// refusedExposureName picks the volume an AuthorizeExposures error names
// (`volume "<name>"`), or the first exposure volume.
func refusedExposureName(box *runtimev1.PodBox, err error) string {
	for _, v := range box.GetVolumes() {
		if v.GetExpose() != nil && strings.Contains(err.Error(), fmt.Sprintf("volume %q", v.GetName())) {
			return v.GetName()
		}
	}
	return firstExposureVolume(box)
}

// exposeRootOf is the data root whose expose/ tree runtimed keeps this
// node's exposures under, derived the way runtimed derives it: the data root
// it is given (dataRootOf) when there is one, else the runtime root.
func exposeRootOf(cfg RuntimedConfig) string {
	if dataRoot, _, err := dataRootOf(cfg); err == nil && dataRoot != "" {
		return filepath.Clean(dataRoot)
	}
	return filepath.Clean(runtimeRoot(cfg.Root))
}

// exposeACL is the node's runtime.Deps.ExposeACL, backed by internal/hostacl:
// the runtime calls it as the exposure directory's owner (this process's
// uid), and hostacl changes each ACL through a no-follow descriptor.
type exposeACL struct{}

// Grant adds uid's inheritable entry on dir and on what is already under it,
// read-only or read-write; for read-write the owner gets the same entry, so
// the pod keeps access to what the account creates.
func (exposeACL) Grant(dir string, uid uint32, readWrite bool) error {
	a := hostacl.ReadOnly
	if readWrite {
		a = hostacl.ReadWrite
	}
	_, err := hostacl.GrantTree(dir, a, uid, uint32(os.Getuid()))
	return err
}

// Revoke removes uid's allow entries from dir itself, never below it: dir is
// 0700, so without its entry uid reaches nothing under it.
func (exposeACL) Revoke(dir string, uid uint32) error {
	_, err := hostacl.RevokeSearch(dir, uid)
	return err
}
