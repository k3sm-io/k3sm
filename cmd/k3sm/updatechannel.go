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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	crdconfig "k3sm.io/apis/config/crd"
	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"

	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/update"
	"k3sm.io/k3sm/pkg/updatectl"
	"k3sm.io/k3sm/pkg/version"
)

// updatePolicyGVR is the UpdatePolicy resource the channel is read from.
var updatePolicyGVR = updatesv1alpha1.SchemeGroupVersion.WithResource("updatepolicies")

// errChannelUnreadable is an UpdatePolicy a reader that may read it could not
// read or decode, or one whose channel is neither stable nor rc. Such a check
// fails rather than resolving on a channel nobody chose.
var errChannelUnreadable = errors.New("the update channel could not be read")

// errChannelUnsupported is a write the server has no resource for, still so when
// the wait for the CRD ended: an older server, or one whose update controller has
// not ensured the CRD. It never reads as a set channel.
var errChannelUnsupported = errors.New("this server does not support update channels")

// channelCRDWait bounds how long a write waits for the UpdatePolicy CRD. The
// update controller ensures it as the server starts and establishment trails that
// by seconds, so a server that has none by then is an older one.
const channelCRDWait = 15 * time.Second

// exitChannelCheckFailed is `k3sm update channel <value>` when the write took and
// the check after it failed: the channel is set and nothing has verified it. It is
// not exitInternalError, which is a write that did not happen.
const exitChannelCheckFailed = 3

// channelReading is what a channelSource found.
type channelReading struct {
	// channel is the channel to resolve on, stable or rc.
	channel updatesv1alpha1.UpdateChannel
	// published is, on rc read from a published pair, the pair's latest release.
	published string
	// note says why this reader runs as stable when it does so on anything but
	// the cluster's plain answer; empty otherwise.
	note string
}

// channelSource reads the release channel with the credentials a check already
// holds. It adds no RBAC: an identity that may read the UpdatePolicy reads it,
// and any other reads the pair a server publishes on its own Node, which every
// node identity may read already.
type channelSource struct {
	// dyn reads the UpdatePolicy; nil means no cluster.
	dyn dynamic.Interface
	// kube lists the Nodes the pair is published on.
	kube kubernetes.Interface
	// pairOnly reads only the pair, as a worker does.
	pairOnly bool
	// objectOnly never falls back to the pair: a Forbidden object is unreadable.
	// Apply sets it, because the pair is display and offer data and must not
	// choose a release to roll a cluster to.
	objectOnly bool
}

// read is the channel. Everything but an unreadable or unknown object, which is
// an error wrapping errChannelUnreadable, has an answer: no cluster, no object
// and no CRD on an older server all mean stable.
func (s channelSource) read(ctx context.Context) (channelReading, error) {
	ctx, cancel := context.WithTimeout(ctx, update.DefaultTimeout)
	defer cancel()
	if s.pairOnly {
		return s.readPair(ctx), nil
	}
	if s.dyn == nil {
		return channelReading{channel: updatesv1alpha1.UpdateChannelStable, note: "no cluster to read the update channel from; checking as stable"}, nil
	}
	obj, err := s.dyn.Resource(updatePolicyGVR).Get(ctx, updatesv1alpha1.UpdatePolicyName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return channelReading{channel: updatesv1alpha1.UpdateChannelStable}, nil
	case apierrors.IsForbidden(err) && !s.objectOnly:
		return s.readPair(ctx), nil
	case err != nil:
		return channelReading{}, fmt.Errorf("%w: %w", errChannelUnreadable, err)
	}
	var policy updatesv1alpha1.UpdatePolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &policy); err != nil {
		return channelReading{}, fmt.Errorf("%w: %w", errChannelUnreadable, err)
	}
	switch policy.Spec.Channel {
	case "", updatesv1alpha1.UpdateChannelStable:
		return channelReading{channel: updatesv1alpha1.UpdateChannelStable}, nil
	case updatesv1alpha1.UpdateChannelRC:
		return channelReading{channel: updatesv1alpha1.UpdateChannelRC}, nil
	}
	return channelReading{}, fmt.Errorf("%w: %w %q", errChannelUnreadable, update.ErrUnknownChannel, status.ClipText(string(policy.Spec.Channel), 64))
}

// readPair is the channel from the pair the most recently checked control-plane
// Node publishes. It never fails: a reader here cannot roll the cluster, so what
// it cannot read it reports as stable and says why. A latest with no channel is
// an older server's pair, plain stable.
func (s channelSource) readPair(ctx context.Context) channelReading {
	cannot := func(why string) channelReading {
		return channelReading{
			channel: updatesv1alpha1.UpdateChannelStable,
			note:    "the server's channel could not be read (" + status.ClipText(why, 256) + "); checking as stable",
		}
	}
	if s.kube == nil {
		return cannot("no cluster client")
	}
	nodes, err := s.kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return cannot(err.Error())
	}
	rec, _, ok := status.PublishedUpdateRecord(nodes.Items)
	if !ok {
		return channelReading{channel: updatesv1alpha1.UpdateChannelStable, note: "no server has published a channel yet; checking as stable"}
	}
	switch rec.Channel {
	case "", updatesv1alpha1.UpdateChannelStable:
		return channelReading{channel: updatesv1alpha1.UpdateChannelStable}
	case updatesv1alpha1.UpdateChannelRC:
		if !version.CanonicalTag(rec.Latest) {
			return cannot(fmt.Sprintf("the release published with it, %q, is not a release tag", rec.Latest))
		}
		return channelReading{channel: updatesv1alpha1.UpdateChannelRC, published: rec.Latest}
	}
	return cannot(fmt.Sprintf("%v %q", update.ErrUnknownChannel, rec.Channel))
}

// checkOnChannel reads the channel, then runs one check on it. A channel it
// cannot read fails the check before anything is asked of the release index.
func checkOnChannel(ctx context.Context, in update.Inputs, src channelSource) (update.Report, channelReading, error) {
	reading, err := src.read(ctx)
	if err != nil {
		return update.NewReport(in), reading, fmt.Errorf("resolve the latest release: %w", err)
	}
	in.Channel, in.Published = reading.channel, reading.published
	rep, err := update.Check(ctx, in)
	return rep, reading, err
}

// effectiveChannel is ch, with empty read as the stable it means.
func effectiveChannel(ch updatesv1alpha1.UpdateChannel) updatesv1alpha1.UpdateChannel {
	if ch == "" {
		return updatesv1alpha1.UpdateChannelStable
	}
	return ch
}

// channelWatch is what the recorder's one goroutine remembers between polls.
//
// attempted lives in memory and is seeded from the record, so a restart inside
// the hour still sees a change, and a server with nowhere to write a record does
// not see one on every poll and spend the release host's limit.
type channelWatch struct {
	// attempted is the channel of the last check started, failed or not. A failed
	// check counts: a retry waits for the interval, not for the next poll.
	attempted updatesv1alpha1.UpdateChannel
	// unread is whether the last check failed on the channel itself.
	unread bool
	// warned is the last reading problem logged, so a poll does not repeat it.
	warned string
}

// checked notes the outcome of a check.
func (w *channelWatch) checked(rep update.Report, err error) {
	if rep.Channel != "" {
		w.attempted = rep.Channel
	}
	w.unread = errors.Is(err, errChannelUnreadable)
}

// pollChannel reads the live channel and reports whether a check is due now:
// the channel moved from the one last checked, or it can be read again after a
// check failed on it.
func (r updateRecorder) pollChannel(ctx context.Context, w *channelWatch) bool {
	if r.readChannel == nil {
		return false
	}
	reading, err := r.readChannel(ctx)
	if ctx.Err() != nil {
		return false
	}
	problem := reading.note
	if err != nil {
		problem = err.Error()
	}
	if problem != "" && problem != w.warned {
		r.logger.Warn("could not read the update channel", "err", problem)
	}
	w.warned = problem
	if err != nil {
		return false
	}
	if reading.channel != w.attempted {
		r.logger.Warn("the update channel changed; checking now", "from", w.attempted, "to", reading.channel)
		w.attempted = reading.channel
		return true
	}
	return w.unread
}

// logCheck logs a failed check: at Warn when the channel is why, because a quiet
// edit or a broken listing would otherwise go unseen outside the row, and at Info
// when it is the ordinary case of a Mac with no route to the release host.
//
// A poll that can read the channel forces a check after one that could not, so a
// check whose own read keeps failing repeats on every poll. unread says the last
// check already failed that way: this spell has had its Warn, and it takes a check
// that reads the channel to start another.
func (r updateRecorder) logCheck(err error, unread bool) {
	switch {
	case err == nil:
	case unread && errors.Is(err, errChannelUnreadable):
		r.logger.Debug("could not check for a k3sm update", "err", err)
	case errors.Is(err, errChannelUnreadable), errors.Is(err, update.ErrChannelList),
		errors.Is(err, update.ErrChannelPageCap), errors.Is(err, update.ErrNoChannelRelease):
		r.logger.Warn("could not check for a k3sm update", "err", err)
	default:
		r.logger.Info("could not check for a k3sm update", "err", err)
	}
}

// planChannel is the plan's channel line.
func planChannel(reading channelReading, err error) string {
	if err != nil {
		return "could not be read"
	}
	return string(reading.channel)
}

// planPin is the plan's pin line, and whether it names a pin for target: the
// digest given with --pin-sha256, else the pin on this Mac's work dir, which only
// binds a roll when this Mac is the server the controller runs on.
func planPin(env updateEnv, target string, pinning bool, sha string) (string, bool) {
	if pinning {
		return "sha256:" + sha + ", from --pin-sha256", true
	}
	if env.workDir == "" {
		return "not known on this Mac", false
	}
	read := env.readPin
	if read == nil {
		read = updatectl.ReadReleasePin
	}
	pin, err := read(env.workDir)
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "not known without sudo", false
	case err != nil:
		return "cannot be trusted, so the server refuses every release until `k3sm update apply --clear-pin`", false
	case pin == nil:
		return "none on this Mac", false
	case pin.Version != target:
		return "none for this release; the pin on this Mac names " + status.ClipText(pin.Version, 128), false
	}
	return "sha256:" + pin.SHA256 + ", set on this Mac", true
}

// runUpdateChannel is `k3sm update channel [stable|rc]`: bare it prints the
// channel this Mac would check on, and with a value it writes the UpdatePolicy and
// runs a check. A channel changes what is offered and never starts a roll.
func runUpdateChannel(ctx context.Context, args []string, env updateEnv) int {
	switch len(args) {
	case 0:
		return showUpdateChannel(ctx, env)
	case 1:
		return setUpdateChannel(ctx, args[0], env)
	}
	fmt.Fprint(env.errOut, updateUsage)
	return exitUsage
}

// showUpdateChannel prints the channel, from the same source a check reads.
func showUpdateChannel(ctx context.Context, env updateEnv) int {
	reading, err := channelSource{dyn: env.dyn, kube: env.inputs.Kube, pairOnly: env.worker}.read(ctx)
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update channel:", err)
		return exitInternalError
	}
	if reading.note != "" {
		fmt.Fprintln(env.errOut, "k3sm update:", reading.note)
	}
	fmt.Fprintln(env.out, reading.channel)
	return 0
}

// setUpdateChannel writes value, then runs a check on it. A check that fails after
// the write, as one with no route to the release host does, exits with its own code
// and says both: a script must not take the channel for verified, and must not take
// a write that happened for one that was refused.
func setUpdateChannel(ctx context.Context, value string, env updateEnv) int {
	channel := updatesv1alpha1.UpdateChannel(value)
	if channel != updatesv1alpha1.UpdateChannelStable && channel != updatesv1alpha1.UpdateChannelRC {
		fmt.Fprintf(env.errOut, "k3sm update channel: unknown channel %q: the channels are stable and rc\n\n%s", value, updateUsage)
		return exitUsage
	}
	_, dyn, err := updateClients(env)
	if err != nil {
		fmt.Fprintln(env.errOut, "k3sm update channel: cannot reach the cluster:", err)
		return exitInternalError
	}
	bound := env.channelWait
	if bound <= 0 {
		bound = channelCRDWait
	}
	if err := writeUpdateChannel(ctx, dyn, channel, bound); err != nil {
		if apierrors.IsForbidden(err) {
			fmt.Fprintf(env.errOut, "k3sm update channel: setting the channel takes cluster-admin, which these credentials do not have: %v\n", err)
			return exitInternalError
		}
		fmt.Fprintln(env.errOut, "k3sm update channel:", err)
		return exitInternalError
	}
	fmt.Fprintf(env.out, "The update channel is now %s. This changes what is offered and starts no roll.\n", channel)
	if env.worker {
		fmt.Fprintln(env.out, "This Mac reads the channel its server publishes, so this check can name the old one until the server has checked.")
	}
	fmt.Fprintln(env.out)
	if code := runUpdateCheck(ctx, nil, env); code != 0 {
		fmt.Fprintf(env.errOut, "k3sm update channel: the write is done and the channel is %s, but the check failed; run `k3sm update check` again\n", channel)
		return exitChannelCheckFailed
	}
	return 0
}

// writeUpdateChannel sets the channel on the singleton, making it if need be. A
// merge patch names only the field this verb owns, and it needs no read first.
//
// Patch answers NotFound both for no object and for no resource; only create
// tells them apart, because creating a cluster-scoped object can be NotFound only
// when the resource itself is missing. That case retries until bound, then returns
// errChannelUnsupported, so a missing CRD never reads as a written channel. A lost
// race with another writer (the object appears or goes between the two calls) also
// retries.
func writeUpdateChannel(ctx context.Context, dyn dynamic.Interface, channel updatesv1alpha1.UpdateChannel, bound time.Duration) error {
	policies := dyn.Resource(updatePolicyGVR)
	patch, err := json.Marshal(map[string]any{"spec": map[string]any{"channel": channel}})
	if err != nil {
		return fmt.Errorf("encode the channel: %w", err)
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": updatesv1alpha1.SchemeGroupVersion.String(),
		"kind":       "UpdatePolicy",
		"metadata":   map[string]any{"name": updatesv1alpha1.UpdatePolicyName},
		"spec":       map[string]any{"channel": string(channel)},
	}}
	noCRD := false
	err = wait.PollUntilContextTimeout(ctx, bound/30, bound, true, func(ctx context.Context) (bool, error) {
		noCRD = false
		_, err := policies.Patch(ctx, updatesv1alpha1.UpdatePolicyName, types.MergePatchType, patch, metav1.PatchOptions{})
		if !apierrors.IsNotFound(err) {
			return err == nil, err
		}
		_, err = policies.Create(ctx, obj, metav1.CreateOptions{})
		noCRD = apierrors.IsNotFound(err)
		switch {
		case err == nil:
			return true, nil
		case noCRD, apierrors.IsAlreadyExists(err):
			return false, nil
		}
		return false, err
	})
	switch {
	case err == nil:
		return nil
	case noCRD && ctx.Err() == nil:
		return fmt.Errorf("%w: the %s CRD is not established after %s", errChannelUnsupported, crdconfig.UpdatePolicyCRDName, bound)
	}
	return fmt.Errorf("write the UpdatePolicy %s: %w", updatesv1alpha1.UpdatePolicyName, err)
}
