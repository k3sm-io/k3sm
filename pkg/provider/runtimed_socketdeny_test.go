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
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
	"k3sm.io/runtimed/pkg/sandbox"
)

// TestRuntimedSocketDeniedToPods proves the runtimed control socket is denied to
// every pod by the RENDERED profile, not merely present in a config field, and
// that the deny survives a caller who supplies no socket paths at all.
//
// It asserts the generated SBPL rather than PodBox.DeniedUnixSocketPaths for two
// reasons. First, the field is an input to a generator that could stop emitting
// it (or emit it in the wrong place) without the field changing. Second, SBPL is
// LAST-MATCH-WINS: a deny hoisted above (allow network-outbound) is inert, and a
// test that only greps for the path would stay green through that regression —
// hence the ordering assertion below.
func TestRuntimedSocketDeniedToPods(t *testing.T) {
	const netdSock = "/var/lib/k3sm/run/netd.sock"
	// The absolute default, in the two spellings libsandbox may see it as: it
	// lives under the /var firmlink, so the generator emits the /private form too
	// and a deny written against only one of them fails open.
	absSock := runtimed.DefaultSocketPath
	absPrivate := "/private" + absSock

	tests := []struct {
		name string
		// root is RuntimedConfig.Root — the runtime work-dir the derived socket
		// spelling and the pod data volume both hang off.
		root string
		// supplied is the caller-provided DeniedUnixSocketPaths.
		supplied []string
		// want are socket literals the rendered deny stanza MUST carry.
		want []string
		// exact, when set, additionally pins the deny stanza to exactly want
		// (deduplication proof for the posture where the two spellings coincide).
		exact bool
	}{
		{
			// The gate proper: nothing is supplied, so a deny-set that were only
			// as good as its producer would emit no socket stanza at all. BOTH
			// daemon sockets must appear — netd's non-omittably too, even though
			// the node command also passes it, because "the caller remembered this
			// one" is not a property the profile may depend on.
			name: "no supplied paths still denies both daemon sockets",
			root: "/opt/k3sm-lab/data",
			want: []string{
				absSock, absPrivate, "/opt/k3sm-lab/data/run/runtimed.sock",
				netdSock, "/private" + netdSock, "/opt/k3sm-lab/data/run/netd.sock",
			},
		},
		{
			// A caller-supplied path must ADD to the base set, never stand in for
			// it. netd is supplied here AND in the base set, which also proves the
			// union dedupes rather than double-emitting.
			name:     "supplied netd socket extends the base set",
			root:     "/opt/k3sm-lab/data",
			supplied: []string{netdSock},
			want: []string{
				netdSock, "/private" + netdSock,
				absSock, absPrivate,
				"/opt/k3sm-lab/data/run/runtimed.sock",
			},
		},
		{
			// A work-dir under a firmlink: the DERIVED spelling needs both forms
			// too, for the same libsandbox path-resolution reason as the absolute one.
			name: "work-dir under a firmlink denies both forms of the derived spelling",
			root: "/var/k3sm-lab",
			want: []string{
				absSock, absPrivate,
				"/var/k3sm-lab/run/runtimed.sock", "/private/var/k3sm-lab/run/runtimed.sock",
			},
		},
		{
			// Default posture: the absolute const and the work-dir-derived spelling
			// are the same path, and the profile must say it once.
			name: "default root collapses the two spellings",
			root: "",
			// exact: with the default root the const and the work-dir derivation
			// are the same string for BOTH daemons, so the union must dedupe to
			// four literals (two sockets x two firmlink forms) and not six.
			want:  []string{absSock, absPrivate, netdSock, "/private" + netdSock},
			exact: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile := renderPodProfile(t, tc.root, tc.supplied)
			denied, denyLine := socketDenyLiterals(t, profile)
			if denyLine < 0 {
				t.Fatalf("rendered profile has no AF_UNIX deny stanza:\n%s", profile)
			}
			for _, w := range tc.want {
				if !slices.Contains(denied, w) {
					t.Errorf("socket deny set %v is missing %q", denied, w)
				}
			}
			if tc.exact {
				got := slices.Clone(denied)
				slices.Sort(got)
				want := slices.Clone(tc.want)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Errorf("socket deny set = %v, want exactly %v", got, want)
				}
			}
			// Positive control: the deny is NARROW. A profile that denied every
			// socket, or that dropped the network allow entirely, would satisfy every
			// assertion above while breaking every pod.
			if slices.Contains(denied, "/tmp/x.sock") {
				t.Errorf("socket deny set %v denies an unrelated path", denied)
			}
			allowLine := lineIndex(profile, "(allow network-outbound)")
			if allowLine < 0 {
				t.Fatalf("allow_network pod lost (allow network-outbound):\n%s", profile)
			}
			// Ordering: SBPL is last-match-wins, so a deny emitted ABOVE the network
			// allow is silently inert even though it reads correctly.
			if denyLine < allowLine {
				t.Errorf("socket deny at line %d precedes (allow network-outbound) at line %d — last-match-wins makes it inert", denyLine, allowLine)
			}
		})
	}
}

// renderPodProfile runs a pod through the provider's box translation and then
// through the SBPL generator with the SAME posture the runtime uses (work-dir ==
// the runtime root), returning the rendered profile.
func renderPodProfile(t *testing.T, root string, supplied []string) string {
	t.Helper()
	r := newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
		NodeName:              "n",
		NodeIP:                "192.168.1.10",
		Root:                  root,
		DeniedUnixSocketPaths: supplied,
	}, nil, nil)
	box, err := r.buildBox(context.Background(), runtimedPod("default", "web"), "192.168.1.10")
	if err != nil {
		t.Fatalf("buildBox: %v", err)
	}
	profile, err := sandbox.Generate(box.GetSandboxProfile(), sandbox.GenerateOptions{
		Posture: sandbox.Posture{WorkDir: root},
		PodIP:   "192.168.1.10",
	})
	if err != nil {
		t.Fatalf("sandbox.Generate: %v", err)
	}
	return profile
}

// socketDenyLiterals returns every path literal in the profile's AF_UNIX deny
// stanza together with the line index the stanza opens at, or (nil, -1) when the
// profile emits no such stanza.
func socketDenyLiterals(t *testing.T, profile string) ([]string, int) {
	t.Helper()
	start := -1
	inDeny := false
	var out []string
	for i, raw := range strings.Split(profile, "\n") {
		line := strings.TrimSpace(raw)
		if line == "(deny network-outbound" {
			start, inDeny = i, true
			continue
		}
		// Only literals INSIDE the deny stanza count. Collecting them
		// profile-wide would let a generator that emitted the same literal in an
		// ALLOW stanza satisfy every assertion here while inverting the control —
		// the test's claim is that the path is DENIED, not that it appears.
		if inDeny && line == ")" {
			inDeny = false
			continue
		}
		rest, ok := strings.CutPrefix(line, "(remote unix-socket (literal ")
		if !ok || !inDeny {
			continue
		}
		quoted, ok := strings.CutSuffix(rest, "))")
		if !ok {
			continue
		}
		p, err := strconv.Unquote(quoted)
		if err != nil {
			t.Fatalf("unquote socket literal %q: %v", quoted, err)
		}
		out = append(out, p)
	}
	return out, start
}

// lineIndex returns the index of the first line equal to want (ignoring
// surrounding whitespace), or -1.
func lineIndex(profile, want string) int {
	for i, raw := range strings.Split(profile, "\n") {
		if strings.TrimSpace(raw) == want {
			return i
		}
	}
	return -1
}

// TestSocketDenyStampIsAUnion pins the STAMP SITE (stampSocketDenies) against a
// profile that ALREADY carries a deny.
//
// Nothing in the current translation path pre-sets DeniedUnixSocketPaths, so a
// bare `=` at the stamp site is behaviourally identical today and no end-to-end
// case can tell the two apart. That is exactly why this is pinned directly: the
// union is defensive against a future translation step that adds a deny of its
// own, and a defence nothing asserts is one a later edit silently removes.
func TestSocketDenyStampIsAUnion(t *testing.T) {
	const preExisting = "/var/run/some-future-helper.sock"

	base := baseSocketDenies("")
	r := &runtimedRuntime{deniedSocks: unionSocketDenies(base)}
	sp := &runtimev1.SandboxProfile{DeniedUnixSocketPaths: []string{preExisting}}
	r.stampSocketDenies(sp)
	got := sp.GetDeniedUnixSocketPaths()

	if !slices.Contains(got, preExisting) {
		t.Errorf("the stamp dropped a deny already on the box: %q missing from %v", preExisting, got)
	}
	for _, want := range base {
		if !slices.Contains(got, want) {
			t.Errorf("the stamp dropped a base deny: %q missing from %v", want, got)
		}
	}
	// A nil profile must be a no-op, not a panic.
	r.stampSocketDenies(nil)

	// And it must be idempotent: unioning a set with itself changes nothing.
	// Compare against the NORMALIZED form, not the raw base — at the default root
	// the const and the work-dir derivation are the same string for both daemons,
	// so the raw list carries duplicates by construction and it is exactly the
	// union's job to collapse them.
	once := unionSocketDenies(base)
	if twice := unionSocketDenies(base, base); !slices.Equal(twice, once) {
		t.Errorf("union of a set with itself = %v, want %v", twice, once)
	}
	if len(once) != 2 {
		t.Errorf("default root should collapse to 2 literals, got %d: %v", len(once), once)
	}
}
