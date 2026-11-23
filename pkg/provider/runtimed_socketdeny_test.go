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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/keystorepaths"
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
	// The keystore's socket at the default data root, which with no DataRoot
	// configured is the runtime root.
	keysSock := keystorepaths.SocketPath(sandbox.DefaultWorkDir)
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
			// six literals (two daemon sockets and the keystore's, each in two
			// firmlink forms) and not ten.
			want:  []string{absSock, absPrivate, netdSock, "/private" + netdSock, keysSock, "/private" + keysSock},
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
	return renderPodProfileWith(t, RuntimedConfig{Root: root, DeniedUnixSocketPaths: supplied})
}

// renderPodProfileWith is renderPodProfile over a config carrying Root and
// any further fields under test; the node name, IP and log root are set here.
func renderPodProfileWith(t *testing.T, cfg RuntimedConfig) string {
	t.Helper()
	cfg.NodeName = "n"
	cfg.NodeIP = "192.168.1.10"
	// A temp dir, NOT root: these tests deliberately pass unwritable,
	// non-existent roots (/opt/k3sm-lab, /var/k3sm-lab) to exercise the socket
	// path spellings, and the box translation now also creates the pod's log
	// tree under PodLogsDir.
	cfg.PodLogsDir = t.TempDir()
	r := newRuntimedWith(newFakeRuntimeServer(), cfg, nil, nil)
	box, err := r.buildBox(context.Background(), runtimedPod("default", "web"), "192.168.1.10")
	if err != nil {
		t.Fatalf("buildBox: %v", err)
	}
	profile, err := sandbox.Generate(box.GetSandboxProfile(), sandbox.GenerateOptions{
		Posture: sandbox.Posture{WorkDir: cfg.Root},
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

	base := baseSocketDenies("", "", nil)
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
	if len(once) != 3 {
		t.Errorf("default root should collapse to 3 literals, got %d: %v", len(once), once)
	}
}

// TestBaseSocketDeniesKeystoreSocket proves the keystore's user socket is in
// the provider's own deny-set, derived from runtimed's
// keystorepaths.SocketPath of the DATA root (not the runtime root, which it
// equals only on a default node), and that the rendered profile denies
// connect(2) to it inside the AF_UNIX deny stanza, after every network allow,
// since SBPL is last-match-wins (docs/design/keystore.md § "Pod denies").
func TestBaseSocketDeniesKeystoreSocket(t *testing.T) {
	for _, tc := range []struct {
		name, root, dataRoot, want string
	}{
		{"default node", "", "", "/var/lib/k3sm/keystore-sock/keys.sock"},
		{"data root apart from the pod root", "/opt/k3sm-lab/pods", "/opt/k3sm-lab/data", "/opt/k3sm-lab/data/keystore-sock/keys.sock"},
		{"no data root falls back to the runtime root", "/opt/k3sm-lab/data", "", "/opt/k3sm-lab/data/keystore-sock/keys.sock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantRoot := tc.dataRoot
			if wantRoot == "" {
				wantRoot = tc.root
			}
			if wantRoot == "" {
				wantRoot = sandbox.DefaultWorkDir
			}
			if got := keystorepaths.SocketPath(wantRoot); got != tc.want {
				t.Fatalf("keystorepaths.SocketPath(%q) = %q, want %q", wantRoot, got, tc.want)
			}
			if base := baseSocketDenies(tc.root, tc.dataRoot, nil); !slices.Contains(base, tc.want) {
				t.Fatalf("baseSocketDenies(%q, %q) = %v, missing %q", tc.root, tc.dataRoot, base, tc.want)
			}

			profile := renderPodProfileWith(t, RuntimedConfig{Root: tc.root, DataRoot: tc.dataRoot})
			denied, denyLine := socketDenyLiterals(t, profile)
			if !slices.Contains(denied, tc.want) {
				t.Fatalf("the rendered AF_UNIX deny stanza %v does not deny %q:\n%s", denied, tc.want, profile)
			}
			for i, raw := range strings.Split(profile, "\n") {
				if strings.HasPrefix(strings.TrimSpace(raw), "(allow network") && i > denyLine {
					t.Errorf("a network allow at line %d follows the socket deny at line %d, which makes the deny inert", i, denyLine)
				}
			}
		})
	}
}

// TestBaseSocketDeniesResolvesDataRoot proves a data root reached through a
// symlink has its keystore socket denied by the resolved path as well as
// the literal one, that a resolution adding only the /private firmlink adds
// nothing (the profile renderer writes that spelling), and that a data root
// that cannot be resolved keeps the literal deny and is logged. It swaps
// evalDataRoot, so it is not parallel.
func TestBaseSocketDeniesResolvesDataRoot(t *testing.T) {
	saved := evalDataRoot
	t.Cleanup(func() { evalDataRoot = saved })
	links := map[string]string{
		"/opt/k3sm-lab/data": "/Volumes/Lab/k3sm-data",
		"/var/lib/k3sm":      "/private/var/lib/k3sm",
	}
	evalDataRoot = func(p string) (string, error) {
		if r, ok := links[p]; ok {
			return r, nil
		}
		return "", errors.New("fake: no such file or directory")
	}
	keys := func(base []string) []string {
		var out []string
		for _, p := range base {
			if strings.HasSuffix(p, "/"+keystorepaths.SocketName) {
				out = append(out, p)
			}
		}
		return out
	}

	got := keys(baseSocketDenies("/opt/k3sm-lab/pods", "/opt/k3sm-lab/data", nil))
	want := []string{"/opt/k3sm-lab/data/keystore-sock/keys.sock", "/Volumes/Lab/k3sm-data/keystore-sock/keys.sock"}
	if !slices.Equal(got, want) {
		t.Fatalf("symlinked data root: keystore denies %v, want %v", got, want)
	}

	if got := keys(baseSocketDenies("", "", nil)); !slices.Equal(got, []string{"/var/lib/k3sm/keystore-sock/keys.sock"}) {
		t.Fatalf("default data root: keystore denies %v, want the literal only", got)
	}

	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	if got := keys(baseSocketDenies("/opt/other", "/opt/other", log)); !slices.Equal(got, []string{"/opt/other/keystore-sock/keys.sock"}) {
		t.Fatalf("unresolvable data root: keystore denies %v, want the literal only", got)
	}
	if n := strings.Count(logs.String(), "could not be resolved"); n != 1 {
		t.Fatalf("%d lines for an unresolvable data root, want 1: %q", n, logs.String())
	}

	// The rendered profile denies the resolved spelling too.
	profile := renderPodProfileWith(t, RuntimedConfig{Root: "/opt/k3sm-lab/pods", DataRoot: "/opt/k3sm-lab/data"})
	denied, _ := socketDenyLiterals(t, profile)
	for _, w := range want {
		if !slices.Contains(denied, w) {
			t.Fatalf("the rendered AF_UNIX deny stanza %v does not deny %q", denied, w)
		}
	}
}
