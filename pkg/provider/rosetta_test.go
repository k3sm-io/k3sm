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
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// infoServer is a runtimev1.RuntimeServer that serves ONE canned GetRuntimeInfo
// response (or an error) and counts the calls — the seam that proves Capabilities
// makes exactly ONE RPC for all three capability booleans. Everything else stays
// Unimplemented: this fake exists only for the capability handshake.
type infoServer struct {
	runtimev1.UnimplementedRuntimeServer

	info  *runtimev1.GetRuntimeInfoResponse
	err   error
	calls int
}

func (s *infoServer) GetRuntimeInfo(context.Context, *runtimev1.GetRuntimeInfoRequest) (*runtimev1.GetRuntimeInfoResponse, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.info, nil
}

// TestRosettaCapabilitiesFromInfo is the B103 k3sm-side proof of the ONE-RPC →
// ONE-capability-value mapping the node labels from: nodeCapabilitiesFromInfo maps a
// GetRuntimeInfo response to the three capability booleans, failing CLOSED on every
// degenerate input, and Capabilities makes exactly one RPC and fails closed on error.
//
// Every assertion is a t.Run SUBTEST of this one function on purpose — the named gate
// runs `go test -run '^TestRosettaCapabilitiesFromInfo$'`, so a sibling top-level
// test would be silently filtered out and never run.
//
// The condition Type strings come from the IMPORTED runtimed constants, never
// restated literals: the reader fails closed, so a producer/consumer rename must be a
// compile error here rather than a permanently-absent node label. runtimed's own
// rosetta_test.go pins those constants to their wire VALUES; this side pins the
// mapping.
func TestRosettaCapabilitiesFromInfo(t *testing.T) {
	t.Parallel()

	const (
		condTrue        = runtimev1.ConditionStatus_CONDITION_STATUS_TRUE
		condFalse       = runtimev1.ConditionStatus_CONDITION_STATUS_FALSE
		condUnknown     = runtimev1.ConditionStatus_CONDITION_STATUS_UNKNOWN
		condUnspecified = runtimev1.ConditionStatus_CONDITION_STATUS_UNSPECIFIED
	)
	cond := func(typ string, st runtimev1.ConditionStatus, reason string) *runtimev1.RuntimeCondition {
		return &runtimev1.RuntimeCondition{Type: typ, Status: st, Reason: reason}
	}
	info := func(cs ...*runtimev1.RuntimeCondition) *runtimev1.GetRuntimeInfoResponse {
		return &runtimev1.GetRuntimeInfoResponse{Conditions: cs}
	}
	assertCaps := func(t *testing.T, got, want NodeCapabilities) {
		t.Helper()
		if got != want {
			t.Errorf("nodeCapabilitiesFromInfo = %+v, want %+v", got, want)
		}
	}

	// Every condition TRUE: all three capabilities advertised. The label composition
	// (rosetta-linux = VMBackend ∧ RosettaGuest) is cmd/k3sm's job — this mapper
	// reports the three RAW facts.
	t.Run("both_true_vm_true", func(t *testing.T) {
		t.Parallel()
		got := nodeCapabilitiesFromInfo(info(
			cond(runtimed.ConditionSandboxBackend, condTrue, "Available"),
			cond(runtimed.ConditionVMBackendAvailable, condTrue, "Available"),
			cond(runtimed.ConditionRosettaHostAvailable, condTrue, "Available"),
			cond(runtimed.ConditionRosettaGuestAvailable, condTrue, "Available"),
		))
		assertCaps(t, got, NodeCapabilities{VMBackend: true, RosettaHost: true, RosettaGuest: true})
	})

	// Host Rosetta only — no VZ, no guest translation. This is the shape a
	// Rosetta-installed but VZ-incapable Mac reports, and the reason the linux label
	// is a conjunction rather than the guest condition alone.
	t.Run("host_only", func(t *testing.T) {
		t.Parallel()
		got := nodeCapabilitiesFromInfo(info(
			cond(runtimed.ConditionVMBackendAvailable, condFalse, "Unavailable"),
			cond(runtimed.ConditionRosettaHostAvailable, condTrue, "Available"),
			cond(runtimed.ConditionRosettaGuestAvailable, condFalse, "VMBackendUnavailable"),
		))
		assertCaps(t, got, NodeCapabilities{RosettaHost: true})
	})

	// An explicit FALSE is a capability absence, never an advertisement.
	t.Run("status_false", func(t *testing.T) {
		t.Parallel()
		got := nodeCapabilitiesFromInfo(info(
			cond(runtimed.ConditionVMBackendAvailable, condFalse, "Unavailable"),
			cond(runtimed.ConditionRosettaHostAvailable, condFalse, "NotInstalled"),
			cond(runtimed.ConditionRosettaGuestAvailable, condFalse, "NotSupported"),
		))
		assertCaps(t, got, NodeCapabilities{})
	})

	// UNKNOWN ⇒ NOT advertised. The mapper tests for == TRUE, so an indeterminate
	// probe fails closed; a `!= FALSE` test would have read UNKNOWN as capable.
	t.Run("status_unknown_is_not_capable", func(t *testing.T) {
		t.Parallel()
		got := nodeCapabilitiesFromInfo(info(
			cond(runtimed.ConditionVMBackendAvailable, condUnknown, "Indeterminate"),
			cond(runtimed.ConditionRosettaHostAvailable, condUnknown, "Indeterminate"),
			cond(runtimed.ConditionRosettaGuestAvailable, condUnknown, "QueryFailed"),
		))
		assertCaps(t, got, NodeCapabilities{})
	})

	// UNSPECIFIED is the PROTO ZERO value — what a future/older producer that forgot
	// to set Status emits, and what a nil condition getter returns. It must read as
	// NOT capable, or an unset field would silently advertise every capability.
	t.Run("status_unspecified_proto_zero_is_not_capable", func(t *testing.T) {
		t.Parallel()
		got := nodeCapabilitiesFromInfo(info(
			cond(runtimed.ConditionVMBackendAvailable, condUnspecified, ""),
			cond(runtimed.ConditionRosettaHostAvailable, condUnspecified, ""),
			cond(runtimed.ConditionRosettaGuestAvailable, condUnspecified, ""),
		))
		assertCaps(t, got, NodeCapabilities{})
		if condUnspecified != 0 {
			t.Errorf("CONDITION_STATUS_UNSPECIFIED = %d, want the proto zero 0 (this subtest's premise)", condUnspecified)
		}
	})

	// Version skew: an OLDER runtimed that predates B103 emits only the two B1
	// conditions. The vm fact still lands (B1 does not regress); the Rosetta pair
	// fails closed with no error anywhere, so the node simply carries no Rosetta label.
	t.Run("rosetta_conditions_absent_older_runtimed", func(t *testing.T) {
		t.Parallel()
		got := nodeCapabilitiesFromInfo(info(
			cond(runtimed.ConditionSandboxBackend, condTrue, "Available"),
			cond(runtimed.ConditionVMBackendAvailable, condTrue, "Available"),
		))
		assertCaps(t, got, NodeCapabilities{VMBackend: true})
	})

	// A nil response (a producer that returned no error and no body) advertises nothing.
	t.Run("nil_response", func(t *testing.T) {
		t.Parallel()
		assertCaps(t, nodeCapabilitiesFromInfo(nil), NodeCapabilities{})
	})

	// An empty condition list advertises nothing.
	t.Run("empty_conditions", func(t *testing.T) {
		t.Parallel()
		assertCaps(t, nodeCapabilitiesFromInfo(info()), NodeCapabilities{})
		assertCaps(t, nodeCapabilitiesFromInfo(&runtimev1.GetRuntimeInfoResponse{}), NodeCapabilities{})
	})

	// A duplicated Type is not something runtimed emits, but the wire allows it
	// (Conditions is `repeated` with a free-string Type). Pin the documented verdict:
	// FIRST match wins, so the resolution is deterministic rather than
	// last-writer-or-whatever-the-loop-happens-to-do.
	t.Run("duplicate_conditions_first_match_wins", func(t *testing.T) {
		t.Parallel()
		got := nodeCapabilitiesFromInfo(info(
			cond(runtimed.ConditionRosettaHostAvailable, condTrue, "Available"),
			cond(runtimed.ConditionRosettaHostAvailable, condFalse, "NotInstalled"),
			cond(runtimed.ConditionRosettaGuestAvailable, condFalse, "NotSupported"),
			cond(runtimed.ConditionRosettaGuestAvailable, condTrue, "Available"),
		))
		assertCaps(t, got, NodeCapabilities{RosettaHost: true})
	})

	// A nil condition ENTRY inside the list must not panic — the proto getters are
	// nil-safe and the mapper relies on that.
	t.Run("nil_condition_entry_does_not_panic", func(t *testing.T) {
		t.Parallel()
		got := nodeCapabilitiesFromInfo(info(nil, cond(runtimed.ConditionRosettaHostAvailable, condTrue, "Available"), nil))
		assertCaps(t, got, NodeCapabilities{RosettaHost: true})
	})

	// An RPC error advertises NOTHING and does not panic: a probe failure must never
	// FALSELY label a node capable. (UnimplementedRuntimeServer is the error source —
	// the same shape a runtimed too old to serve the RPC would produce.)
	t.Run("rpc_error_fails_closed", func(t *testing.T) {
		t.Parallel()
		r, _ := newRuntimedFake(t)
		got := r.Capabilities(context.Background())
		assertCaps(t, got, NodeCapabilities{})
		if r.VMBackendAvailable(context.Background()) {
			t.Error("VMBackendAvailable must be false on an RPC error (B1 fail-closed)")
		}
	})

	// A nil response WITH a nil error over the real RPC seam also fails closed.
	t.Run("rpc_nil_response_fails_closed", func(t *testing.T) {
		t.Parallel()
		s := &infoServer{}
		r := newRuntimedWith(s, RuntimedConfig{NodeName: "n", NodeIP: "10.0.0.1", Root: t.TempDir()}, nil, nil)
		assertCaps(t, r.Capabilities(context.Background()), NodeCapabilities{})
	})

	// ONE RPC for all three booleans: three separate probes could each observe a
	// DIFFERENT daemon state and yield an incoherent label set (rosetta-linux stamped
	// from a later observation while virtualization was deleted from an earlier one).
	t.Run("capabilities_makes_exactly_one_rpc", func(t *testing.T) {
		t.Parallel()
		s := &infoServer{info: info(
			cond(runtimed.ConditionVMBackendAvailable, condTrue, "Available"),
			cond(runtimed.ConditionRosettaHostAvailable, condTrue, "Available"),
			cond(runtimed.ConditionRosettaGuestAvailable, condTrue, "Available"),
		)}
		r := newRuntimedWith(s, RuntimedConfig{NodeName: "n", NodeIP: "10.0.0.1", Root: t.TempDir()}, nil, nil)
		got := r.Capabilities(context.Background())
		assertCaps(t, got, NodeCapabilities{VMBackend: true, RosettaHost: true, RosettaGuest: true})
		if s.calls != 1 {
			t.Errorf("Capabilities issued %d GetRuntimeInfo RPCs, want exactly 1", s.calls)
		}
	})

	// B1 must not regress: the single-capability VMBackendAvailable view agrees with
	// the consolidated struct on both verdicts.
	t.Run("vmbackendavailable_agrees_with_capabilities", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name string
			st   runtimev1.ConditionStatus
			want bool
		}{
			{"true", condTrue, true},
			{"false", condFalse, false},
			{"unknown", condUnknown, false},
		} {
			s := &infoServer{info: info(cond(runtimed.ConditionVMBackendAvailable, tc.st, "r"))}
			r := newRuntimedWith(s, RuntimedConfig{NodeName: "n", NodeIP: "10.0.0.1", Root: t.TempDir()}, nil, nil)
			if got := r.VMBackendAvailable(context.Background()); got != tc.want {
				t.Errorf("%s: VMBackendAvailable = %v, want %v", tc.name, got, tc.want)
			}
			if got := r.Capabilities(context.Background()).VMBackend; got != tc.want {
				t.Errorf("%s: Capabilities().VMBackend = %v, want %v", tc.name, got, tc.want)
			}
		}
	})
}
