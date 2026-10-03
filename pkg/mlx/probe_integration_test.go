//go:build integration

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

package mlx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServingProbeOverARealSocket keeps the probe table's end-to-end paths
// through net/http's real client, dialer, connection handling and body reads.
// The unit-tier table (probe_test.go) derives the same verdicts from fake
// transports, so a verdict there cannot depend on how loaded the machine is;
// these cases prove the fakes fail and answer the way the network does. They
// need no privilege:
//
//	CGO_ENABLED=1 go test -tags integration -run TestServingProbeOverARealSocket ./pkg/mlx/
func TestServingProbeOverARealSocket(t *testing.T) {
	t.Run("refused_dial_is_the_downloading_verdict", func(t *testing.T) {
		// A server stood up then immediately closed: the port refuses the
		// connection, exactly like a pod whose serving container has not
		// bound its port yet because it is still fetching weights. The budget
		// cannot change the verdict — a refusal and an elapsed budget are both
		// "no response", both Unreachable — so the short one costs nothing.
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("handler must not be reached: the server is closed before probing")
		}))
		srv.Close()

		got := probeVia(t, http.DefaultTransport, srv.URL, probeHangTimeout)
		if got != ProbeUnreachable {
			t.Fatalf("got %q, want %q (ProbeUnreachable)", got, ProbeUnreachable)
		}
	})

	t.Run("health_ok_model_listed_is_serving", func(t *testing.T) {
		// The unit table's serving fixture over a real loopback listener. It
		// runs under probeContentBudget: the budget is a liveness guard here,
		// not a race the round trip has to win.
		srv := httptest.NewServer(servingHandler())
		defer srv.Close()

		got := probeVia(t, http.DefaultTransport, srv.URL, probeContentBudget)
		if got != ProbeServing {
			t.Fatalf("got %q, want %q (ProbeServing)", got, ProbeServing)
		}
	})
}
