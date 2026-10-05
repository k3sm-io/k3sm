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

package pairing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// ArmFile is the joiner's arming state under the agent work dir.
const ArmFile = "pairing-arm.json"

// DefaultArm is how long `install --auto-join` arms the joiner when the operator
// names no duration.
const DefaultArm = 10 * time.Minute

// ErrNotArmed reports a joiner that is not armed, or whose arming expired: it does
// nothing. Compare with errors.Is.
var ErrNotArmed = errors.New("pairing: this Mac is not armed to pair (run `sudo k3sm pair --listen <dur>`)")

// Arm is the joiner's persisted arming state.
type Arm struct {
	// Until is when the arming expires.
	Until time.Time `json:"until"`
	// Cluster is the optional cluster pin a beacon must carry; empty trusts the
	// first open-pairing server heard (the documented limitation).
	Cluster string `json:"cluster,omitempty"`
}

// Armed reports whether the joiner may act at now.
func (a Arm) Armed(now time.Time) bool { return now.Before(a.Until) }

// ArmPath returns the arming file's path under an agent work dir.
func ArmPath(workDir string) string { return filepath.Join(workDir, ArmFile) }

// WriteArm arms the joiner at path for d from now, with an optional cluster pin.
func WriteArm(path string, now time.Time, d time.Duration, cluster string) (Arm, error) {
	if d <= 0 {
		return Arm{}, fmt.Errorf("arming duration must be positive, got %s", d)
	}
	a := Arm{Until: now.Add(d), Cluster: strings.ToLower(strings.TrimSpace(cluster))}
	return a, writeAtomic(path, a)
}

// LoadArm reads the arming state; an absent file is an unarmed joiner.
func LoadArm(path string) (Arm, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Arm{}, false, nil
	}
	if err != nil {
		return Arm{}, false, fmt.Errorf("read pairing arm state: %w", err)
	}
	var a Arm
	if err := json.Unmarshal(b, &a); err != nil {
		return Arm{}, false, fmt.Errorf("decode pairing arm state %s: %w", path, err)
	}
	return a, true, nil
}

// Disarm removes the arming state (after a join it never runs again).
func Disarm(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("disarm pairing: %w", err)
	}
	return nil
}

// Result is what a successful pairing hands the ordinary join.
type Result struct {
	// Token is the one-shot join token (never written to disk).
	Token string
	// Server is the join target host: the server's link-local address zoned with
	// this Mac's arrival interface, e.g. "fe80::1%bridge0".
	Server string
	// ServerLinkIP is the server's direct-link address on the cable, for the
	// first-contact route and the persisted bootstrap address.
	ServerLinkIP string
	// Iface is this Mac's interface the beacon arrived on.
	Iface string
	// ClusterPin is the pin the join is made against (the beacon's).
	ClusterPin string
}

// PairFunc asks the server that sent h for a token for nodeName.
type PairFunc func(ctx context.Context, h Heard, nodeName string) (netv1alpha1.PairResponse, error)

// Joiner is the new Mac's pairing state machine. It is inert unless armed, and it
// stops at the first token it obtains.
type Joiner struct {
	// Arm is the arming state.
	Arm Arm
	// NodeName is the name this Mac joins as.
	NodeName string
	// Pair asks a server for a token (RequestPair in production).
	Pair PairFunc
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Logger receives one line per ignored beacon reason (at Debug) and per
	// attempt (at Info).
	Logger *slog.Logger
}

// Consider is the joiner-side trust decision for one beacon, pure: it returns ""
// when the joiner should ask that server for a token, else why it ignores it.
func (j Joiner) Consider(h Heard, now time.Time) string {
	switch {
	case !j.Arm.Armed(now):
		return "not-armed"
	case h.Beacon.Version != netv1alpha1.BeaconVersion:
		return "unknown-beacon-version"
	case !h.Beacon.PairingOpen:
		return "pairing-closed"
	case j.Arm.Cluster != "" && !strings.EqualFold(strings.TrimSpace(h.Beacon.ClusterPin), j.Arm.Cluster):
		return "cluster-pin-mismatch"
	case h.Beacon.ClusterPin == "":
		return "no-cluster-pin"
	}
	return ""
}

// Run consumes beacons until it obtains a token, the arming expires (ErrNotArmed)
// or ctx ends. An unarmed joiner returns ErrNotArmed at once and reads nothing.
func (j Joiner) Run(ctx context.Context, beacons <-chan Heard) (Result, error) {
	now := j.now()
	if !j.Arm.Armed(now) {
		return Result{}, ErrNotArmed
	}
	log := j.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	expiry := time.NewTimer(j.Arm.Until.Sub(now))
	defer expiry.Stop()
	for {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-expiry.C:
			return Result{}, ErrNotArmed
		case h, ok := <-beacons:
			if !ok {
				return Result{}, errors.New("pairing: the beacon receiver stopped")
			}
			if why := j.Consider(h, j.now()); why != "" {
				log.Debug("pairing: ignoring a beacon", "reason", why, "iface", h.Iface, "from", h.Src.String(), "node", h.Beacon.NodeName)
				continue
			}
			log.Info("pairing: asking a server for a join token", "iface", h.Iface, "server", h.Beacon.NodeName)
			resp, err := j.Pair(ctx, h, j.NodeName)
			if err != nil {
				log.Warn("pairing: the server did not pair this Mac; waiting for the next beacon", "iface", h.Iface, "server", h.Beacon.NodeName, "err", err)
				continue
			}
			return Result{
				Token:        resp.Token,
				Server:       h.Src.WithZone(h.Iface).String(),
				ServerLinkIP: resp.ServerLinkIP,
				Iface:        h.Iface,
				ClusterPin:   strings.ToLower(strings.TrimSpace(h.Beacon.ClusterPin)),
			}, nil
		}
	}
}

func (j Joiner) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

// RequestPair POSTs a pair request to the server that sent h, over TLS pinned to
// the beacon's cluster pin (bootstrap.PinnedClient): a server whose chain does not
// verify against that pin is never asked anything.
func RequestPair(ctx context.Context, h Heard, nodeName string) (netv1alpha1.PairResponse, error) {
	return requestPair(ctx, bootstrap.PinnedClient(h.Beacon.ClusterPin), bootstrap.HTTPSURL(h.PairAddress()), nodeName)
}

func requestPair(ctx context.Context, client *http.Client, base, nodeName string) (netv1alpha1.PairResponse, error) {
	body, err := json.Marshal(netv1alpha1.PairRequest{Version: netv1alpha1.PairVersion, NodeName: nodeName})
	if err != nil {
		return netv1alpha1.PairResponse{}, fmt.Errorf("marshal pair request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+bootstrap.PairPath, bytes.NewReader(body))
	if err != nil {
		return netv1alpha1.PairResponse{}, fmt.Errorf("build pair request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return netv1alpha1.PairResponse{}, fmt.Errorf("post pair request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg := make([]byte, 256)
		n, _ := resp.Body.Read(msg)
		return netv1alpha1.PairResponse{}, fmt.Errorf("pair request refused (%s): %s", resp.Status, strings.TrimSpace(string(msg[:n])))
	}
	var out netv1alpha1.PairResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return netv1alpha1.PairResponse{}, fmt.Errorf("decode pair response: %w", err)
	}
	if out.Token == "" {
		return netv1alpha1.PairResponse{}, errors.New("pair response carries no token")
	}
	return out, nil
}
