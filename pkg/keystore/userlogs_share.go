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

package keystore

import (
	"bytes"
	"fmt"
)

// The per-uid byte shares and revocation budgets of each append-only log
// (docs/design/keystore.md § "Per-uid fairness").
const (
	// defaultLogUIDShare is keystore.logUIDShare, each uid's byte share of
	// each log: 16 MiB, 1/16 of the default hard cap. A configured share
	// over logHardCap / logUIDShareDivisor is refused at checkConfig.
	defaultLogUIDShare = 16 << 20
	logUIDShareDivisor = 16
	// logReconcilerAllowance is each uid's reconciler allowance per log:
	// the revocation budget the reconciler's revocation lines for that
	// uid's deliveries draw on past its share or the hard cap, apart from
	// the socket margin (defaultLogRevocationBytes). It holds the lines of
	// the at most 64 deliveries live when the uid crossed its share, four
	// lines of at most 1 KiB each: 64 × 4 × 1 KiB = 256 KiB.
	logReconcilerAllowance = 256 << 10
	// maxShareUIDs bounds the reader's per-uid map of share bytes: a log
	// charging more distinct uids is sticky damage (errLogTooManyUIDs), so
	// forged lines of many uids cannot grow the map without bound.
	maxShareUIDs = 1 << 16
	// auditViaReconciler is the via of the reconciler's lines: one in the
	// revocation class draws on its uid's reconciler allowance; any other
	// via draws on the socket margin.
	auditViaReconciler = "reconciler"
)

// drawsOn is what one line's bytes are charged to.
type drawsOn int

const (
	// drawsNone: a line charged to no uid (root's, the reconciler budget's,
	// or damage).
	drawsNone drawsOn = iota
	// drawsShare: the uid's byte share.
	drawsShare
	// drawsMargin: the uid's socket margin, past its share or the hard cap.
	drawsMargin
	// drawsAllowance: the uid's reconciler allowance, past its share or the
	// hard cap.
	drawsAllowance
)

// uidShare is each uid's byte share of each log: Config.LogUIDShare, or
// defaultLogUIDShare, 1/16 of the default hard cap. checkConfig refuses a
// configured share over 1/16 of the configured hard cap.
func (s *FileStore) uidShare() int64 {
	if s.logUIDShare != 0 {
		return s.logUIDShare
	}
	return defaultLogUIDShare
}

// lineCharge is the one charging rule of a uid's line, which the reader's
// count (syncRead), the writer's admission (appendLines, room) and so every
// recount use: n bytes of a line that starts at off, led by an append's
// newline at off-1 when lead, of a uid whose share already holds used bytes
// of share. A line that starts at or past hardCap draws on a revocation
// budget, with its leading newline when that too is at or past hardCap; any
// other line is charged to the share, its leading newline included, while
// the share has room for it, and past the share draws on a revocation
// budget too. The budget is the reconciler allowance for a line whose via is
// the reconciler's (recon), the socket margin for every other. Only a line
// in the revocation class is ever written where it draws on a budget, so in
// a log the server wrote a uid's budget bytes are its revocation lines.
func lineCharge(used, hardCap, share int64, recon bool, off, n int64, lead bool) (drawsOn, int64) {
	budget := drawsMargin
	if recon {
		budget = drawsAllowance
	}
	if off >= hardCap {
		if lead && off-1 >= hardCap {
			n++
		}
		return budget, n
	}
	if lead {
		n++
	}
	if used+n <= share {
		return drawsShare, n
	}
	return budget, n
}

// charge adds n bytes of uid's to what on names, refusing, as sticky damage
// the caller records, a map that would charge more distinct uids than the
// reader keeps.
func (s *logState) charge(uid uint32, on drawsOn, n int64) error {
	var m map[uint32]int64
	limit := maxChargedUIDs
	switch on {
	case drawsShare:
		m, limit = s.share, maxShareUIDs
	case drawsMargin:
		m = s.pastCap
	case drawsAllowance:
		m = s.allowance
	case drawsNone:
		return nil
	}
	if _, ok := m[uid]; !ok && len(m) >= limit {
		return errLogTooManyUIDs
	}
	m[uid] += n
	return nil
}

// spentOn is uid's bytes already charged to the budget on names.
func (s *logState) spentOn(uid uint32, on drawsOn) int64 {
	if on == drawsAllowance {
		return s.allowance[uid]
	}
	return s.pastCap[uid]
}

// budgetOf is the per-uid limit of the revocation budget on names.
func (s *FileStore) budgetOf(on drawsOn) int64 {
	if on == drawsAllowance {
		return s.logAllowance
	}
	return s.logRevokeBudget
}

// lineRecon reports whether line, a whole line of this log with or without
// its newline, carries the reconciler's via, so in the revocation class it
// draws on the reconciler allowance (lineCharge). The floor's lines carry no
// via, so each of its lines draws on the socket margin.
func (l *appendLog) lineRecon(line []byte) bool {
	if l.floor {
		return false
	}
	_, recon, err := auditLineCharge(bytes.TrimSuffix(line, []byte{'\n'}))
	return err == nil && recon
}

// shareSpent is the ErrLogFull of a line of the caller's past its own share:
// that uid's alone, never the global append failure.
func (l *appendLog) shareSpent() error {
	return fmt.Errorf("%w (the caller's share of %s is spent)", ErrLogFull, l.name)
}

// budgetSpent is the ErrLogFull of a revocation line past the budget it
// draws on.
func (l *appendLog) budgetSpent(on drawsOn) error {
	if on == drawsAllowance {
		return fmt.Errorf("%w (the caller's reconciler allowance in %s is spent)", ErrLogFull, l.name)
	}
	return fmt.Errorf("%w (the caller's revocation budget in %s is spent)", ErrLogFull, l.name)
}

// planCharge judges lines, each ending in a newline, appended as one buffer
// at size (a leading newline, then the lines) for uid, through lineCharge
// from uid's counts in state: it returns the bytes they draw on each
// revocation budget, or, when a line would draw on one and budget (the
// revocation class) is false, the refusal: past the hard cap pastCap, past
// the share shareSpent.
func (l *appendLog) planCharge(state *logState, size int64, uid uint32, lines [][]byte, budget bool) (margin, allowance int64, err error) {
	used := state.share[uid]
	off := size + 1
	for i, line := range lines {
		on, n := lineCharge(used, state.hardCap, l.s.uidShare(), l.lineRecon(line), off, int64(len(line)), i == 0)
		switch on {
		case drawsShare:
			used += n
		case drawsMargin, drawsAllowance:
			if !budget {
				if off >= state.hardCap {
					return 0, 0, l.pastCap()
				}
				return 0, 0, l.shareSpent()
			}
			if on == drawsAllowance {
				allowance += n
			} else {
				margin += n
			}
		}
		off += int64(len(line))
	}
	return margin, allowance, nil
}
