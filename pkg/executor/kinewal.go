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

package executor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"
)

// A kine built before the Migrate patch (kinePatches) never let SQLite checkpoint,
// so a node upgrading from it can carry a WAL of many gigabytes. kine's startup
// runs PRAGMA wal_checkpoint(TRUNCATE) before it listens, so the first boot of the
// patched kine folds that whole WAL into state.db inside the readiness wait.
// Measured with the pinned pure-Go kine on an Apple-silicon SSD: a 474 MB WAL was
// recovered, checkpointed and truncated in 1.1 s, a 2.04 GB WAL in 2.95 s (about
// 1.5 s per GB with a warm page cache). The wait below allows ten times that per
// GiB, so a cold cache after a reboot still fits, on top of the ordinary wait.
const (
	// largeWALBytes is the WAL size from which the bring-up treats the start as a
	// recovery: it logs it, checks the free space the checkpoint needs, and waits
	// proportionally. A checkpointing kine's WAL settles near 4 MiB.
	largeWALBytes = 64 << 20
	// walRecoveryPerGiB is the extra readiness wait per GiB of WAL.
	walRecoveryPerGiB = 15 * time.Second
	// walSpaceMargin is kept free beyond what the checkpoint is computed to need.
	walSpaceMargin = 64 << 20
)

// ErrKineWALSpace is returned when the volume holding the datastore cannot take
// the growth of state.db that checkpointing a large leftover WAL causes.
var ErrKineWALSpace = errors.New("executor: not enough free space to checkpoint the datastore WAL")

// prepareKineWAL inspects the WAL kine is about to recover and returns how long
// bring-up waits for kine's listener. A WAL under largeWALBytes changes nothing.
// A larger one is logged at Info, its checkpoint's free-space need is checked
// (ErrKineWALSpace when the volume cannot take it), and the wait grows with it.
func prepareKineWAL(logger *slog.Logger, workDir string) (time.Duration, error) {
	db := StateDBPath(workDir)
	fi, err := os.Stat(db + "-wal")
	if err != nil || fi.Size() < largeWALBytes {
		return componentReadyTimeout, nil
	}
	walBytes := fi.Size()
	growth, gerr := walCheckpointGrowth(db)
	if gerr != nil {
		// Unreadable as a WAL: assume the worst case, every frame a new page.
		growth = walBytes
	}
	need := uint64(growth) + walSpaceMargin
	avail, err := freeSpace(dbDir(workDir))
	if err != nil {
		return 0, err
	}
	if avail < need {
		return 0, fmt.Errorf("%w: %s holds a %d-byte WAL whose checkpoint grows state.db by about %d bytes, and %s has %d bytes available (need %d); free space and start the server again, nothing was changed",
			ErrKineWALSpace, db+"-wal", walBytes, growth, dbDir(workDir), avail, need)
	}
	wait := kineReadyTimeout(walBytes)
	logger.Info("recovering a large datastore WAL: kine checkpoints it into state.db before it listens, so this start takes longer",
		"wal-bytes", walBytes, "state.db-growth-bytes", growth, "free-bytes", avail, "wait", wait)
	return wait, nil
}

// kineReadyTimeout is the readiness wait for a kine recovering walBytes of WAL.
func kineReadyTimeout(walBytes int64) time.Duration {
	if walBytes < largeWALBytes {
		return componentReadyTimeout
	}
	gib := (walBytes + (1 << 30) - 1) >> 30
	return componentReadyTimeout + time.Duration(gib)*walRecoveryPerGiB
}

// SQLite WAL layout (https://www.sqlite.org/fileformat2.html#walformat), all
// fields big-endian: a 32-byte header (magic, version, page size, checkpoint
// sequence, salt-1, salt-2, two checksum words), then frames of a 24-byte header
// (page number, database size in pages after a commit or 0, salt-1, salt-2, two
// checksum words) followed by one page.
const (
	walHeaderSize      = 32
	walFrameHeaderSize = 24
	walMagicLE         = 0x377f0682
	walMagicBE         = 0x377f0683
	// walScanFrames bounds the backward search for the last valid commit frame.
	walScanFrames = 4096
)

// walCheckpointGrowth returns how many bytes state.db grows when its WAL is fully
// checkpointed: the database size the last valid commit frame records, minus the
// file's current size. The last commit frame is the last frame, searching from
// the end, whose salts match the header's (older frames from before a WAL reset
// carry other salts). Checksums are not verified: this sizes a free-space check
// and does not decide what SQLite recovers.
func walCheckpointGrowth(db string) (int64, error) {
	f, err := os.Open(db + "-wal")
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	var hdr [walHeaderSize]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return 0, fmt.Errorf("read WAL header: %w", err)
	}
	be := binary.BigEndian
	if m := be.Uint32(hdr[0:4]); m != walMagicLE && m != walMagicBE {
		return 0, fmt.Errorf("not a SQLite WAL (magic %#x)", m)
	}
	pageSize := int64(be.Uint32(hdr[8:12]))
	if pageSize == 1 {
		pageSize = 65536 // the format's encoding of a 64 KiB page
	}
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return 0, fmt.Errorf("WAL page size %d is invalid", pageSize)
	}
	salt1, salt2 := be.Uint32(hdr[16:20]), be.Uint32(hdr[20:24])
	frameSize := walFrameHeaderSize + pageSize
	frames := (fi.Size() - walHeaderSize) / frameSize
	var fh [walFrameHeaderSize]byte
	for i := frames - 1; i >= 0 && i >= frames-walScanFrames; i-- {
		if _, err := f.ReadAt(fh[:], walHeaderSize+i*frameSize); err != nil {
			return 0, fmt.Errorf("read WAL frame %d: %w", i, err)
		}
		pages := int64(be.Uint32(fh[4:8]))
		if pages == 0 || be.Uint32(fh[8:12]) != salt1 || be.Uint32(fh[12:16]) != salt2 {
			continue
		}
		dfi, err := os.Stat(db)
		if err != nil {
			return 0, err
		}
		return max(0, pages*pageSize-dfi.Size()), nil
	}
	return 0, fmt.Errorf("no commit frame in the last %d WAL frames", walScanFrames)
}
