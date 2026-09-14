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
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/install"
)

const datavolUsage = `k3sm datavol — the APFS volume k3sm keeps its data root on

Usage: k3sm datavol <subcommand> [flags]

  mount    mount the recorded data volume (root; what the io.k3sm.datavol LaunchDaemon runs)
  status   report the volume, its quota, its usage and any pre-migration copy (no privilege needed)
  delete   destroy the volume and every declaration of it (root; needs --yes)

The volume is created by 'sudo k3sm install --data-volume'. See docs/user/storage.md.
`

// runDatavol dispatches the three data-volume subcommands.
//
// They are three verbs and not one because they are three different privilege
// and consequence classes: mount is root and idempotent, status is
// unprivileged and read-only, delete is root and destroys every cluster object
// on the volume. Nothing here creates a volume — that is `k3sm install
// --data-volume`, where the rest of the install sequencing lives.
func runDatavol(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, datavolUsage)
		return fmt.Errorf("a subcommand is required: mount, status or delete")
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Print(datavolUsage)
		return nil
	case "mount":
		return runDatavolMount(args[1:])
	case "status":
		return runDatavolStatus(args[1:], os.Stdout)
	case "delete":
		return runDatavolDelete(args[1:])
	default:
		fmt.Fprint(os.Stderr, datavolUsage)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// runDatavolMount mounts the recorded data volume. It is what the
// io.k3sm.datavol LaunchDaemon execs at boot, and it is safe to run by hand at
// any time: MountRecorded returns immediately if the volume is already mounted,
// and retries the transient failures early-boot disk arbitration produces.
//
// A Mac with NO record exits 0 after saying so. That is the load-bearing
// behaviour of the whole command: a leftover plist on a machine whose volume
// was deleted must not turn into a launchd relaunch loop, and "there is no data
// volume here" is a correct outcome, not a failure.
func runDatavolMount(args []string) error {
	fs := flag.NewFlagSet("datavol mount", flag.ContinueOnError)
	record := fs.String("record", dataroot.DefaultRecordPath, "the data-volume record to mount from")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("k3sm datavol mount must run as root — use 'sudo k3sm datavol mount'")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	rec, err := dataroot.ReadRecord(dataroot.OSFS{}, *record)
	if err != nil {
		return err
	}
	if rec == nil {
		logger.Info("no data volume is recorded on this Mac; nothing to mount", "record", *record)
		return nil
	}

	own := datavol.Owner{GID: install.DataRootGID, Mode: install.DataRootMode}
	if uid := lookupServiceUID(); uid > 0 {
		own.UID = uid
	}
	if err := datavol.MountRecorded(context.Background(), datavol.NewDarwin(), dataroot.OSFS{}, *rec, own, logger); err != nil {
		return err
	}
	logger.Info("data volume mounted", "volume", rec.Name, "uuid", rec.UUID, "mountpoint", rec.Mountpoint)
	return nil
}

// datavolStatusReport is the machine shape of `k3sm datavol status -o json`.
// The text screen is rendered from the same values, so the two cannot disagree.
type datavolStatusReport struct {
	// Record is the declaration itself, verbatim.
	Record *dataroot.Record `json:"record"`
	// Mounted reports that something is mounted ON the record's mount point,
	// decided by the device compare rather than by a path string.
	Mounted bool `json:"mounted"`
	// Statfs is the volume's capacity as the kernel reports it, present only
	// when the volume is mounted.
	Statfs *datavolStatfs `json:"statfs,omitempty"`
	// PreVolume reports the pre-migration copy of the old data root.
	PreVolume datavolPreVolume `json:"preVolume"`
}

// datavolStatfs is what statfs(2) says about the mounted volume. It is the
// number the reclaim ladder and the DiskPressure floor actually read, which is
// why status reports it rather than the quota alone.
type datavolStatfs struct {
	TotalBytes uint64 `json:"totalBytes"`
	AvailBytes uint64 `json:"availBytes"`
	UsedBytes  uint64 `json:"usedBytes"`
}

// datavolPreVolume reports the copy a migration left beside the data root.
type datavolPreVolume struct {
	Present bool   `json:"present"`
	Bytes   uint64 `json:"bytes"`
}

// runDatavolStatus reports the data volume, for a human or for a script. It
// needs no privilege: every fact it reads is a mode-0644 record, a statfs and a
// directory stat.
func runDatavolStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("datavol status", flag.ContinueOnError)
	record := fs.String("record", dataroot.DefaultRecordPath, "the data-volume record to report on")
	mountpoint := fs.String("mountpoint", "", "the mount point to probe (default: the record's)")
	format := fs.String("o", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("unknown output format %q, want text or json", *format)
	}

	rec, err := dataroot.ReadRecord(dataroot.OSFS{}, *record)
	if err != nil {
		return err
	}
	dir := *mountpoint
	if dir == "" {
		if rec == nil {
			dir = install.DefaultDataRoot
		} else {
			dir = rec.Mountpoint
		}
	}

	report := datavolStatusReport{Record: rec}
	st, err := dataroot.Read(dataroot.OSFS{}, dir)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", dir, err)
	}
	report.Mounted = st.Mounted
	if st.Mounted {
		var sfs unix.Statfs_t
		if err := unix.Statfs(dir, &sfs); err != nil {
			return fmt.Errorf("statfs %s: %w", dir, err)
		}
		total := sfs.Blocks * uint64(sfs.Bsize)
		avail := sfs.Bavail * uint64(sfs.Bsize)
		report.Statfs = &datavolStatfs{
			TotalBytes: total,
			AvailBytes: avail,
			UsedBytes:  (sfs.Blocks - sfs.Bfree) * uint64(sfs.Bsize),
		}
	}
	preVolume := dir + datavol.PreVolumeSuffix
	if info, err := os.Stat(preVolume); err == nil && info.IsDir() {
		report.PreVolume = datavolPreVolume{Present: true, Bytes: treeBytes(preVolume)}
	}

	if *format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	return writeDatavolStatusText(out, dir, report)
}

// writeDatavolStatusText renders the human screen: one fact per line, the same
// vocabulary `k3sm status` uses on its data-root row.
func writeDatavolStatusText(out io.Writer, dir string, r datavolStatusReport) error {
	if r.Record == nil {
		if _, err := fmt.Fprintf(out, "no data volume is recorded on this Mac; %s is a plain directory\ncreate one: sudo k3sm install --data-volume\n", dir); err != nil {
			return err
		}
		return nil
	}
	quota := "none (the volume can grow to fill its container)"
	if r.Record.QuotaBytes > 0 {
		quota = datavol.FormatSize(r.Record.QuotaBytes)
	}
	lines := [][2]string{
		{"volume", r.Record.Name},
		{"uuid", r.Record.UUID},
		{"mountpoint", r.Record.Mountpoint},
		{"quota", quota},
		{"encrypted", fmt.Sprint(r.Record.Encrypted)},
		{"mounted", fmt.Sprint(r.Mounted)},
	}
	if r.Statfs != nil {
		lines = append(lines,
			[2]string{"used", datavol.FormatSize(r.Statfs.UsedBytes)},
			[2]string{"avail", datavol.FormatSize(r.Statfs.AvailBytes)},
			[2]string{"total", datavol.FormatSize(r.Statfs.TotalBytes)},
		)
	}
	if r.PreVolume.Present {
		lines = append(lines, [2]string{"pre-volume", fmt.Sprintf("%s%s (%s)", r.Record.Mountpoint, datavol.PreVolumeSuffix, datavol.FormatSize(r.PreVolume.Bytes))})
	}
	for _, l := range lines {
		if _, err := fmt.Fprintf(out, "%-12s %s\n", l[0], l[1]); err != nil {
			return err
		}
	}
	return nil
}

// treeBytes totals the regular files under root. It is best effort by design:
// an unreadable subtree contributes nothing rather than failing a status
// command, because the number is there to tell an operator whether the leftover
// copy is worth reclaiming, not to balance a ledger.
func treeBytes(root string) uint64 {
	var total uint64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree is skipped, never fatal
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += uint64(info.Size())
		}
		return nil
	})
	return total
}

// runDatavolDelete destroys the volume and every declaration of it.
//
// It is the ONE primitive that removes a data volume, and it is deliberately
// hard to reach: --yes is required, pkg/datavol refuses while either daemon is
// loaded, and it refuses a mount point no k3sm data root could be at. It never
// touches the .pre-volume copy of a migrated data root — that is the operator's
// rollback and only the operator deletes it.
func runDatavolDelete(args []string) error {
	fs := flag.NewFlagSet("datavol delete", flag.ContinueOnError)
	record := fs.String("record", dataroot.DefaultRecordPath, "the data-volume record to delete from")
	yes := fs.Bool("yes", false, "confirm: destroy the volume and everything on it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("k3sm datavol delete must run as root — use 'sudo k3sm datavol delete --yes'")
	}
	rec, err := dataroot.ReadRecord(dataroot.OSFS{}, *record)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("no data volume is recorded at %s; there is nothing to delete", *record)
	}
	opts := datavol.DeleteOptions{
		Yes:         *yes,
		FstabPath:   dataroot.FstabPath,
		NetdLabel:   install.NetdLabel,
		ServerLabel: install.ServerLabel,
	}
	if err := datavol.Delete(context.Background(), datavol.NewDarwin(), dataroot.OSFS{}, datavolLaunchd{}, *record, *rec, opts); err != nil {
		return err
	}
	fmt.Printf("data volume %s (%s) deleted; %s is gone with it\n", rec.Name, rec.UUID, rec.Mountpoint)
	return nil
}

// datavolLaunchd answers datavol.Delete's one question — is this LaunchDaemon
// loaded — from launchctl. It reuses the status command's print wrapper rather
// than shelling out a second way, so "loaded" means the same thing to the
// delete guard as it does to the status report.
type datavolLaunchd struct{}

// Loaded reports whether launchd has the label in the system domain. A
// non-zero exit is launchctl's answer for "no such service", which is the only
// thing this needs to tell apart.
func (datavolLaunchd) Loaded(label string) bool {
	_, err := launchctlProbe{}.Print(label)
	return err == nil
}
