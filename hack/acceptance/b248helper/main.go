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

// Command b248helper is the privileged driver behind the lab tier of
// hack/acceptance/B248.sh. It is a `go run` tool and is never part of the
// shipped k3sm binary.
//
// It exists because the two operations the lab tier has to prove -- creating a
// small scratch data volume, and migrating a plain directory onto one -- are
// reached in production only through `k3sm install --data-volume`, which also
// creates the service user, writes LaunchDaemons and takes over /var/lib/k3sm.
// Running the installer to prove the volume primitives would mean rebuilding
// the rig's cluster on every gate run. So the gate calls pkg/datavol directly,
// in the SAME order pkg/install does (Ensure -> Migrate -> MountRecorded ->
// WriteRecord), which is what makes the rung evidence about the product rather
// than about this file.
//
// Two properties keep it safe to run on a live rig:
//
//   - Every path it is given must sit under /Library/k3sm-acceptance-datavol/.
//     A mount point or record outside that root is refused before any disk
//     work happens, so the gate cannot reach the rig's real data volume, its
//     record at /Library/Preferences/io.k3sm.datavol.json, or /var/lib/k3sm.
//   - It never writes /etc/fstab. datavol.EnsureFstabLine is the installer's
//     business; a scratch volume that declared itself in fstab would be
//     mounted at boot forever after the gate had deleted it.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
)

// scratchRoot is the ONLY place this tool will touch. It is hard-coded rather
// than a flag: a guard the caller can move is not a guard.
const scratchRoot = "/Library/k3sm-acceptance-datavol"

const usage = `b248helper — the privileged driver behind hack/acceptance/B248.sh's lab tier

Usage:
  b248helper ensure  --name <vol> --size <n[mgt]> --mountpoint <dir> --record <file> [--encrypt]
  b248helper migrate --name <vol> [--size <n[mgt]>] --from <dir> --record <file> --staging <dir> [--remove-old]

Every --mountpoint, --record, --from and --staging must live under ` + scratchRoot + `/.
Both verbs print "uuid=<volume uuid>" on stdout; migrate adds a stats line.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	case "ensure":
		err = runEnsure(os.Args[2:])
	case "migrate":
		err = runMigrate(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		err = fmt.Errorf("unknown verb %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "b248helper: %v\n", err)
		os.Exit(1)
	}
}

// runEnsure creates or adopts a scratch data volume, mounts it and writes the
// record -- the three steps `k3sm install --data-volume` runs when there is no
// data to migrate, in that order.
func runEnsure(args []string) error {
	fs := flag.NewFlagSet("ensure", flag.ContinueOnError)
	name := fs.String("name", "", "APFS volume name to create or adopt")
	size := fs.String("size", "2g", "quota, as the install flag takes it (m, g or t)")
	mountpoint := fs.String("mountpoint", "", "where to mount it (under "+scratchRoot+"/)")
	record := fs.String("record", "", "where to write the record (under "+scratchRoot+"/)")
	encrypt := fs.Bool("encrypt", false, "encrypt the volume and keep the passphrase in the System keychain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	if err := inScratch("--mountpoint", *mountpoint); err != nil {
		return err
	}
	if err := inScratch("--record", *record); err != nil {
		return err
	}
	quota, err := datavol.ParseSize(*size)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*record), 0o700); err != nil {
		return fmt.Errorf("create the record directory: %w", err)
	}

	ctx := context.Background()
	deps := datavol.NewDarwin()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// AllowSmallQuota is set because a gate volume is 2 GiB and
	// datavol.MinQuotaBytes is 32 GiB: the minimum exists so a real data root
	// does not live permanently inside runtimed's reclaim band, which is not a
	// property a scratch volume that exists for ninety seconds needs.
	rec, plan, err := datavol.Ensure(ctx, deps, dataroot.OSFS{}, *record, datavol.Options{
		Name:            *name,
		Mountpoint:      filepath.Clean(*mountpoint),
		QuotaBytes:      quota,
		Encrypt:         *encrypt,
		CreatedBy:       "b248helper",
		AllowSmallQuota: true,
	})
	if err != nil {
		return err
	}
	if err := datavol.MountRecorded(ctx, deps, dataroot.OSFS{}, rec, datavol.Owner{}, logger); err != nil {
		return err
	}
	// Only after a verified mount, exactly as pkg/install does it.
	if err := dataroot.WriteRecord(*record, rec); err != nil {
		return err
	}
	fmt.Printf("uuid=%s\n", rec.UUID)
	fmt.Printf("name=%s mountpoint=%s quota=%d encrypted=%t created=%t adopted=%t existing=%t\n",
		rec.Name, rec.Mountpoint, rec.QuotaBytes, rec.Encrypted, plan.Created, plan.Adopted, plan.Existing)
	return nil
}

// runMigrate moves a plain directory onto a freshly created scratch volume.
//
// It runs the whole installer sequence rather than datavol.Migrate alone,
// because Migrate takes the record of a volume that exists and is NOT yet
// mounted -- which is the state pkg/install's Ensure leaves behind and no
// standalone gate step can otherwise produce. Ensuring a volume here and
// mounting it first would put k3sm's markers on the destination before the
// copy and prove a different sequence than the one that ships.
func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	name := fs.String("name", "", "APFS volume name to create for the migration")
	size := fs.String("size", "2g", "quota, as the install flag takes it (m, g or t)")
	from := fs.String("from", "", "the plain data root to migrate (under "+scratchRoot+"/)")
	record := fs.String("record", "", "where to write the record (under "+scratchRoot+"/)")
	staging := fs.String("staging", "", "the staging mount point (under "+scratchRoot+"/)")
	removeOld := fs.Bool("remove-old", false, "delete the .pre-volume copy once the migration is verified")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	for _, p := range [][2]string{{"--from", *from}, {"--record", *record}, {"--staging", *staging}} {
		if err := inScratch(p[0], p[1]); err != nil {
			return err
		}
	}
	quota, err := datavol.ParseSize(*size)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*record), 0o700); err != nil {
		return fmt.Errorf("create the record directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Clean(*staging), 0o700); err != nil {
		return fmt.Errorf("create the staging mount point: %w", err)
	}

	ctx := context.Background()
	deps := datavol.NewDarwin()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	rec, _, err := datavol.Ensure(ctx, deps, dataroot.OSFS{}, *record, datavol.Options{
		Name:            *name,
		Mountpoint:      filepath.Clean(*from),
		QuotaBytes:      quota,
		CreatedBy:       "b248helper",
		AllowSmallQuota: true,
	})
	if err != nil {
		return err
	}
	fmt.Printf("uuid=%s\n", rec.UUID)

	stats, err := datavol.Migrate(ctx, deps, dataroot.OSFS{}, ditto{}, rec, filepath.Clean(*from), filepath.Clean(*staging),
		datavol.MigrateOptions{RemoveOld: *removeOld})
	if err != nil {
		return err
	}
	if err := datavol.MountRecorded(ctx, deps, dataroot.OSFS{}, rec, datavol.Owner{}, logger); err != nil {
		return err
	}
	if err := dataroot.WriteRecord(*record, rec); err != nil {
		return err
	}
	if err := os.Remove(filepath.Clean(*staging)); err != nil {
		logger.Warn("the staging mount point could not be removed", "staging", *staging, "err", err)
	}
	fmt.Printf("files=%d bytes=%d copy=%s verify=%s\n", stats.Files, stats.Bytes, stats.CopyDuration, stats.VerifyDuration)
	return nil
}

// ditto is the MigrateSystem the installer uses, spelled the same way: ditto(1)
// for the copy (it preserves ownership, modes, xattrs and ACLs, which a Go walk
// would not), rename for the move aside, RemoveAll for --remove-old.
type ditto struct{}

// CopyTree copies src into dst with ditto(1).
func (ditto) CopyTree(src, dst string) error {
	out, err := exec.Command("ditto", filepath.Clean(src)+"/", filepath.Clean(dst)+"/").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ditto %s/ -> %s/: %w: %s", src, dst, err, out)
	}
	return nil
}

// Rename moves old to new within one filesystem.
func (ditto) Rename(old, new string) error { return os.Rename(old, new) }

// RemoveAll deletes path and everything under it.
func (ditto) RemoveAll(path string) error { return os.RemoveAll(path) }

// inScratch refuses any path outside scratchRoot. It is the whole safety story
// of this tool: everything downstream of it unmounts, creates and destroys APFS
// volumes as root, and the one thing that must never happen is a gate run
// aiming any of that at the rig's live data root.
func inScratch(label, p string) error {
	if p == "" {
		return fmt.Errorf("%s is required", label)
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s %q must be an absolute path under %s/", label, p, scratchRoot)
	}
	clean := filepath.Clean(p)
	if !strings.HasPrefix(clean, scratchRoot+"/") {
		return fmt.Errorf("%s %q is outside %s/ — this tool refuses to touch anything else", label, p, scratchRoot)
	}
	return nil
}
