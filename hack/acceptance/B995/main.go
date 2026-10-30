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

// Command B995 is the Security framework probe behind
// hack/acceptance/B995.sh. It asks the framework, never codesign, whether a
// file on disk satisfies a code requirement, and what its signature carries.
// It is a test tool and is never part of the shipped k3sm binary.
//
// Usage:
//
//	B995 check <path> <requirement>   one JSON line: verdict, status, error, wall time
//	B995 info <path>                  one JSON line: identifier, team, flags, entitlements, info-plist
//
// The exit status of check is 0 when the requirement is satisfied, 1 when it
// is not, and 2 on a usage or setup error; the script reads the JSON verdict.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// usage prints the command line and exits 2.
func usage() {
	fmt.Fprintln(os.Stderr, "usage: B995 check <path> <requirement> | B995 info <path>")
	os.Exit(2)
}

// emit writes v as one JSON line on stdout.
func emit(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(2)
	}
	fmt.Println(string(b))
}

func main() {
	if len(os.Args) < 3 {
		usage()
	}
	switch os.Args[1] {
	case "check":
		if len(os.Args) != 4 {
			usage()
		}
		r, err := check(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		emit(r)
		if !r.Satisfied {
			os.Exit(1)
		}
	case "info":
		if len(os.Args) != 3 {
			usage()
		}
		r, err := info(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		emit(r)
	default:
		usage()
	}
}

// CheckResult is the outcome of one requirement check.
type CheckResult struct {
	Path        string  `json:"path"`
	Requirement string  `json:"requirement"`
	Satisfied   bool    `json:"satisfied"`
	Status      int     `json:"status"`
	Error       string  `json:"error,omitempty"`
	WallMillis  float64 `json:"wall_ms"`
}

// InfoResult is what SecCodeCopySigningInformation reports for one file.
type InfoResult struct {
	Path            string   `json:"path"`
	Identifier      string   `json:"identifier"`
	Team            string   `json:"team"`
	Flags           uint32   `json:"flags"`
	HardenedRuntime bool     `json:"hardened_runtime"`
	Entitlements    []string `json:"entitlements"`
	InfoPlist       bool     `json:"info_plist"`
	BundleID        string   `json:"bundle_id,omitempty"`
	ShortVersion    string   `json:"short_version,omitempty"`
}
