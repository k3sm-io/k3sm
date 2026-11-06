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

// Command vmpodfitaudit lists the vm objects the vm pod fit policy would refuse. It
// reads the JSON of "kubectl get pods,deploy,sts,ds,rs,job,cronjob -A -o json" on
// stdin and prints one row per refusal: object, rule, message. It makes no cluster
// call. Exit 0: nothing refused; 1: at least one object refused; 2: input error.
package main

import (
	"errors"
	"fmt"
	"os"

	"k3sm.io/k3sm/pkg/policy"
)

func main() {
	err := policy.AuditVMPodFit(os.Stdin, os.Stdout)
	switch {
	case err == nil:
	case errors.Is(err, policy.ErrVMPodFitRefused):
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
