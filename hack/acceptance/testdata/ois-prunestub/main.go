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

// Command ois-prunestub is the node-cache half the one-image-store lab gate's ois.8
// gives `k3sm image prune --force` (hack/acceptance/one-image-store.sh). The real
// daemon's PruneImages has no filter: it evicts every image no pod uses at that
// moment, another workload's included, and the gate must touch only what it pushed.
// So the forced prune dials this socket instead, and PruneImages answers that it
// removed nothing. The registry half is untouched by this, which is what ois.8 asserts.
//
// Usage: ois-prunestub <socket> <lifetime>. It exits on its own after lifetime, so a
// run that dies cannot leave it behind.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

type images struct {
	runtimev1.UnimplementedImagesServer
}

func (images) PruneImages(_ context.Context, req *runtimev1.PruneImagesRequest) (*runtimev1.PruneImagesResponse, error) {
	fmt.Printf("PruneImages dry_run=%v: answered with nothing removed\n", req.GetDryRun())
	return &runtimev1.PruneImagesResponse{}, nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: ois-prunestub <socket> <lifetime>")
		os.Exit(2)
	}
	lifetime, err := time.ParseDuration(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "ois-prunestub:", err)
		os.Exit(2)
	}
	l, err := net.Listen("unix", os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "ois-prunestub:", err)
		os.Exit(1)
	}
	s := grpc.NewServer()
	runtimev1.RegisterImagesServer(s, images{})
	time.AfterFunc(lifetime, s.Stop)
	if err := s.Serve(l); err != nil {
		fmt.Fprintln(os.Stderr, "ois-prunestub:", err)
		os.Exit(1)
	}
}
