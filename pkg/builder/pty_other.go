//go:build !darwin

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

package builder

import (
	"context"
	"io"
	"os"
)

// IsTerminal reports false: only darwin runs buildx on a pseudo-terminal.
func IsTerminal(*os.File) bool { return false }

// RunBuildxPTY is RunBuildxTo with buildx's stderr copied to term and log.
func RunBuildxPTY(ctx context.Context, bin string, args, env []string, stdout io.Writer, term *os.File, log io.Writer) error {
	return RunBuildxTo(ctx, bin, args, env, stdout, io.MultiWriter(term, log))
}
