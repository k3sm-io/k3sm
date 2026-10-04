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
	"io"
	"log/slog"
)

// newDaemonLogger builds the text logger a daemon command runs under and
// installs it as the process default with slog.SetDefault. It is process-global
// and for daemon entry points only: library code that calls slog.Default() or
// the package-level slog functions then shares the daemon's handler and level
// instead of Go's legacy Info handler.
func newDaemonLogger(w io.Writer, level slog.Leveler) *slog.Logger {
	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	return logger
}
