// Package gen is a pinned-tools fixture: only //go:generate lines run commands.
package gen

// An ordinary comment is not a command: go install example.com/x@latest

//go:generate go run example.com/tool/cmd/gen@v1.0.0 -out table.go
//go:generate go run ./internal/gen
