//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// runCurl replaces the process with curl, so that curl handles signals and exit codes itself.
//
// It returns only if the replacement fails.
func runCurl(path string, args, env []string) int {
	err := syscall.Exec(path, append([]string{"curl"}, args...), env)
	_, _ = fmt.Fprintf(os.Stderr, "curlp: cannot run curl: %v\n", err)
	return 127
}
