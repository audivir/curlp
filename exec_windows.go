//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// runCurl runs curl with the standard streams attached and returns its exit code.
func runCurl(path string, args, env []string) int {
	cmd := exec.Command(path, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "curlp: cannot run curl: %v\n", err)
		return 127
	}
	return 0
}
