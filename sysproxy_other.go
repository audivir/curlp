//go:build !darwin

package main

// systemPACURL returns an empty string, as only macOS provides a system PAC to read.
func systemPACURL() (string, error) {
	return "", nil
}
