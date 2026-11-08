package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/x509roots/fallback/bundle"
)

var (
	insecureFlagRE = regexp.MustCompile(`^-[a-zA-Z]*k[a-zA-Z]*$`)
	certSuffixes   = map[string]bool{".pem": true, ".crt": true, ".cer": true}
)

// hasOwnTLSTrust reports whether args set their own CA store or disable certificate checks.
func hasOwnTLSTrust(args []string) bool {
	for _, arg := range args {
		switch {
		case arg == "--cacert", arg == "--capath", arg == "--insecure":
			return true
		case strings.HasPrefix(arg, "--cacert="), strings.HasPrefix(arg, "--capath="):
			return true
		case insecureFlagRE.MatchString(arg):
			return true
		}
	}
	return false
}

// readCertificates returns the PEM certificates of a file, or of all certificate files below a
// dir, without duplicates.
//
// Only CERTIFICATE blocks that parse are taken, so a private key in the same file never ends up
// in a bundle. A missing path gives no certificates.
func readCertificates(path string) ([][]byte, error) {
	// WalkDir does not descend into a root that is a symlink, so resolve it first.
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	path = resolved
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	files := []string{path}
	if info.IsDir() {
		files = nil
		walkErr := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip what cannot be read.
			}
			if !d.IsDir() && certSuffixes[strings.ToLower(filepath.Ext(p))] {
				files = append(files, p)
			}
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}

	seen := make(map[string]bool)
	var certs [][]byte
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for {
			var block *pem.Block
			block, data = pem.Decode(data)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				continue
			}
			encoded := pem.EncodeToMemory(block)
			if !seen[string(encoded)] {
				seen[string(encoded)] = true
				certs = append(certs, encoded)
			}
		}
	}
	return certs, nil
}

// buildBundle returns the standard root certificates followed by extra.
//
// Roots with constraints that PEM cannot express (distrust dates) are left out.
func buildBundle(extra [][]byte) []byte {
	var buf bytes.Buffer
	for root := range bundle.Roots() {
		if root.Constraint != nil {
			continue
		}
		// writing to a bytes.Buffer never fails.
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: root.Certificate})
	}
	for _, cert := range extra {
		buf.Write(cert)
	}
	return buf.Bytes()
}

// writeIfChanged replaces the file at path with data, unless it already has that content.
//
// The replacement is atomic, as parallel runs may rebuild the same bundle.
func writeIfChanged(path string, data []byte) error {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // fails after the rename, which is fine.
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// caBundleArgs returns the curl arguments that trust the certificates at caPath next to the
// standard roots, or nil if there are none or args set their own trust.
func caBundleArgs(args []string, caPath, bundlePath string) ([]string, error) {
	if hasOwnTLSTrust(args) {
		return nil, nil
	}
	certs, err := readCertificates(caPath)
	if err != nil || len(certs) == 0 {
		return nil, err
	}
	if err := writeIfChanged(bundlePath, buildBundle(certs)); err != nil {
		return nil, err
	}
	return []string{"--cacert", bundlePath}, nil
}
