package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	pacFetchTimeout = 2 * time.Second
	maxPACSize      = 1 << 20
)

var windowsDriveRE = regexp.MustCompile(`^/[A-Za-z]:`)

// fileURI returns the file URI of an absolute path.
func fileURI(path string) string {
	slashed := filepath.ToSlash(path)
	if len(slashed) == 0 || slashed[0] != '/' {
		slashed = "/" + slashed
	}
	return (&url.URL{Scheme: "file", Path: slashed}).String()
}

// fileURIPath returns the local path of a file URI.
func fileURIPath(u *url.URL) string {
	path := u.Path
	if windowsDriveRE.MatchString(path) {
		path = path[1:]
	}
	return filepath.FromSlash(path)
}

// pacSearch describes where to look for a PAC file.
type pacSearch struct {
	override  string
	envURI    string
	cwd       string
	configDir string
	homeDir   string
	system    func() string
}

// find returns the location of the first PAC file found, or an empty string.
//
// The order is the override, the environment, proxy.pac in the current dir, in the config dir of
// curlp, and in the home dir, and finally the PAC configured in the system.
func (s pacSearch) find() string {
	if s.override != "" {
		return s.override
	}
	if s.envURI != "" {
		return s.envURI
	}
	candidates := []string{
		filepath.Join(s.configDir, "curlp", "proxy.pac"),
		filepath.Join(s.homeDir, "proxy.pac"),
	}
	if s.cwd != "" {
		candidates = append([]string{filepath.Join(s.cwd, "proxy.pac")}, candidates...)
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return fileURI(candidate)
		}
	}
	if s.system != nil {
		return s.system()
	}
	return ""
}

// loadPAC reads the PAC script from a file URI or downloads it from an http(s) URL.
//
// The download ignores the proxy settings of the environment, as the PAC decides about them.
func loadPAC(location string, client *http.Client) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "file":
		data, err := os.ReadFile(fileURIPath(u))
		if err != nil {
			return "", err
		}
		return string(data), nil
	case "http", "https":
		ctx, cancel := context.WithTimeout(context.Background(), pacFetchTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("unexpected status %s", resp.Status)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxPACSize+1))
		if err != nil {
			return "", err
		}
		if len(data) > maxPACSize {
			return "", fmt.Errorf("PAC script is larger than %d bytes", maxPACSize)
		}
		return string(data), nil
	default:
		return "", fmt.Errorf("unsupported PAC location scheme %q", u.Scheme)
	}
}
