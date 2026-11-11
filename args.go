package main

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	helpFlagRE    = regexp.MustCompile(`^-[a-zA-Z]*h[a-zA-Z]*$`)
	verboseFlagRE = regexp.MustCompile(`^-[a-zA-Z]*v[a-zA-Z]*$`)
	schemeRE      = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)
)

// options holds the options of curlp and the arguments that are forwarded to curl.
type options struct {
	pacFile     string
	showVersion bool
	envURL      string
	noCA        bool
	noPAC       bool
	localDNS    bool
	verbose     bool
	help        bool
	curlArgs    []string
}

// parseArgs splits argv into the options of curlp and the arguments for curl.
//
// The verbose and help flags also stay in the curl arguments, as curl understands them too.
func parseArgs(argv []string) (options, error) {
	var opts options
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--pac-file":
			if i+1 >= len(argv) {
				return options{}, errors.New("option --pac-file: requires parameter")
			}
			opts.pacFile = argv[i+1]
			i++
			continue
		case strings.HasPrefix(arg, "--pac-file="):
			opts.pacFile = strings.TrimPrefix(arg, "--pac-file=")
			continue
		case arg == "--curlp-env":
			if i+1 >= len(argv) {
				return options{}, errors.New("option --curlp-env: requires parameter")
			}
			opts.envURL = argv[i+1]
			i++
			continue
		case strings.HasPrefix(arg, "--curlp-env="):
			opts.envURL = strings.TrimPrefix(arg, "--curlp-env=")
			continue
		case arg == "--curlp-version":
			opts.showVersion = true
			continue
		case arg == "--no-curlp-ca":
			opts.noCA = true
			continue
		case arg == "--no-pac":
			opts.noPAC = true
			continue
		case arg == "--local-dns":
			opts.localDNS = true
			continue
		case arg == "--help" || helpFlagRE.MatchString(arg):
			opts.help = true
		case arg == "--verbose" || verboseFlagRE.MatchString(arg):
			opts.verbose = true
		case arg == "--no-verbose":
			opts.verbose = false
		}
		opts.curlArgs = append(opts.curlArgs, arg)
	}
	return opts, nil
}

// toPACLocation turns a path or URI given with --pac-file into a URI.
func toPACLocation(value string) (string, error) {
	if u, err := url.Parse(value); err == nil && len(u.Scheme) > 1 {
		return value, nil
	}
	path := value
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, rest)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return fileURI(abs), nil
}

// targetURL parses the last argument as the URL curl requests.
//
// Like curl, it assumes http for a URL without a scheme. The second result is false if the
// argument has no host.
func targetURL(args []string) (*url.URL, bool) {
	if len(args) == 0 {
		return nil, false
	}
	value := strings.TrimSpace(args[len(args)-1])
	if value == "" {
		return nil, false
	}
	if !schemeRE.MatchString(value) {
		value = "http://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return nil, false
	}
	return u, true
}
