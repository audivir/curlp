// Command curlp wraps curl with automatic PAC-based proxy resolution.
package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = "dev"

// activeVar is set for the curl that curlp starts, to detect a curlp that runs itself.
const activeVar = "CURLP_ACTIVE"

const helpText = `curlp: curl with automatic PAC-based proxy selection

Usage: curlp [curlp options] [curl arguments] URL

Options of curlp (all other arguments go to curl):
  --pac-file <path|uri>  Use this PAC file instead of searching for one.
  --no-pac               Do not use a PAC file for this call (wins over --pac-file).
  --no-curlp-ca          Do not trust the additional certificates for this call.
  --curlp-version        Print the version of curlp.
  --curlp-env <url>      Print the environment for a program other than curl that requests
                         this URL, one NAME=value per line, and exit: HTTPS_PROXY and
                         HTTP_PROXY if the PAC selects a proxy, and SSL_CERT_FILE with the
                         bundle of the additional certificates if there are any.

Environment:
  CURLP_PAC_URI          PAC file to use, as a path, file URI, or http(s) URL.
  CURLP_CURL_PATH        The curl to run, as a path or a name looked up in PATH.
                         Without it, the first curl in PATH that is not curlp runs.
  CURLP_CA_PATH          File or directory of certificates to trust next to the standard
                         roots (default ~/.config/ssl). Empty turns this off.

PAC file search (first match wins):
  1. --pac-file
  2. $CURLP_PAC_URI
  3. $XDG_CONFIG_HOME/curlp/proxy.pac (or ~/.config/curlp/proxy.pac)
  4. ~/proxy.pac
  5. the automatic proxy configuration URL of macOS, if enabled in the network settings

The additional certificates are skipped if curl gets --cacert, --capath, or -k.
`

// logger writes the messages of curlp to out, with the info messages only if verbose is set.
type logger struct {
	out     io.Writer
	verbose bool
}

func (l logger) infof(format string, args ...any) {
	if l.verbose {
		_, _ = fmt.Fprintf(l.out, format+"\n", args...)
	}
}

func (l logger) warnf(format string, args ...any) {
	_, _ = fmt.Fprintf(l.out, format+"\n", args...)
}

// config holds what planCurl reads from its surroundings, so that tests can replace it.
type config struct {
	log       logger
	lookupEnv func(string) (string, bool)
	homeDir   string
	configDir string
	systemPAC func() (string, error)
	lookup    lookupFunc
	client    *http.Client
}

// newConfig returns the config for the running process.
func newConfig(log logger) config {
	home, _ := os.UserHomeDir()
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		configDir = filepath.Join(home, ".config")
	}
	return config{
		log:       log,
		lookupEnv: os.LookupEnv,
		homeDir:   home,
		configDir: configDir,
		systemPAC: systemPACURL,
		lookup:    lookupIPv4,
		client:    &http.Client{Transport: &http.Transport{}},
	}
}

// plan holds the arguments for curl and the environment variables to set for it.
type plan struct {
	args []string
	env  map[string]string
	// caBundle is the bundle with the additional certificates, if planCurl made one.
	caBundle string
}

// planCurl decides which proxy and CA bundle curl gets for the request in opts.
//
// Every problem with the PAC or the bundle is reported as a warning, and curl then runs without
// the part that failed.
func planCurl(opts options, cfg config) plan {
	p := plan{args: opts.curlArgs, env: map[string]string{}}

	// a set but empty CURLP_CA_PATH turns the additional certificates off.
	caPath, caSet := cfg.lookupEnv("CURLP_CA_PATH")
	if !caSet {
		caPath = filepath.Join(cfg.homeDir, ".config", "ssl")
	}
	if !opts.noCA && caPath != "" {
		bundlePath := filepath.Join(cfg.homeDir, ".cache", "curlp", "ca-bundle.pem")
		caArgs, err := caBundleArgs(opts.curlArgs, caPath, bundlePath)
		if err != nil {
			cfg.log.warnf("Could not prepare the CA bundle: %v", err)
		}
		p.args = append(caArgs, opts.curlArgs...)
		if len(caArgs) == 2 {
			p.caBundle = bundlePath
		}
	}

	if opts.noPAC {
		cfg.log.infof("PAC disabled; forwarding args to curl without a proxy")
		return p
	}

	override := opts.pacFile
	if override != "" {
		var err error
		if override, err = toPACLocation(override); err != nil {
			cfg.log.warnf("Invalid --pac-file: %v", err)
			return p
		}
	}
	envURI, _ := cfg.lookupEnv("CURLP_PAC_URI")
	search := pacSearch{
		override:  override,
		envURI:    envURI,
		configDir: cfg.configDir,
		homeDir:   cfg.homeDir,
		system: func() string {
			location, err := cfg.systemPAC()
			if err != nil {
				cfg.log.infof("Could not read the PAC of the system: %v", err)
			}
			return location
		},
	}
	location := search.find()
	if location == "" {
		cfg.log.infof("No PAC file found; forwarding args to curl without a proxy")
		return p
	}

	target, ok := targetURL(opts.curlArgs)
	if !ok {
		cfg.log.infof("No URL in the arguments; forwarding args to curl without a proxy")
		return p
	}

	cfg.log.infof("Parsing PAC file from %s", location)
	script, err := loadPAC(location, cfg.client)
	if err != nil {
		cfg.log.warnf("Could not load the PAC file from %s: %v; forwarding without a proxy", location, err)
		return p
	}
	runtime, err := newPACRuntime(script, cfg.lookup)
	if err != nil {
		cfg.log.warnf("Could not use the PAC file from %s: %v; forwarding without a proxy", location, err)
		return p
	}
	proxy, err := runtime.findProxy(target.String(), target.Hostname())
	if err != nil {
		cfg.log.warnf("Could not evaluate the PAC file from %s: %v; forwarding without a proxy", location, err)
		return p
	}
	if proxy == "" {
		cfg.log.infof("Forwarding args to curl without a proxy")
		return p
	}
	cfg.log.infof("Using proxy: %s", proxy)
	p.env["http_proxy"] = proxy
	p.env["https_proxy"] = proxy
	return p
}

// envLines returns the environment for another program that requests rawURL, as NAME=value.
//
// The program is not curl, so the proxy is given as HTTPS_PROXY and HTTP_PROXY, and the
// additional certificates as SSL_CERT_FILE.
func envLines(rawURL string, opts options, cfg config) []string {
	opts.curlArgs = []string{rawURL}
	p := planCurl(opts, cfg)
	var lines []string
	if proxy := p.env["https_proxy"]; proxy != "" {
		lines = append(lines, "HTTPS_PROXY="+proxy, "HTTP_PROXY="+proxy)
	}
	if p.caBundle != "" {
		lines = append(lines, "SSL_CERT_FILE="+p.caBundle)
	}
	return lines
}

// findCurl returns the curl to run: $CURLP_CURL_PATH if set, otherwise the first curl in PATH.
//
// The value of $CURLP_CURL_PATH is a path or a name that is looked up in PATH, and it must be
// executable. Any candidate that is the same file as self is skipped when searching PATH, so
// curlp can be installed under the name curl. A $CURLP_CURL_PATH that names self is an error.
func findCurl(lookupEnv func(string) (string, bool), self string) (string, error) {
	if name, ok := lookupEnv("CURLP_CURL_PATH"); ok && name != "" {
		path, err := exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("cannot find curl %q: %w", name, err)
		}
		if sameFile(path, self) {
			return "", fmt.Errorf("CURLP_CURL_PATH %q is curlp itself", name)
		}
		return path, nil
	}

	pathVar, _ := lookupEnv("PATH")
	for _, dir := range filepath.SplitList(pathVar) {
		if dir == "" {
			continue
		}
		path, err := exec.LookPath(filepath.Join(dir, "curl"))
		if err == nil && !sameFile(path, self) {
			return path, nil
		}
	}
	return "", errors.New("curl not found in PATH (curlp itself is skipped)")
}

// sameFile reports whether a and b are the same file, following symlinks and hard links.
func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
}

// withEnv returns env with the variables in set replacing any earlier value.
//
// An exec'd process reads the first entry of a variable, so a plain append would not override.
func withEnv(env []string, set map[string]string) []string {
	out := make([]string, 0, len(env)+len(set))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := set[name]; !replaced {
			out = append(out, entry)
		}
	}
	for name, value := range set {
		out = append(out, name+"="+value)
	}
	return out
}

func run(argv []string) int {
	opts, err := parseArgs(argv)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "curlp: %v\n", err)
		return 1
	}
	if opts.showVersion {
		fmt.Println("curlp", version)
		return 0
	}

	if opts.envURL != "" {
		cfg := newConfig(logger{out: os.Stderr, verbose: opts.verbose})
		for _, line := range envLines(opts.envURL, opts, cfg) {
			fmt.Println(line)
		}
		return 0
	}

	// the guard catches a copy of curlp that findCurl cannot recognize as itself.
	if _, active := os.LookupEnv(activeVar); active {
		_, _ = fmt.Fprintln(os.Stderr, "curlp: called by itself; set CURLP_CURL_PATH to the real curl")
		return 1
	}
	self, _ := os.Executable()
	curlPath, err := findCurl(os.LookupEnv, self)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "curlp: %v\n", err)
		return 127
	}

	env := withEnv(os.Environ(), map[string]string{activeVar: "1"})
	if opts.help {
		_, _ = fmt.Fprint(os.Stderr, helpText)
		return runCurl(curlPath, opts.curlArgs, env)
	}
	if len(opts.curlArgs) == 0 {
		return runCurl(curlPath, nil, env)
	}

	p := planCurl(opts, newConfig(logger{out: os.Stderr, verbose: opts.verbose}))
	return runCurl(curlPath, p.args, withEnv(env, p.env))
}

func main() {
	os.Exit(run(os.Args[1:]))
}
