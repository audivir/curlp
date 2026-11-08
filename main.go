// Command curlp wraps curl with automatic PAC-based proxy resolution.
package main

import (
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

const helpText = `curlp options:
  Wraps curl with automatic PAC-based proxy resolution.
  --pac-file <path|uri>  Use this PAC file instead of searching for one.
  --curlp-version        Print the version of curlp.
  PAC file location (first match wins):
    --pac-file
    $CURLP_PAC_URI
    ./proxy.pac
    $XDG_CONFIG_HOME/curlp/proxy.pac (or ~/.config/curlp/proxy.pac)
    ~/proxy.pac
    automatic proxy configuration URL of macOS
  All certificates in $CURLP_CA_PATH (a file or dir, default ~/.config/ssl) are trusted
  next to the standard roots, unless --cacert, --capath, or -k is given.
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
	getenv    func(string) string
	cwd       string
	homeDir   string
	configDir string
	systemPAC func() (string, error)
	lookup    lookupFunc
	client    *http.Client
}

// newConfig returns the config for the running process.
func newConfig(log logger) config {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		configDir = filepath.Join(home, ".config")
	}
	return config{
		log:       log,
		getenv:    os.Getenv,
		cwd:       cwd,
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
}

// planCurl decides which proxy and CA bundle curl gets for the request in opts.
//
// Every problem with the PAC or the bundle is reported as a warning, and curl then runs without
// the part that failed.
func planCurl(opts options, cfg config) plan {
	p := plan{args: opts.curlArgs, env: map[string]string{}}

	caPath := cfg.getenv("CURLP_CA_PATH")
	if caPath == "" {
		caPath = filepath.Join(cfg.homeDir, ".config", "ssl")
	}
	bundlePath := filepath.Join(cfg.homeDir, ".cache", "curlp", "ca-bundle.pem")
	caArgs, err := caBundleArgs(opts.curlArgs, caPath, bundlePath)
	if err != nil {
		cfg.log.warnf("Could not prepare the CA bundle: %v", err)
	}
	p.args = append(caArgs, opts.curlArgs...)

	override := opts.pacFile
	if override != "" {
		if override, err = toPACLocation(override); err != nil {
			cfg.log.warnf("Invalid --pac-file: %v", err)
			return p
		}
	}
	search := pacSearch{
		override:  override,
		envURI:    cfg.getenv("CURLP_PAC_URI"),
		cwd:       cfg.cwd,
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

	curlPath, err := exec.LookPath("curl")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "curlp: curl not found in PATH")
		return 127
	}

	env := os.Environ()
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
