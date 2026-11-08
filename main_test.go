package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func testConfig(t *testing.T, log *bytes.Buffer) config {
	t.Helper()
	root := t.TempDir()
	return config{
		log:       logger{out: log, verbose: true},
		lookupEnv: func(string) (string, bool) { return "", false },
		cwd:       filepath.Join(root, "cwd"),
		homeDir:   filepath.Join(root, "home"),
		configDir: filepath.Join(root, "home", ".config"),
		systemPAC: func() (string, error) { return "", nil },
		lookup:    stubLookup(nil),
		client:    http.DefaultClient,
	}
}

func TestPlanCurlSetsBothProxyVariablesFromPAC(t *testing.T) {
	var log bytes.Buffer
	cfg := testConfig(t, &log)
	writeFile(t, filepath.Join(cfg.configDir, "curlp", "proxy.pac"), clusterPAC)

	p := planCurl(options{curlArgs: []string{"-s", "git.example.test"}}, cfg)
	want := map[string]string{
		"http_proxy":  "socks5://127.0.0.1:1111",
		"https_proxy": "socks5://127.0.0.1:1111",
	}
	if !reflect.DeepEqual(p.env, want) {
		t.Errorf("env = %v, want %v", p.env, want)
	}
	if !reflect.DeepEqual(p.args, []string{"-s", "git.example.test"}) {
		t.Errorf("args = %v", p.args)
	}

	p = planCurl(options{curlArgs: []string{"https://example.com"}}, cfg)
	if len(p.env) != 0 {
		t.Errorf("a DIRECT result must set no proxy, got %v", p.env)
	}
}

func TestPlanCurlNoPACSkipsEvenAnExplicitPACFile(t *testing.T) {
	var log bytes.Buffer
	cfg := testConfig(t, &log)
	pac := filepath.Join(t.TempDir(), "proxy.pac")
	writeFile(t, pac, clusterPAC)
	writeFile(t, filepath.Join(cfg.configDir, "curlp", "proxy.pac"), clusterPAC)

	p := planCurl(options{noPAC: true, pacFile: pac, curlArgs: []string{"git.example.test"}}, cfg)
	if len(p.env) != 0 {
		t.Errorf("--no-pac must set no proxy, got %v", p.env)
	}
	if !strings.Contains(log.String(), "PAC disabled") {
		t.Errorf("log = %q", log.String())
	}
}

func TestPlanCurlWithoutPACOrWithBrokenPAC(t *testing.T) {
	var log bytes.Buffer
	cfg := testConfig(t, &log)
	opts := options{curlArgs: []string{"-s", "http://x"}}

	if p := planCurl(opts, cfg); len(p.env) != 0 || !strings.Contains(log.String(), "No PAC file found") {
		t.Errorf("no PAC: env = %v, log = %q", p.env, log.String())
	}

	log.Reset()
	writeFile(t, filepath.Join(cfg.configDir, "curlp", "proxy.pac"), "function FindProxyForURL(")
	p := planCurl(opts, cfg)
	if len(p.env) != 0 || !reflect.DeepEqual(p.args, opts.curlArgs) {
		t.Errorf("broken PAC must leave the request alone: env = %v, args = %v", p.env, p.args)
	}
	if !strings.Contains(log.String(), "Could not use the PAC file") {
		t.Errorf("broken PAC must be reported, log = %q", log.String())
	}
}

func TestPlanCurlReportsMissingPACFileOverride(t *testing.T) {
	var log bytes.Buffer
	cfg := testConfig(t, &log)
	opts := options{pacFile: filepath.Join(t.TempDir(), "missing.pac"), curlArgs: []string{"http://x"}}

	p := planCurl(opts, cfg)
	if len(p.env) != 0 || !strings.Contains(log.String(), "Could not load the PAC file") {
		t.Errorf("env = %v, log = %q", p.env, log.String())
	}
}

func TestPlanCurlAddsCABundleBeforeUserArguments(t *testing.T) {
	var log bytes.Buffer
	cfg := testConfig(t, &log)
	writeFile(t, filepath.Join(cfg.homeDir, ".config", "ssl", "ca.pem"), string(testCert(t, 1)))

	p := planCurl(options{curlArgs: []string{"-s", "https://x"}}, cfg)
	bundle := filepath.Join(cfg.homeDir, ".cache", "curlp", "ca-bundle.pem")
	if want := []string{"--cacert", bundle, "-s", "https://x"}; !reflect.DeepEqual(p.args, want) {
		t.Errorf("args = %v, want %v", p.args, want)
	}
}

func TestPlanCurlCAControls(t *testing.T) {
	custom := t.TempDir()
	writeFile(t, filepath.Join(custom, "other.pem"), string(testCert(t, 9)))

	tests := []struct {
		name   string
		opts   options
		env    map[string]string
		wantCA bool
	}{
		{name: "default dir", wantCA: true},
		{name: "per call switch", opts: options{noCA: true}},
		{name: "empty variable turns it off", env: map[string]string{"CURLP_CA_PATH": ""}},
		{name: "variable selects another dir", env: map[string]string{"CURLP_CA_PATH": custom}, wantCA: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var log bytes.Buffer
			cfg := testConfig(t, &log)
			writeFile(t, filepath.Join(cfg.homeDir, ".config", "ssl", "ca.pem"), string(testCert(t, 1)))
			cfg.lookupEnv = func(name string) (string, bool) {
				value, ok := tt.env[name]
				return value, ok
			}
			tt.opts.curlArgs = []string{"-s", "https://x"}

			p := planCurl(tt.opts, cfg)
			hasCA := len(p.args) > 2 && p.args[0] == "--cacert"
			if hasCA != tt.wantCA {
				t.Errorf("args = %v, want a CA bundle: %v", p.args, tt.wantCA)
			}
			if !hasCA && !reflect.DeepEqual(p.args, tt.opts.curlArgs) {
				t.Errorf("without a bundle the arguments must stay unchanged, got %v", p.args)
			}
		})
	}
}

func executable(t *testing.T, path string) {
	t.Helper()
	writeFile(t, path, "#!/bin/sh\n")
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func envOf(vars map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := vars[name]
		return value, ok
	}
}

func TestFindCurlExplicitPath(t *testing.T) {
	dir := t.TempDir()
	curl, self := filepath.Join(dir, "my-curl"), filepath.Join(dir, "curlp")
	executable(t, curl)
	executable(t, self)
	writeFile(t, filepath.Join(dir, "plain-file"), "x")

	if got, err := findCurl(envOf(map[string]string{"CURLP_CURL_PATH": curl}), self); err != nil || got != curl {
		t.Errorf("explicit path: got %q, %v", got, err)
	}
	for name, value := range map[string]string{
		"not executable": filepath.Join(dir, "plain-file"),
		"missing":        filepath.Join(dir, "missing"),
		"curlp itself":   self,
	} {
		if got, err := findCurl(envOf(map[string]string{"CURLP_CURL_PATH": value}), self); err == nil {
			t.Errorf("%s must be an error, not a fallback to another curl, got %q", name, got)
		}
	}
}

func TestFindCurlSkipsItselfInPATH(t *testing.T) {
	root := t.TempDir()
	first, second := filepath.Join(root, "first"), filepath.Join(root, "second")
	self := filepath.Join(first, "curlp")
	executable(t, self)
	real := filepath.Join(second, "curl")
	executable(t, real)
	pathVar := strings.Join([]string{"", first, second}, string(os.PathListSeparator))

	// curlp installed as "curl" through a symlink or a hard link comes first in PATH.
	for name, link := range map[string]func(string, string) error{"symlink": os.Symlink, "hard link": os.Link} {
		t.Run(name, func(t *testing.T) {
			alias := filepath.Join(first, "curl")
			_ = os.Remove(alias)
			if err := link(self, alias); err != nil {
				t.Fatal(err)
			}
			got, err := findCurl(envOf(map[string]string{"PATH": pathVar}), self)
			if err != nil || got != real {
				t.Errorf("got %q, %v, want the curl after curlp in PATH", got, err)
			}
		})
	}

	if _, err := findCurl(envOf(map[string]string{"PATH": first}), self); err == nil {
		t.Error("with only curlp named curl in PATH there is nothing to run")
	}
}

func TestWithEnvReplacesInheritedValues(t *testing.T) {
	// an exec'd process reads the first entry of a variable, so duplicates would lose.
	env := []string{"A=1", "http_proxy=http://old:1", "B=2=3"}
	got := withEnv(env, map[string]string{"http_proxy": "socks5://new:2", "https_proxy": "socks5://new:2"})
	sort.Strings(got)
	want := []string{"A=1", "B=2=3", "http_proxy=socks5://new:2", "https_proxy=socks5://new:2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
