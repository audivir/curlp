package main

import (
	"bytes"
	"net/http"
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
		getenv:    func(string) string { return "" },
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
