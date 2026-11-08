package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want options
	}{
		{
			name: "pac file with separate value is not forwarded",
			argv: []string{"--pac-file", "a.pac", "-s", "http://x"},
			want: options{pacFile: "a.pac", curlArgs: []string{"-s", "http://x"}},
		},
		{
			name: "pac file with equals sign",
			argv: []string{"--pac-file=a.pac", "http://x"},
			want: options{pacFile: "a.pac", curlArgs: []string{"http://x"}},
		},
		{
			name: "last verbose flag wins and curl still gets them",
			argv: []string{"-v", "--no-verbose", "http://x"},
			want: options{curlArgs: []string{"-v", "--no-verbose", "http://x"}},
		},
		{
			name: "short flag bundles with v and h",
			argv: []string{"-sv", "-sh"},
			want: options{verbose: true, help: true, curlArgs: []string{"-sv", "-sh"}},
		},
		{
			name: "uppercase H for headers is no help flag",
			argv: []string{"-H", "A: b", "http://x"},
			want: options{curlArgs: []string{"-H", "A: b", "http://x"}},
		},
		{
			name: "own version flag is not forwarded",
			argv: []string{"--curlp-version"},
			want: options{showVersion: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseArgs(tt.argv)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseArgs() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseArgsPACFileWithoutValue(t *testing.T) {
	if _, err := parseArgs([]string{"http://x", "--pac-file"}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestTargetURL(t *testing.T) {
	tests := []struct {
		arg      string
		wantHost string
		wantOK   bool
	}{
		{"git.example.test", "git.example.test", true},
		{"localhost:8080/path", "localhost", true},
		{"https://user@host.example/p?q=1", "host.example", true},
		{"  example.com  ", "example.com", true},
		{"http://", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			u, ok := targetURL([]string{"-s", tt.arg})
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && u.Hostname() != tt.wantHost {
				t.Errorf("host = %q, want %q", u.Hostname(), tt.wantHost)
			}
		})
	}
}

func TestToPACLocation(t *testing.T) {
	got, err := toPACLocation("http://127.0.0.1:1112/proxy.pac")
	if err != nil || got != "http://127.0.0.1:1112/proxy.pac" {
		t.Errorf("URL changed: %q, %v", got, err)
	}

	got, err = toPACLocation("rel dir/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs("rel dir/proxy.pac")
	if !strings.HasPrefix(got, "file:///") || !strings.HasSuffix(got, "rel%20dir/proxy.pac") {
		t.Errorf("path %q became %q, want an escaped file URI of %q", "rel dir/proxy.pac", got, abs)
	}
}
