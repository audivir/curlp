package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPACSearchOrder(t *testing.T) {
	root := t.TempDir()
	configDir, home := filepath.Join(root, "cfg"), filepath.Join(root, "home")
	search := pacSearch{
		override:  "",
		envURI:    "",
		configDir: configDir,
		homeDir:   home,
		system:    func() string { return "http://system/proxy.pac" },
	}

	if got := search.find(); got != "http://system/proxy.pac" {
		t.Errorf("no files: got %q, want the system PAC", got)
	}

	writeFile(t, filepath.Join(home, "proxy.pac"), "home")
	if got := search.find(); !strings.HasSuffix(got, "/home/proxy.pac") {
		t.Errorf("home file: got %q", got)
	}
	writeFile(t, filepath.Join(configDir, "curlp", "proxy.pac"), "config")
	if got := search.find(); !strings.HasSuffix(got, "/cfg/curlp/proxy.pac") {
		t.Errorf("config file must beat home: got %q", got)
	}

	search.envURI = "http://env/proxy.pac"
	if got := search.find(); got != "http://env/proxy.pac" {
		t.Errorf("environment must beat files: got %q", got)
	}
	search.override = "http://flag/proxy.pac"
	if got := search.find(); got != "http://flag/proxy.pac" {
		t.Errorf("flag must beat environment: got %q", got)
	}
}

func TestPACSearchIgnoresCurrentDirectory(t *testing.T) {
	// a proxy.pac in a downloaded repository must not decide where the requests go.
	cwd := t.TempDir()
	writeFile(t, filepath.Join(cwd, "proxy.pac"), clusterPAC)
	t.Chdir(cwd)
	search := pacSearch{configDir: t.TempDir(), homeDir: t.TempDir()}
	if got := search.find(); got != "" {
		t.Errorf("got %q, want no PAC", got)
	}
}

func TestPACSearchIgnoresDirectoryNamedProxyPAC(t *testing.T) {
	configDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(configDir, "curlp", "proxy.pac"), 0o755); err != nil {
		t.Fatal(err)
	}
	search := pacSearch{configDir: configDir, homeDir: t.TempDir()}
	if got := search.find(); got != "" {
		t.Errorf("got %q, want no PAC", got)
	}
}

func TestLoadPACFileURIWithSpaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a dir", "proxy.pac")
	writeFile(t, path, "script")
	got, err := loadPAC(fileURI(path), http.DefaultClient)
	if err != nil || got != "script" {
		t.Errorf("loadPAC() = %q, %v", got, err)
	}
}

func TestLoadPACHTTP(t *testing.T) {
	mux := http.NewServeMux()
	// python's http.server sends .pac files as octet-stream, which must not matter.
	mux.HandleFunc("/ok.pac", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("script"))
	})
	mux.HandleFunc("/big.pac", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxPACSize+1)))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	if got, err := loadPAC(server.URL+"/ok.pac", server.Client()); err != nil || got != "script" {
		t.Errorf("octet-stream PAC: got %q, %v", got, err)
	}
	if _, err := loadPAC(server.URL+"/missing.pac", server.Client()); err == nil {
		t.Error("a 404 must be an error")
	}
	if _, err := loadPAC(server.URL+"/big.pac", server.Client()); err == nil {
		t.Error("an oversized PAC must be an error")
	}
	if _, err := loadPAC("ftp://host/proxy.pac", server.Client()); err == nil {
		t.Error("an unsupported scheme must be an error")
	}
}

func TestFileURIRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x y", "p#1.pac")
	u, err := url.Parse(fileURI(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := fileURIPath(u); got != path {
		t.Errorf("round trip = %q, want %q", got, path)
	}
}
