package main

import (
	"net"
	"testing"
	"time"
)

const clusterPAC = `function FindProxyForURL(url, host) {
    if (
        dnsDomainIs(host, ".example.test") ||
        host === "example.test" ||
        isInNet(host, "192.168.0.0", "255.255.0.0")
    ) {
        return "SOCKS 127.0.0.1:1111";
    }
    return "DIRECT";
}`

func stubLookup(hosts map[string]string) lookupFunc {
	return func(host string) (net.IP, bool) {
		if ip := net.ParseIP(host); ip != nil {
			return ip.To4(), ip.To4() != nil
		}
		if addr, ok := hosts[host]; ok {
			return net.ParseIP(addr).To4(), true
		}
		return nil, false
	}
}

func findProxy(t *testing.T, script, url, host string) string {
	t.Helper()
	rt, err := newPACRuntime(script, stubLookup(map[string]string{"intranet.example": "192.168.7.9"}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := rt.findProxy(url, host, false)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestClusterPAC(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"git.example.test", "socks5h://127.0.0.1:1111"},
		{"example.test", "socks5h://127.0.0.1:1111"},
		{"192.168.0.10", "socks5h://127.0.0.1:1111"},
		{"intranet.example", "socks5h://127.0.0.1:1111"},
		{"example.com", ""},
		{"192.169.0.1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := findProxy(t, clusterPAC, "http://"+tt.host+"/", tt.host); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProxyURLFromDirectives(t *testing.T) {
	tests := []struct {
		result string
		want   string
	}{
		{"PROXY a:3128; DIRECT", "http://a:3128"},
		{"DIRECT; PROXY a:3128", ""},
		{"proxy a:3128", "http://a:3128"},
		{"HTTPS secure:443", "https://secure:443"},
		{"SOCKS4 s:1080", "socks4a://s:1080"},
		{"SOCKS5 s:1080", "socks5h://s:1080"},
		{"SOCKS s:1080", "socks5h://s:1080"},
		{"BOGUS x:1; PROXY a:3128", "http://a:3128"},
		{"PROXY", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.result, func(t *testing.T) {
			if got := proxyURLFromDirectives(tt.result, false); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPACBuiltins(t *testing.T) {
	script := `function FindProxyForURL(url, host) {
        var checks = [
            shExpMatch(url, "http://*.example.com/a?c"),
            !shExpMatch(url, "http://*.example.com/abc/"),
            isPlainHostName("intranet"),
            !isPlainHostName("a.b"),
            dnsDomainLevels("a.b.c") === 2,
            localHostOrDomainIs("www", "www.example.com"),
            !localHostOrDomainIs("www.other.com", "www.example.com"),
            dnsResolve("intranet.example") === "192.168.7.9",
            dnsResolve("nowhere.invalid") === null,
            isResolvable("intranet.example"),
            !isResolvable("nowhere.invalid"),
            !isInNet("nowhere.invalid", "10.0.0.0", "255.0.0.0"),
        ];
        for (var i = 0; i < checks.length; i++) {
            if (!checks[i]) { return "PROXY failed" + i + ":1"; }
        }
        return "DIRECT";
    }`
	if got := findProxy(t, script, "http://www.example.com/abc", "www.example.com"); got != "" {
		t.Errorf("a builtin misbehaves: %q", got)
	}
}

func TestPACUnsupportedAndBrokenScripts(t *testing.T) {
	lookup := stubLookup(nil)

	rt, err := newPACRuntime(`function FindProxyForURL(u, h) { return weekdayRange("MON") ? "DIRECT" : "DIRECT"; }`, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.findProxy("http://x/", "x", false); err == nil {
		t.Error("weekdayRange must report an error instead of guessing")
	}

	if _, err := newPACRuntime(`var x = 1;`, lookup); err == nil {
		t.Error("a script without FindProxyForURL must be an error")
	}
	if _, err := newPACRuntime(`function FindProxyForURL(`, lookup); err == nil {
		t.Error("a syntax error must be an error")
	}

	rt, err = newPACRuntime(`function FindProxyForURL(u, h) { }`, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.findProxy("http://x/", "x", false); err == nil {
		t.Error("no return value must be an error")
	}
}

func TestPACRunawayScriptIsInterrupted(t *testing.T) {
	old := pacEvalTimeout
	pacEvalTimeout = 50 * time.Millisecond
	defer func() { pacEvalTimeout = old }()

	rt, err := newPACRuntime(`function FindProxyForURL(u, h) { while (true) {} }`, stubLookup(nil))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := rt.findProxy("http://x/", "x", false); err == nil {
		t.Fatal("expected a timeout error")
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the script was not interrupted in time")
	}
}

func TestProxyURLFromDirectivesLocalDNS(t *testing.T) {
	tests := []struct {
		result string
		want   string
	}{
		{"SOCKS s:1080", "socks5://s:1080"},
		{"SOCKS5 s:1080", "socks5://s:1080"},
		{"SOCKS4 s:1080", "socks4://s:1080"},
		{"PROXY a:3128", "http://a:3128"},
	}
	for _, tt := range tests {
		t.Run(tt.result, func(t *testing.T) {
			if got := proxyURLFromDirectives(tt.result, true); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
