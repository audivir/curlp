package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// pacEvalTimeout limits a PAC script and each name lookup it makes.
var pacEvalTimeout = 2 * time.Second

// lookupFunc resolves a host name to its IPv4 address.
type lookupFunc func(host string) (net.IP, bool)

// lookupIPv4 resolves host with the resolver of Go, accepting IPv4 literals as they are.
func lookupIPv4(host string) (net.IP, bool) {
	if ip := net.ParseIP(host); ip != nil {
		v4 := ip.To4()
		return v4, v4 != nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), pacEvalTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil, false
	}
	return ips[0].To4(), true
}

// localIPv4 returns the address of the interface that routes to the internet.
//
// The UDP "connection" only selects a route and sends no packet.
func localIPv4() string {
	conn, err := net.Dial("udp4", "192.0.2.1:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer func() { _ = conn.Close() }()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return "127.0.0.1"
}

// shellGlobToRegexp converts the shell expression of shExpMatch into an anchored regexp.
func shellGlobToRegexp(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// pacRuntime evaluates the FindProxyForURL function of a PAC script.
type pacRuntime struct {
	vm   *goja.Runtime
	find goja.Callable
}

// newPACRuntime evaluates script with the PAC built-ins available.
//
// The functions for dates and times (weekdayRange, dateRange, and timeRange) are not supported
// and raise an error if a script calls them.
func newPACRuntime(script string, lookup lookupFunc) (*pacRuntime, error) {
	vm := goja.New()
	unsupported := func(name string) func(goja.FunctionCall) goja.Value {
		return func(goja.FunctionCall) goja.Value {
			panic(vm.NewGoError(fmt.Errorf("%s is not supported by curlp", name)))
		}
	}
	builtins := map[string]any{
		"isPlainHostName": func(host string) bool { return !strings.Contains(host, ".") },
		"dnsDomainIs": func(host, domain string) bool {
			return strings.HasSuffix(strings.ToLower(host), strings.ToLower(domain))
		},
		"localHostOrDomainIs": func(host, hostdom string) bool {
			return host == hostdom || (!strings.Contains(host, ".") && strings.HasPrefix(hostdom, host+"."))
		},
		"isResolvable": func(host string) bool {
			_, ok := lookup(host)
			return ok
		},
		"dnsResolve": func(host string) any {
			if ip, ok := lookup(host); ok {
				return ip.String()
			}
			return nil
		},
		"isInNet": func(host, pattern, mask string) bool {
			ip, ok := lookup(host)
			patternIP, maskIP := net.ParseIP(pattern).To4(), net.ParseIP(mask).To4()
			if !ok || patternIP == nil || maskIP == nil {
				return false
			}
			for i := range ip {
				if ip[i]&maskIP[i] != patternIP[i]&maskIP[i] {
					return false
				}
			}
			return true
		},
		"myIpAddress":     localIPv4,
		"dnsDomainLevels": func(host string) int { return strings.Count(host, ".") },
		"shExpMatch": func(str, glob string) bool {
			re, err := shellGlobToRegexp(glob)
			return err == nil && re.MatchString(str)
		},
		"weekdayRange": unsupported("weekdayRange"),
		"dateRange":    unsupported("dateRange"),
		"timeRange":    unsupported("timeRange"),
		"alert":        func(string) {},
	}
	for name, fn := range builtins {
		if err := vm.Set(name, fn); err != nil {
			return nil, err
		}
	}

	r := &pacRuntime{vm: vm}
	if err := r.guard(func() error {
		_, err := vm.RunString(script)
		return err
	}); err != nil {
		return nil, fmt.Errorf("evaluate PAC script: %w", err)
	}
	find, ok := goja.AssertFunction(vm.Get("FindProxyForURL"))
	if !ok {
		return nil, errors.New("PAC script defines no FindProxyForURL function")
	}
	r.find = find
	return r, nil
}

// guard runs fn and interrupts the script if it takes longer than pacEvalTimeout.
func (r *pacRuntime) guard(fn func() error) error {
	timer := time.AfterFunc(pacEvalTimeout, func() { r.vm.Interrupt("PAC script timed out") })
	defer timer.Stop()
	defer r.vm.ClearInterrupt()
	return fn()
}

// findProxy returns the proxy URL the script selects for rawURL, or an empty string for a
// direct connection.
func (r *pacRuntime) findProxy(rawURL, host string) (string, error) {
	var result goja.Value
	err := r.guard(func() error {
		var callErr error
		result, callErr = r.find(goja.Undefined(), r.vm.ToValue(rawURL), r.vm.ToValue(host))
		return callErr
	})
	if err != nil {
		return "", fmt.Errorf("run FindProxyForURL: %w", err)
	}
	if goja.IsUndefined(result) || goja.IsNull(result) {
		return "", errors.New("FindProxyForURL returned no value")
	}
	return proxyURLFromDirectives(result.String()), nil
}

// proxyURLFromDirectives converts the first usable entry of a PAC result like
// "PROXY a:80; DIRECT" into a proxy URL for curl.
//
// DIRECT as the first usable entry and unknown directives give an empty string.
func proxyURLFromDirectives(result string) string {
	for _, part := range strings.Split(result, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToUpper(fields[0])
		if directive == "DIRECT" {
			return ""
		}
		if len(fields) < 2 {
			continue
		}
		switch directive {
		case "PROXY", "HTTP":
			return "http://" + fields[1]
		case "HTTPS":
			return "https://" + fields[1]
		case "SOCKS", "SOCKS5":
			return "socks5://" + fields[1]
		case "SOCKS4":
			return "socks4://" + fields[1]
		}
	}
	return ""
}
